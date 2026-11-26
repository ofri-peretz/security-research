# What dogfooding found in our ESLint plugins

Each item was found by running our own plugins on this repo. It's either on the labs (where
the right answer is known) or on our tooling (where a hit had to be triaged by hand). Fix them
in the eslint monorepo. When a fix ships, `scripts/lab-lint.mjs` fails until the matching
entry in `scripts/lab-expectations.json` is removed, and the inline suppressions named below
can go.

Versions: `node-security@6.3.2`, `secure-coding@6.5.1`, `mcp-sdk-security@2.1.5` (strict).

## Recall gaps: lab root causes with no rule

| Lab    | Root cause                                                        | CWE      |
| ------ | ----------------------------------------------------------------- | -------- |
| grpc-1 | Identity taken from client-settable gRPC metadata (`x-*-user`)    | CWE-290  |
| grpc-2 | gRPC reflection registered on a public listener                   | CWE-306  |
| ws-1   | No per-message membership check in a `ws` message handler         | CWE-639  |
| ws-2   | Origin header used as authentication; allowlist regex without `$` | CWE-1385 |

## Real-world recall: known CVEs our plugins miss

Found by `npm run hunt` on published packages with a public, fixed advisory. These are
the most valuable gaps, because each is a real bug that shipped.

| Package             | Advisory      | Root cause                                                                                                                                                                                                 | What fired at the sink               |
| ------------------- | ------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------ |
| `mcp-remote@0.1.15` | CVE-2025-6514 | The OAuth `authorization_endpoint` from a remote MCP server reaches the `open` package (`open(sanitizeUrl(authorizationUrl))`, bundled `dist/chunk-*.js:13835`), which launches it through the OS (CWE-78) | Nothing, under recommended or strict |

Suggested rule (mcp-sdk-security or node-security): a URL from a network response or remote
metadata passed to `open` / `child_process` / `shell.openExternal` without a scheme
allowlist (`https:` only).

## Rules worth adding (from the AI/MCP assessment research)

Each catches something static analysis can see. See [standards/ai-mcp-assessment.md](standards/ai-mcp-assessment.md).

| Candidate rule                                                          | CWE                    | Why                                                     |
| ----------------------------------------------------------------------- | ---------------------- | ------------------------------------------------------- |
| URL from server metadata opened without a scheme allowlist              | CWE-78, CWE-20         | The CVE-2025-6514 pattern, missed by every current rule |
| Outbound fetch of a metadata- or tool-supplied URL without an allowlist | CWE-918                | SSRF through MCP discovery and tools                    |
| Model output reaching `eval` / `innerHTML` / raw SQL                    | CWE-94, CWE-79, CWE-89 | LLM05                                                   |
| Tool description built from untrusted data                              | CWE-1427               | Tool poisoning at the source                            |
| Webhook signature compared with `===`                                   | CWE-208                | Timing-unsafe verification                              |
| Request body spread into a model create/update                          | CWE-915                | Mass assignment (API3)                                  |
| Wildcard OAuth scopes in MCP config                                     | CWE-250                | MCP02                                                   |

## Precision in the default config

The 2026-11-26 hunt of `mcp-remote@0.1.15`:

- **`strict`:** 371 hits. 146 `no-improper-type-validation`, 85 `no-insecure-comparison`
  (`==`), 77 `detect-object-injection`. Almost all of these are in bundled dependencies.
  `recommended` gives 34, so hunting defaults to `recommended`.
- **`secure-coding/no-graphql-injection`, in recommended: 30 false positives.** It fires on
  ajv's code generator, which builds JavaScript by string concatenation (for example
  `out += " { keyword: '" + ...` at `dist/chunk-*.js:1733`). The file has no GraphQL at all
  (the word "graphql" appears 0 times). This is the highest-priority precision bug found so far,
  because it's in the config users get by default. Fix: require a GraphQL client, a `gql`
  tag, or a query-shaped string (`query`/`mutation` + a selection set) before reporting.

## False positives

| Rule                                        | Where                                                   | What the rule misses                                       | Status                                          |
| ------------------------------------------- | ------------------------------------------------------- | ---------------------------------------------------------- | ----------------------------------------------- |
| `secure-coding/detect-object-injection`     | `protocol-ctf/solutions/ws-3/fixed-server.mjs:17`       | `Set.has(key)` denylist of prototype keys + `continue`     | Fix in progress (session started 2026-11-26)    |
| `secure-coding/no-improper-sanitization`    | `protocol-ctf/challenges/websockets/ws-2/server.mjs:36` | `ws.send(JSON.stringify(...))` isn't an HTML sink          | Fix in progress (same session)                  |
| `secure-coding/detect-object-injection` ×3  | `protocol-ctf/ctf.mjs` (`p.solves[id]` etc.)            | Key validated by a lookup that throws, in another function | Open; probably accept as a cross-function limit |
| `secure-coding/detect-object-injection`     | `report/cvss.mjs` (`selected[k]`)                       | `keys.indexOf(k) < 0` early return is an allowlist guard   | Open                                            |
| `secure-coding/detect-object-injection`     | `report/build-cwe.mjs` (`entries[id]`)                  | Key is a `\d+` regex capture, so a numeric string          | Open                                            |
| `secure-coding/no-unchecked-loop-condition` | `protocol-ctf/lib/http.mjs:4`                           | `for await` body throws past a size limit, so it's bounded | Open                                            |
| `node-security/no-arbitrary-file-access`    | `report/build-cwe.mjs`                                  | Path is a CLI argument in a dev script                     | Open; arguably by design                        |

## Wrong or contradictory messages

| Rule                                        | Problem                                                                                                                                                                      |
| ------------------------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `node-security/detect-eval-with-expression` | On `new Function(...)` built from client input, the message says "Use template literals instead of eval() for string interpolation". That's the wrong fix for code injection |
| `secure-coding/no-insecure-comparison`      | Tags a timing-unsafe password comparison (CWE-208) as `OWASP:A02-Security` (Misconfiguration). A07 Authentication Failures fits better                                       |

## True positives our plugins found in our own code (fixed)

- `node-security/require-emitter-error-handler`: `protocol-ctf/lib/runner.mjs` and `ctf.mjs`
  spawned children with no `'error'` listener.
- `node-security/no-toctou-vulnerability`: `protocol-ctf/lib/flags.mjs` checked for the secret
  file and then wrote it, so concurrent servers could derive different flags.
- `secure-coding/no-format-string-injection`: `report/cli.mjs` logged a path the user controls
  inside the format string.
