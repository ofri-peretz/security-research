# Our ESLint plugins vs. the lab

Run on 2026-11-26 against the nine vulnerable `server.mjs` files, ESLint 9 with the `strict`
configs of the published `eslint-plugin-node-security@6.3.1`, `eslint-plugin-secure-coding@6.5.0`
and `eslint-plugin-mcp-sdk-security@2.1.4`.

| Challenge | Root cause | Caught by the root-cause rule? | What fired |
|---|---|---|---|
| ws-1 | BOLA in a `ws` message handler | No | unrelated: `no-hardcoded-credentials` (test fixture), `no-insecure-comparison` |
| ws-2 | Auth by Origin header + unanchored regex | No | `no-improper-sanitization` on `ws.send(JSON.stringify(...))`, likely a **false positive** |
| ws-3 | Prototype pollution in recursive merge | **Yes** | `secure-coding/detect-object-injection` (line 14) |
| grpc-1 | Trusted identity metadata | No | nothing |
| grpc-2 | Reflection on + internal service on public listener | No | nothing |
| grpc-3 | `new Function` on user input | **Yes** | `node-security/detect-eval-with-expression` (line 31) |
| ai-1 | `exec` with interpolated tool arg | **Yes** | `node-security/no-shell-injection` (line 26) |
| ai-2 | Indirect prompt injection + over-privileged agent | n/a | toy model, no SDK to match |
| ai-3 | Secret in system prompt | n/a | toy model, no SDK to match |

**3 of 7 applicable root causes caught.** Candidate rules this suggests, in rough order of value:

1. `grpc` reflection enabled without an environment guard (easy, high signal).
2. Authorization from client-controllable identity headers / gRPC metadata (`x-*-user`).
3. WebSocket upgrade handlers that authorize on `Origin`, and origin/host allowlist regexes without `$`.
4. Per-message authorization in `ws` `on('message')` handlers (harder: needs data-flow).
5. `mcp-sdk-security` coverage for hand-rolled MCP servers (raw `tools/call` dispatch, no SDK).
6. Investigate the `no-improper-sanitization` hit on JSON sent over a socket (possible FP).

Each lab is a ready-made answer-key case (vulnerable) plus a clean control (fixed) for that rule.

## Run 2: 2026-11-26, vulnerable **and** fixed servers

Same `strict` configs, newer patches: `node-security@6.3.2`, `secure-coding@6.5.1`,
`mcp-sdk-security@2.1.5`. Run 1 scanned only the vulnerable servers. This run also scans each
`fixed-server.mjs`, so a hit that is still there after the fix shows up as a false positive.

| Challenge | Vulnerable: root cause caught? | Fixed: root-cause rule silent? | Verdict on other hits |
|---|---|---|---|
| ai-1 | Yes: `no-shell-injection:26` | Yes | `require-secure-credential-storage:12` on both (lab fixture assigns its own token to `process.env`; noise) |
| ai-2, ai-3 | n/a (toy model) | n/a | none |
| grpc-1 | No | (none) | none |
| grpc-2 | No | (none) | none |
| grpc-3 | Yes: `detect-eval-with-expression:31` | Yes | none |
| ws-1 | No | (none) | `no-hardcoded-credentials:8`, `no-insecure-comparison:31` on both: true positives, outside the lab's lesson |
| ws-2 | No | (none) | `no-improper-sanitization:36`: **right line, wrong reason**. The bug is client-chosen config keys (CWE-200), not sanitization; the fix's `PUBLIC_KEYS` allowlist silences it |
| ws-3 | Yes: `detect-object-injection:14` | **No: still fires at line 17** | **False positive**: the rule ignores the `FORBIDDEN.has(key)` + `continue` guard on the line above |

**Recall unchanged at 3/7. Precision on fixed controls: 1 root-cause false positive in 3.**
New work this adds to run 1's list:

7. `secure-coding/detect-object-injection`: treat a `Set.has(key)` denylist of `__proto__` /
   `constructor` / `prototype` with an early `continue`/`return` as a guard (FP, `fixed/ws-3:17`).
8. `secure-coding/no-improper-sanitization`: don't treat `ws.send(JSON.stringify(...))` as an
   output sink; the real signal there is unrestricted key lookup.
