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
