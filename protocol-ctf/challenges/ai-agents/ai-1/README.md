# ai-1 · Tool Time  (Level 1, 100 XP)

`netops-mcp` is an MCP server that gives an AI assistant a `dns_check` tool. Anyone who can
influence the assistant's tool arguments (a user, a poisoned web page, a malicious ticket) controls
what reaches this server, so we skip the model and talk MCP directly.

**Goal:** the server process holds its own credential in the `OPS_API_TOKEN` environment
variable. Make a tool call return it. Flag: `CTF{ai-1_...}`.

```bash
node ctf.mjs start ai-1        # POST JSON-RPC to http://127.0.0.1:41301/mcp
```

Start with the MCP handshake:
```bash
curl -s localhost:41301/mcp -d '{"jsonrpc":"2.0","id":1,"method":"tools/list"}'
curl -s localhost:41301/mcp -d '{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"dns_check","arguments":{"hostname":"localhost"}}}'
```

**What you are learning:** the most common real MCP server bug (same class as CVE-2025-6514 in
`mcp-remote`). OWASP LLM05 Improper Output Handling and LLM06
Excessive Agency: the model's output becomes a shell command. Also: why denylist "sanitizers" fail.

macOS / Linux shell assumed. Keep payloads read-only (print values, nothing destructive).
