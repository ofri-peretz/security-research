# ws-3 · Merge Conflict  (Level 3, 300 XP)

A realtime game lobby lets each player patch their own settings over the socket with partial
JSON (`{"type":"settings.patch","patch":{"sound":{"volume":7}}}`). There is also an
`admin.secrets` command. You are `guest`, and there is no way to log in as anyone else.

**Goal:** make the server think you are an admin. Flag: `CTF{ws-3_...}`.

```bash
node ctf.mjs start ws-3        # ws://127.0.0.1:41103
```

You get the full server source (`server.mjs`), as you would when hunting in an open-source
project. Read it first.

**What you are learning:** a JavaScript-specific bug class. It shows up wherever untrusted
JSON meets a recursive merge, clone or path setter, over HTTP, WebSockets, queues or MCP. It
is one of the most common real findings in Node libraries.

Note: the effect is process-wide. Restart the server to get a clean state.
