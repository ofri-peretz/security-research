# grpc-3 · Stream Filter  (Level 3, 300 XP)

A reporting service streams orders that match a filter expression you send
(`orders.proto` is next to this file). Example filter: `o.total > 50 && o.status == "shipped"`.
The server source is yours to read, as in an open-source audit.

**Goal:** the server keeps a payments signing key in its environment
(`PAYMENTS_SIGNING_KEY`). Get it back through the stream. Flag: `CTF{grpc-3_...}`.

```bash
node ctf.mjs start grpc-3     # 127.0.0.1:41203
```

**What you are learning:** server streaming is a response channel you can write into, and
"flexible filter languages" are a classic path to code injection (`eval`, `new Function`,
`vm`, template engines, Mongo `$where`). Getting the data *out* is part of the exploit: think
about which field of the response you control.

Safety: this runs real JavaScript inside a local process on your machine. Keep payloads to
reading values. No file deletion, no network calls.
