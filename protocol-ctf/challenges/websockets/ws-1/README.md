# ws-1 · Eavesdrop  (Level 1, 100 XP)

A small team runs its chat over WebSockets. You have the guest account (`guest` / `guest`).
Alice, an admin, talks in a room you are not a member of.

**Goal:** read the staff conversation. The flag looks like `CTF{ws-1_...}`.

```bash
node ctf.mjs start ws-1        # ws://127.0.0.1:41101
```

Protocol: JSON text frames. The server greets you with the commands it supports.
Any WebSocket client works: `npx wscat -c ws://127.0.0.1:41101`, or a few lines of Node with the
`ws` package (already installed here).

**What you are learning:** WebSocket servers authenticate once at connect or login, then every
later message is a new request that needs its own authorization check. Bug hunters call a
missing per-object check BOLA / IDOR.

Submit: `node ctf.mjs submit ws-1 'CTF{...}'`
