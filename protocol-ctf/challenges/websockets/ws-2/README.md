# ws-2 · Origin Story  (Level 2, 200 XP)

An internal ops console streams live configuration over a WebSocket at `/live`. The team's
reasoning: "only our console page can open this socket, because browsers always send the
`Origin` header." You have no account at all.

**Goal:** get the vault token out of the live config. Flag: `CTF{ws-2_...}`.

```bash
node ctf.mjs start ws-2        # http://127.0.0.1:41102 , socket at /live
```

**What you are learning:** the WebSocket handshake is an HTTP request. `Origin` is a header the
*browser* sets to protect *its user* (it is how a server stops Cross-Site WebSocket Hijacking).
It is not authentication. Also watch how the allowlist is written.

Stretch question (answer is in the writeup): the server *also* accepts the admin's `sid`
cookie. If the Origin check were simply removed, what attack would a malicious web page be able
to run against a logged-in admin?
