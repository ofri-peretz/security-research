# ws-2 · Origin Story: writeup

**Class:** Authentication based on a client-controlled header (CWE-290 / CWE-346), plus an
unanchored allowlist regex. Related: Cross-Site WebSocket Hijacking (CSWSH, CWE-1385).

## Recon
`GET /` says: auth is the `sid` cookie *or* "requests coming from the console origin". Connecting
with no Origin gets `403`.

## Exploit
```js
new WebSocket('ws://127.0.0.1:41102/live', { origin: 'https://console.corp.local.attacker.example' })
```
then `{"cmd":"dump"}`. The `get` command redacts `vaultToken`, `dump` does not: two code paths, one check.

## Why it works
- `Origin` is set by browsers to protect *the user of that browser*. Any non-browser client
  (Node, curl, Burp, a script) sets whatever it wants. It can never authenticate a caller.
- The regex `^https:\/\/console\.corp\.local` has no `$` (end anchor), so
  `https://console.corp.local.attacker.example` also matches. That matters even for real browsers:
  an attacker who owns `attacker.example` can serve a page from that subdomain.

## Stretch answer: what if the Origin check were simply removed?
Then it's textbook **CSWSH**. WebSocket handshakes are not covered by CORS or the same-origin policy.
A malicious page the admin visits runs `new WebSocket('wss://ops.corp/live')`, the browser attaches
the admin's `sid` cookie automatically, and the page reads the socket. So for cookie-authenticated
sockets, an **exact** Origin allowlist (or a CSRF-style token in the first message) is required,
*in addition to* the cookie. Origin protects against CSWSH; it is not authentication. (SameSite
cookies help but are not a full defence: same-site subdomains are not cross-site.)

## Report drill
> **Title:** Unauthenticated read of live ops config (incl. vault token) via spoofed Origin header.
> **Severity driver:** no credentials needed, secret material exposed.
> **Fix:** authenticate every socket (session/token); keep an exact-match Origin allowlist for CSWSH; never stream secrets to clients.

## Fix
`fixed-server.mjs`: exact `Set` of origins, the cookie is the only authentication, and secret
keys are not served over the socket at all.

## Scanner check
**Not caught.** One unrelated hit (`secure-coding/no-improper-sanitization` on `ws.send(JSON.stringify(...))`
at line 36, which looks like a **false positive**: JSON sent over a socket is not a markup sink).
**Rule gaps:** (1) `ws` upgrade handler that authorizes on `req.headers.origin`; (2) regex
allowlist of origins/hosts without an end anchor.
