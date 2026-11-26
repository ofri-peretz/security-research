# ws-1 · Eavesdrop: writeup

**Class:** Broken Object Level Authorization (BOLA / IDOR) on a WebSocket message. CWE-639, OWASP A01:2021.
Plus a small information leak (CWE-200) that hands you the object id.

## Recon
1. Connect. The `hello` frame lists commands: `login, rooms, join, say`.
2. Log in as guest. You get `welcome`, and then an unrequested `presence` frame:
   `{"type":"presence","user":"alice","in":["lobby","staff"]}`. Now you know a room name.
3. `rooms` returns only `["lobby"]`. The UI would never show you `staff`.

## Exploit
```json
{"type":"join","room":"staff"}
```
The reply includes the room history, with the flag. `say` in `staff` is refused, which is the tell:
the developer wrote the membership check in one handler and forgot it in the other.

## Why it works
WebSocket auth usually happens once (at the handshake or a `login` message). After that, every
message is effectively a new API request, but frameworks don't give you per-route middleware for
messages, so checks get written by hand in each `case`. Missing one is the most common WebSocket bug
in real programs.

## Hunting habit
For every message type, ask: "which object does this name, and where is ownership checked?" Make
a table of message type × check. Then look for ids leaked in pushes the server sends you unasked
(presence, typing indicators, notifications, error messages).

## Report drill
> **Title:** Any authenticated user can read private chat rooms via the `join` message.
> **Impact:** confidentiality of all private rooms, including staff secrets.
> **Steps:** log in as `guest`; send `{"type":"join","room":"staff"}`; history is returned.
> **Root cause:** `join` lacks the membership check that `say` has. Room names leak via `presence`.
> **Fix:** enforce membership in `join` (and in every handler, ideally via one `authorize(user, room)` helper); stop sending other users' room lists.

## Fix
See `fixed-server.mjs`: the membership check is added to `join`, and `presence` no longer lists
rooms. The reference exploit guesses `staff` when the leak is gone and is still denied.

## Scanner check (eslint-plugin-secure-coding / node-security strict, run 2026-11-26)
**Not caught.** `express-security/no-idor-resource-access` exists but targets Express route
handlers. **Rule gap:** a per-message authorization check in `ws` `on('message')` switch handlers.
