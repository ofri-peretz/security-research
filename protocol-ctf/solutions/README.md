# Solutions (spoilers)

Each folder has:

- `WRITEUP.md`: recon, the exploit, why it works, how you would write it up in a report, the fix,
  and whether our ESLint plugins catch it.
- `exploit.mjs`: the reference exploit (`node solutions/<id>/exploit.mjs` with the server running).
- `control.mjs`: a negative control that must be denied. It proves the finding is what we think it
  is, and not something broader or an artifact of the lab.
- `fixed-server.mjs`: a reference patch. `npm run verify` proves the exploit fails against it while
  the legitimate feature keeps working.

Solve first, then read. The writeup is most useful compared against your own notes.
