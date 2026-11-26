# Protocol CTF

Hands-on, local-only security labs for the protocols real bug-bounty and pen-test work runs into.
Each challenge is a small, intentionally vulnerable service. You exploit it, capture the flag,
then patch it so the exploit fails while the feature keeps working: the same two skills a
finding report and a remediation retest need.

> Everything binds to `127.0.0.1`. Nothing here touches a real target. Never expose these services.

## Quick start

```bash
npm install
node ctf.mjs                    # scoreboard
node ctf.mjs start ws-1         # run a challenge (read its README.md first)
node ctf.mjs submit ws-1 'CTF{ws-1_...}'
node ctf.mjs hint ws-1          # costs 15% of the challenge's XP per hint
node ctf.mjs fix ws-1           # after you patch challenges/.../server.mjs: +50% bonus XP
node ctf.mjs log                # your history
```

Requirements: Node 20+, macOS or Linux (the ai-1 shell payloads assume a POSIX shell).
Nice to have: [grpcurl](https://github.com/fullstorydev/grpcurl), `wscat` (`npx wscat`), Burp or
Caido for WebSockets. Everything can be done with Node alone.

## Challenges

| Track | Id | Title | Level | What you learn |
|---|---|---|---|---|
| WebSockets | ws-1 | Eavesdrop | 1 | Per-message authorization (BOLA), leaky push frames |
| WebSockets | ws-2 | Origin Story | 2 | Origin is not auth, CSWSH, regex anchoring |
| WebSockets | ws-3 | Merge Conflict | 3 | Prototype pollution to auth bypass |
| gRPC | grpc-1 | Trust the Gateway | 1 | Spoofed identity metadata behind a gateway |
| gRPC | grpc-2 | Hidden Methods | 2 | Server reflection recon, raw protobuf wire format |
| gRPC | grpc-3 | Stream Filter | 3 | Code injection, using a stream as the exfil channel |
| AI agents | ai-1 | Tool Time | 1 | MCP tool command injection, denylist bypass (LLM05/06) |
| AI agents | ai-2 | Poisoned Note | 2 | Indirect prompt injection to tool abuse (LLM01/06) |
| AI agents | ai-3 | Leaky Prompt | 3 | System prompt leakage, guardrail bypass (LLM07/02) |

The AI track uses small deterministic toy models (no API key, same result every run). They
simulate a model that can be steered; the bugs are in the architecture around the model, which is
what you'd report.

## Scoring

- Solve: level × 100 XP, minus 15% per hint taken before solving.
- Fix: +50% of the base XP when `node ctf.mjs fix <id>` confirms the legitimate feature still
  works (`functional.mjs`) **and** the reference exploit no longer gets the flag.
- Ranks: Recruit → Packet Sniffer (200) → Frame Smuggler (600) → Protocol Breaker (1100) →
  Exploit Developer (1700) → Protocol Wizard (2300). Max today: 2700.
- Badges per track: cleared, no hints, patched every bug.

Progress lives in `.ctf/progress.json` (gitignored). Flags are derived from a per-install secret
in `.ctf/secret`. **Honor rules:** don't read `.ctf/secret` or compute flags, and treat
`solutions/` as the answer key. Server source is fair game except where a README says
"black-box".

To reset a challenge after patching it: `git checkout challenges/<track>/<id>/server.mjs`.

## Working like a hunter

For each challenge, keep notes in the shape of a real report: title, impact, steps, root cause,
fix. Each writeup ends with a "report drill" and a "scanner check" so you can compare. The point
of the lab is the habit, not the flag.

## For maintainers

`npm run verify` proves every lab is real. For each challenge, against the vulnerable server: the
functional check passes, a negative control is denied, and the reference exploit returns the exact
flag. Against `solutions/<id>/fixed-server.mjs`: the functional check passes and the exploit fails.
Run one with `npm run verify -- ws-3`.

Adding a challenge: `challenges/<track>/<id>/{challenge.json, README.md, server.mjs, hints.json, functional.mjs}`
and `solutions/<id>/{exploit.mjs, control.mjs, fixed-server.mjs, WRITEUP.md}`. Pick an unused port in
the track's block (WebSockets 411xx, gRPC 412xx, AI 413xx) and make `npm run verify` green.

See [docs/ROADMAP.md](docs/ROADMAP.md) for the next tracks and [docs/SCANNER-RESULTS.md](docs/SCANNER-RESULTS.md)
for how our ESLint plugins do against these bugs.
