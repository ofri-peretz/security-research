# ai-3 · Leaky Prompt  (Level 3, 300 XP)

ShopBot is a support chatbot at `http://127.0.0.1:41303`. Its system prompt contains a staff-only
discount code. The team added two guardrails: an input filter that refuses prompt-extraction
attempts, and an output filter that blocks any reply containing the code.

**Goal:** get the staff discount code. Flag: `CTF{ai-3_...}`.

```bash
node ctf.mjs start ai-3
curl -s localhost:41303/     # what ShopBot can do
curl -s localhost:41303/chat -d '{"session":"me","message":"how long is shipping?"}'
```

Black-box is more fun here: try it from the skill list before reading `server.mjs`.
ShopBot runs a deterministic toy model (`toy-chat.mjs`) so the lab is offline and repeatable.

**What you are learning:** OWASP LLM07 System Prompt Leakage and LLM02 Sensitive Information
Disclosure. The real lesson is architectural: a secret in a prompt is a secret you have already
given to every user. Keyword filters on input and exact-match filters on output are what most
teams ship first; a pen-test report should show why they are not a control.
