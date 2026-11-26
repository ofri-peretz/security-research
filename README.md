# Security Research

Ofri Peretz's security research workspace: the process, labs and tooling behind coordinated
vulnerability disclosure work, iterated in public.

## Contents

| Path | What it is |
|---|---|
| [`protocol-ctf/`](protocol-ctf/) | Local-only, intentionally vulnerable labs (WebSockets, gRPC, AI agents/MCP) with verified exploits, fixes and writeups. `npm run verify` proves each lab. |

Related open-source tooling: [eslint](https://github.com/ofri-peretz/eslint) (security ESLint plugins),
[interlace](https://github.com/ofri-peretz/interlace), [burgee](https://github.com/ofri-peretz/burgee).

## Disclosure policy

Findings are reported privately to maintainers and published here only after a fix ships or the
disclosure window closes. Nothing in this repository targets a live system.

## License

All rights reserved. This repository is public for visibility only; no permission to use, copy,
modify or distribute is granted. See [LICENSE](LICENSE).
