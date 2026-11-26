# Repo gates: decisions made during Build

Built 2026-11-26 from the accepted
[findings-report spec](../specs/2026-11-26-findings-report.md#repo-gates) while running
autonomously. Every decision that departs from the spec, or that the spec left open, is listed
here so it can be reviewed and reversed.

## What runs where

| Gate                                                                     | pre-commit          | pre-push                   | CI                  |
| ------------------------------------------------------------------------ | ------------------- | -------------------------- | ------------------- |
| commitlint (conventional, fixed scope list)                              | commit-msg          | n/a                        | n/a                 |
| Open-finding guard                                                       | staged diff + paths | every commit not on `main` | n/a (list is local) |
| gitleaks                                                                 | staged              | n/a                        | full history        |
| markdownlint (eslint repo's rule set)                                    | staged `.md`        | via `ci:local`             | yes                 |
| prettier                                                                 | staged              | changed vs `origin/main`   | changed vs base     |
| oxlint                                                                   | staged `.js`/`.mjs` | via `ci:local`             | yes                 |
| Our ESLint security plugins, strict, 0 warnings                          | n/a                 | via `ci:local`             | yes                 |
| Script tests (`node --test`)                                             | n/a                 | via `ci:local`             | yes                 |
| lab-lint dogfood (recall + precision vs `scripts/lab-expectations.json`) | n/a                 | via `ci:local`             | yes                 |
| protocol-ctf `verify` (45 exploit/fix checks)                            | n/a                 | via `ci:local`             | yes                 |
| Lockfiles in sync                                                        | n/a                 | n/a                        | yes                 |
| OSV scan, both lockfiles                                                 | n/a                 | n/a                        | yes                 |
| CodeQL (labs excluded)                                                   | n/a                 | n/a                        | PR, push, weekly    |

## Decisions

1. **The labs aren't reformatted.** prettier would rewrite 98 existing files. `protocol-ctf/` is
   in `.prettierignore`, and the format gate only checks files a change touches. Formatting the
   labs, if wanted, gets its own PR. Reason: changing code someone else pushed must never be
   a side effect.
2. **oxlint and the repo-wide ESLint skip `challenges/` and `solutions/`.** Those files are
   meant to be vulnerable. `scripts/lab-lint.mjs` lints them instead, and there a hit is an
   expected answer. oxlint found 7 small issues in the lab code (4 unused imports, an
   unnecessary regex escape, an unused expression, a `startsWith` suggestion). They're left for
   the lab owner. The regex escape sits in a deliberately vulnerable server, where "cleaning" it
   could change the exploit.
3. **Our plugins found 7 issues in the labs' own tooling (`ctf.mjs`, `lib/`).** They're
   triaged, not suppressed wholesale:
   - **3 true positives, fixed.** `lib/runner.mjs` and `ctf.mjs` spawned children with no
     `'error'` listener, so a failed spawn would hang `verify` or crash the CLI.
     `lib/flags.mjs` had a check-then-write race on the flag secret, which could make two lab
     servers starting at once derive different flags. It now uses `wx` + `EEXIST`.
   - **4 false positives, suppressed inline with the reason, and logged as plugin bugs:**
     - `detect-object-injection` ×3 on `p.solves[id]`: `id` already passed `findChallenge()`,
       which only returns exact catalog ids. The guard is in another function.
     - `no-unchecked-loop-condition` on `for await (chunk of req)`: the loop throws once the
       body passes `limit`.
4. **One edit to lab content.** In `ai-2/README.md`, `<untrusted>` was rendered as an HTML tag,
   so it was invisible on GitHub. It's now in backticks.
5. **`katex` is overridden to `^0.18.2`.** OSV flagged GHSA-238p-pmpm-9mq7 (CVSS 2.1) in
   `katex`, pulled in by markdownlint-cli2. The eslint repo uses the same override.
6. **The open-finding guard fails when `.open-findings` is missing.** A guard with nothing to
   check would pass silently. An empty file means "no open findings". It's proven against the
   real 2026-11-26 leak commit: run over that commit it exits 1, and on current `main` it
   exits 0. It never prints the matched term.
7. **Not added yet:**
   - The Claude reviewer needs a `CLAUDE_CODE_OAUTH_TOKEN` repo secret, which only the owner
     can set.
   - burgee `hookset-check` and the link check: the hookset presets aren't in the local burgee
     checkout, so they couldn't be checked against this `lefthook.yml`.
   - Dependabot auto-merge waits until this PR gate has run green on `main`.

## Proven to fail (AI-SDLC rule 4)

- **Open-finding guard:** 6 `node --test` cases, plus the real leak commit (exit 1).
- **lab-lint:** an expectations file with a renamed root-cause rule and an emptied
  `ws-3.fixedHits` fails with a "RECALL REGRESSION" and a "NEW HIT" message. Restored, it passes.
- **gitleaks:** full history scanned, no leaks. **OSV:** it failed on `katex` before the
  override and passes after.
