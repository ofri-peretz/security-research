---
slug: findings-report
intent: docs/intents/2026-11-26-security-research-practice.md
opened: 2026-11-26
---

**Status:** accepted 2026-11-26 · **Next:** Build, starting with the repo gates

# Findings report: spec

## Goal

Generate a **professional security assessment report**. A client's SOC 2 auditor should be able
to rely on it as vulnerability-management evidence, and a maintainer should be able to act on it.
It is generated from machine-readable findings, never written by hand.

**First user is us.** Iteration 1 renders the protocol-ctf scanner run (run 2: vulnerable and
fixed servers, 2026-11-26) as an assessment of our own ESLint plugins. Every gap it shows feeds
back into the plugins, and every gap in the report feeds back into this spec.

## Non-goals

- Not a SOC 2 report. Only a CPA firm issues those. The report says so on its cover.
- Not a hosted service (PRINCIPLES: packages, never services).
- No scanner of our own. Findings come in as SARIF from any tool (ESLint, CodeQL, manual tests).
- v1 does not compute CVSS scores. It validates the v4.0 vector and records the score and
  rationale given by the analyst. Computing the score from FIRST's macro-vector table comes later,
  once v1 has shipped a report.

## Inputs

1. **`results.sarif`**: SARIF 2.1.0, what was found and where.
2. **`engagement.json`**: what an auditor needs about the test itself (see
   [standards](../standards/README.md), items 1–3, 8, 10):
   client, system boundary, target version (commit SHA or package@version), tester name and
   independence statement, start/end dates, methodology, tools and versions, the standard
   editions mapped to, and Type II period if any.
3. **`findings.json`**: analyst triage, keyed by SARIF result fingerprint:
   - `verdict`: `true-positive` | `false-positive` | `accepted-risk` | `out-of-scope`
   - `cwe`: a Base or Variant ID (validated)
   - `cvss`: v4.0 vector, score, rationale
   - `asvs`: requirement IDs and level; `owasp`: Top 10 / API / LLM / MCP category with edition
   - `soc2`: Common Criteria it evidences
   - `status`: `open` | `fixed` | `retested`, with the fix commit and the retest result
   - `reproduction`: exploit, negative control, and fix paths (protocol-ctf's shape)

## Output

One **self-contained HTML file** (no network, no JS needed, print-ready CSS, so "Print → PDF" is
the PDF path), plus `report.json` carrying the same data.

Sections, in this order:

1. **Cover**: client, target@version, dates, tester, report version, "This is not a SOC 2
   report" statement.
2. **Executive summary**: counts by severity and status, the three highest risks in plain words,
   and a posture trend when previous reports exist.
3. **Scope and methodology**: boundary, versions, method, tools, limitations, what was not tested.
4. **Standards**: every standard cited, with its edition and date.
5. **Findings overview**: one row per finding (ID, title, severity, CWE, OWASP, status).
6. **Finding detail**: description, evidence (`path:line`, snippet), reproduction, impact,
   CVSS vector + rationale, CWE / ASVS / OWASP / SOC 2 mapping, remediation, retest result.
7. **SOC 2 evidence matrix**: Common Criterion → findings → status. The auditor's index.
8. **Appendix**: false positives and accepted risks with reasons, tool versions, the input
   files' SHA-256 hashes, and a glossary.

## Validation: the report refuses to build when

- a CWE is a Pillar, DISCOURAGED, or PROHIBITED (from a vendored MITRE CWE catalog subset)
- a CVSS vector doesn't parse as v4.0, or has no rationale
- a `fixed` finding has no fix commit, or a `retested` finding has no retest evidence
- `engagement.json` is missing the boundary, version, tester, dates or editions
- a SARIF result has no triage entry: nothing ships untriaged

## Shape

- A `report/` package in this repo, plain Node ESM, **zero runtime dependencies**.
- CLI: `node report/cli.mjs --sarif … --engagement … --findings … --out report.html`.
- `scripts/eslint-to-sarif.mjs` (about 40 lines) converts ESLint JSON for the dogfood run.
  This avoids a formatter dependency.

## Feedback loop (AI-SDLC rule 2)

`npm test` in `report/` exits non-zero if:

- a golden fixture (the dogfood run) renders differently from the committed snapshot
- any validation rule above accepts an input it should refuse (one fixture per rule, each
  proven to fail first)

## Repo gates

These are the gates our other repos already enforce, adapted to a repo of plain `.mjs` files and
Markdown. They're taken from `workshops` (CI and verify battery), `burgee` (minimal lefthook
layout) and `eslint` (quality jobs). The gates have to be in place before the `report/` package is
built, so Build starts here.

| Gate | Hook | CI (PR + push to main) | From |
|---|---|---|---|
| Conventional commits (commitlint, fixed scope list: `report`, `protocol-ctf`, `docs`, `ci`) | commit-msg | n/a | `eslint/commitlint.config.mjs`, burgee hookset |
| markdownlint on staged `.md` | pre-commit | full run | `eslint/lefthook.yml` |
| prettier `--check` on staged files | pre-commit | full run | eslint `format-drift`, without the ratchet |
| oxlint | pre-commit | yes | `eslint/quality.yml` |
| **Our own ESLint security plugins**, `--max-warnings 0` (see below) | pre-push | yes | dogfood |
| `npm run verify`: protocol-ctf labs, then `report/` tests | pre-push | yes | `workshops/package.json` `verify` |
| Lockfile in sync | n/a | yes | `eslint/quality.yml` `lockfile` |
| OSV scan of lockfiles | n/a | yes | `eslint/quality.yml` `supply-chain`, `osv-scanner.toml` |
| **gitleaks**: secrets scan, full history on push | pre-commit (staged) | yes | new. None of our repos has one, and a security repo must |
| **Open-finding guard**: refuse any file naming a target listed in a local, untracked `.open-findings` file | pre-commit + pre-push | n/a (list stays local) | new, after the 2026-11-26 incident |
| actionlint | n/a | when `.github/**` changes | `eslint/package.json` `lint:workflows` |
| Link check | n/a | yes | `eslint/package.json` `check-links` |
| CodeQL (javascript) | n/a | push + nightly | `eslint/codeql.yml` |
| Scheduled failure opens an issue | n/a | on cron failure | `eslint/.github/actions/report-failure` |
| Hooks match the hookset presets | n/a | yes | `burgee/hookset-check.yml@hookset@1.1.1` |
| Claude reviewer | n/a | PR, not draft | `eslint/claude-code-review.yml`, needs a `CLAUDE_CODE_OAUTH_TOKEN` repo secret |

**Linting an intentionally vulnerable repo with our own plugins.** Most repos ignore a file that
fails lint. Here the result is turned into a test:

- `challenges/**/server.mjs` **must** fire the root-cause rule its lab names. A lab declares that
  rule in its `challenge.json`. If the rule stops firing, it's a recall regression in the plugin.
- `solutions/**/fixed-server.mjs` **must** be clean. A hit there is a plugin false positive.
  Today that's `ws-3:17`: known and listed, so the gate fails only on *new* false positives.
- Everything else (`lib/`, `report/`, `scripts/`) lints at `--max-warnings 0`, like any repo.

Each plugin release then gets a recall and precision check against labs with known answers. The
SARIF from that run is the input for the dogfood report.

**Left out:** typecheck and build (no TypeScript), rule audits, corpus recall and the benchmark
configs (eslint-monorepo specific), and Dependabot auto-merge (only once the PR gate exists).

**Not yet confirmed:** the `interlace` AI-SDLC doc and `ai-sdlc:audit` script aren't on its
checked-out branch, so this repo hasn't been checked against the audit yet. Run
`npm run ai-sdlc:audit` once they land, and add any stage it finds missing.

## Open questions for acceptance

1. Should ESLint `require-secure-credential-storage` hits on lab fixtures be triaged
   `out-of-scope` or `accepted-risk`? It's the same question for any intentionally vulnerable
   target.
2. Should the report be branded (Interlace) or neutral?
3. Is HTML plus print-to-PDF enough, or does a client need a native PDF (which would mean a
   dependency)?
