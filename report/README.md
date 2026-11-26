# report

Turns SARIF findings into a professional security assessment report: one self-contained HTML
file (print it to get a PDF) plus `report.json`. Spec:
[docs/specs/2026-11-26-findings-report.md](../docs/specs/2026-11-26-findings-report.md).

```bash
node report/cli.mjs --sarif results.sarif --engagement engagement.json \
  --findings findings.json [--log retest.log] --out report.html
```

- **`results.sarif`**: what the tools and the tester found (SARIF 2.1.0).
- **`engagement.json`**: scope, target version, tester and independence, dates, methodology,
  tools, and the standard editions. See `dogfood/engagement.json`.
- **`findings.json`**: the analyst's triage. Each `findings[]` entry claims the SARIF results
  that are its evidence and carries the CWE, CVSS v4.0 vector and rationale, ASVS / OWASP /
  SOC 2 mapping, status, fix and retest. Every other result goes in `triage` with a verdict and
  a reason.
- **`--log`**: retest output. A `retested` finding names the log section and the line it
  expects there.

**v2 fields** (spec: [docs/specs/2026-11-26-report-v2-saas.md](../docs/specs/2026-11-26-report-v2-saas.md)):

- **Each finding:** `difficulty`, `exploitScenario`, `remediation.shortTerm` / `longTerm` /
  `owner` / `targetDate`, optional `chainsWith`, and optional `reproducibility` for AI
  findings.
- **Fixes:** `fix.kind` is `client` (needs a commit later than the tested version) or
  `reference` (rendered as "Reference fix verified", never as a client retest). A retest needs
  `retest.by` and evidence.
- **The engagement:** `issueDate`, `confidentiality`, `rulesOfEngagement`, `levelOfEffort`,
  a dated `timeline`, `revisions`, `strategicRecommendations`, `positiveObservations`,
  and `coverage` (every test with pass / fail / n/a / out-of-scope).
- **New SaaS engagement:** start from [templates/saas-engagement.json](templates/saas-engagement.json).
  It refuses to build until every one of its 14 domains is tested or scoped out with a reason.

It refuses to build (exit 1, nothing written) on:

- a CWE that is a Pillar, a view, unknown, or Discouraged/Prohibited
- a malformed CVSS vector, or one without a rationale
- a fix without a commit, or a retest without matching evidence in the log
- an untriaged or invented result
- an ASVS ID that doesn't exist
- a missing engagement field

`node report/dogfood/build.mjs` regenerates the dogfood engagement from the live labs.
`npm run test:scripts` re-renders it and compares the output with `dogfood/out/`.

Vendored data: `vendor/cvss-v4` (FIRST reference scorer, BSD-2-Clause), `data/cwe.json`
(MITRE CWE 5.0), `data/asvs.json` (ASVS 5.0.0 IDs and levels only).

## Running a client engagement

Client data never enters this repo. Each client gets a private workspace under
`~/.security-research/clients/<slug>` (`SR_HOME`), readable only by you.

1. `npm run engagement -- new <slug> "<Client legal name>" --tester "<you>"` creates the
   workspace. Send the client `scoping.md` and `authorization.md`. Don't start testing until
   authorization is signed.
2. Fill in `engagement.json` from the scoping answers. Put scanner output in `tool/*.sarif`,
   and record manual results (Burp, tenant swaps, logic flaws) in `manual.json` as
   `{ id: "M-01", title, location, detail }`.
3. Triage in `findings.json`: every result is claimed by a finding or triaged out.
4. `npm run engagement -- status <slug>` shows what is still untested.
5. `npm run engagement -- build <slug>` writes `out/report.html` and `report.json`. It
   refuses until every coverage domain is tested or scoped out.
6. Once the client has fixed:
   `npm run engagement -- retest <slug> F-01 --commit <their fix> --result pass|fail --by "<you>" --evidence "<what you saw>"`.
   It refuses the originally tested commit, and failed attempts stay on the record. Then rebuild
   and run `npm run engagement -- letter <slug>` for the retest letter.
7. **SOC 2 Type II**, repeated tests over the audit period: keep finding IDs stable for the
   client, and build with `--previous <last report.json>`. The report adds new, resolved and
   still-open findings since then.
