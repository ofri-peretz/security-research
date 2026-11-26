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
