# Findings report v1: decisions made during Build

Built 2026-11-26 from the accepted [findings-report spec](../specs/2026-11-26-findings-report.md)
while running autonomously. This lists every departure from the spec and every call the spec
left open.

## Changed from the spec

1. **v1 computes CVSS scores; the spec deferred this.** A report with hand-typed scores would
   contain wrong numbers, and nothing would catch them. FIRST's reference scorer is vendored
   byte-for-byte (`report/vendor/cvss-v4`, BSD-2-Clause) and run in a `node:vm` context,
   because it relies on sloppy-mode globals. It was checked against Red Hat's independent
   `cvss` library on 500 seeded random vectors, including threat and environmental metrics:
   0 mismatches. The pairs are committed as `report/test/cvss-oracle.json`.
2. **ASVS IDs are validated, not just accepted.** The ASVS 5.0.0 requirement IDs, levels and
   section names are vendored (`report/data/asvs.json`, 345 requirements). The requirement
   _text_ is CC BY-SA 4.0 and stays upstream, so this all-rights-reserved repo carries no
   share-alike content.
3. **CWE 5.0 has no categories.** MITRE's 2026-10-28 catalog has weaknesses and views only.
   Validation refuses unknown IDs, views, Pillars, and anything MITRE marks Discouraged or
   Prohibited (`report/data/cwe.json`, rebuilt by `report/build-cwe.mjs`).
4. **Triage keys are readable** (`<tool>/<rule>@<path>:<line>`) so a person can write
   `findings.json`. The limit: moving code changes the key, which is noted in the code.
   Switch to SARIF `partialFingerprints` when findings need to survive refactors.
5. **Retest evidence is checked against a log.** A finding marked `retested` must name the log
   section and the line it expects. The dogfood log is protocol-ctf's `verify` output, cut
   down to lab headers and PASS/FAIL lines, so no flag values are committed.

## Calls made on the dogfood report

- **Framed as a client engagement on the lab servers,** not as an assessment of the plugins.
  That's the shape the product is for, and it exercises the full evidence chain: exploit,
  negative control, fix, retest.
- **The tester is declared not independent.** The report says so, because a client report
  would need that disclosed.
- **F-10 (timing comparison) carries `E:U`.** We didn't exploit it and know of no public
  exploit. Without the threat metric CVSS v4 assumes the worst case: it scored 6.3 Medium
  without `E:U` and 1.7 Low with it.
- **Plugin tag prefixes are stripped from tool messages.** Our plugins prefix messages with
  their own CWE, OWASP and CVSS tags. In a client report those contradicted the analyst's
  mapping (the plugin said CVSS 5.9 and A02 for the F-10 line), so only the plain text is kept.
- **"Highest risks" ranks by severity.** It first listed the open findings first, which put a
  Medium above three Criticals. Status is shown next to each risk instead.
- **No forced page breaks.** One section per printed page wasted half of most pages. The
  print-to-PDF output is now 17 A4 pages.

## Not done

- Golden test is for the dogfood report only. A second, independent engagement fixture would
  catch renderer assumptions that only hold for these labs.
- No OSV output for advisories yet. That's the next step on the advisory side.
- The SOC 2 criteria mapping (CC6.1, CC7.1, CC8.1) is the tester's, and the report says so. A CPA
  should review the mapping before it's used with a client.
