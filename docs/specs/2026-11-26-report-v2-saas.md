---
slug: report-v2-saas
intent: docs/intents/2026-11-26-security-research-practice.md
opened: 2026-11-26
---

**Status:** built 2026-11-26 under the owner's standing autonomy instruction. Review the merged
result; it hasn't been through the usual Design→Build acceptance.

# Report v2 and the SaaS / platform assessment method

Based on three research passes on 2026-11-26:

- our report compared with Trail of Bits and Cure53 reports and the WSTG reporting chapter
- a SaaS and platform assessment method (WSTG v4.2, ASVS 5.0.0, API Top 10 2023, CSA CCM v4.1,
  CIS, SLSA v1.2, NIST SP 800-115)
- AI-agent, MCP and API platform testing (the MCP spec 2025-11-25, LLM Top 10 2025, MCP Top 10
  beta, the Agentic Top 10 for 2026)

The methods are written up in [saas-assessment.md](../standards/saas-assessment.md) and
[ai-mcp-assessment.md](../standards/ai-mcp-assessment.md).

## Report v2: what changes, ranked by the review

1. **Retests have to be honest.** A finding's fix is either `client` or `reference`. A client
   fix must name a commit that differs from the target version. A retest must say who did it,
   when, and what evidence was seen. A reference fix (one the tester wrote, as in the dogfood
   labs) renders as "Reference fix verified", never as "Fixed and retested".
2. **Difficulty sits beside severity.** Every finding carries `difficulty` (Low / Medium / High)
   and a one-line basis. The executive summary shows a severity × difficulty matrix, which also
   ranks findings that share a CVSS score.
3. **Exploit scenario and chains.** Every finding has `exploitScenario`, and may list
   `chainsWith` finding IDs. A chained ID must exist.
4. **Remediation is split.** `remediation.shortTerm` (required), `longTerm`, `owner` and
   `targetDate`.
5. **Severity glossary.** Rendered in the appendix: what each level means and its CVSS v4.0
   band.
6. **Strategic recommendations and positive observations** in the executive summary.
7. **Engagement record and document control.** The engagement gains `timeline` (dated
   milestones), `levelOfEffort`, `rulesOfEngagement`, `confidentiality`, `issueDate` and
   `revisions`. Each is rendered.
8. **Coverage.** `coverage[]` lists every test performed with its standard reference and result
   (pass / fail / not applicable). A `fail` must name the finding it produced, and every finding
   must come from a failed test or from tool output. An auditor can then see what was tested and
   found clean.
9. **AI findings carry reproducibility.** Optional `reproducibility`: `{ model, version, trials,
successes }`. CVSS can't express how often a probabilistic attack works, so it's reported
   next to the score.
10. **Client-facing voice.** No tool internals in the body: no generator footer, and the CWE
    catalog version moves to the appendix. Tool messages are labeled "Tool output". The SOC 2
    mapping is narrowed (CC8.1 only for change-management findings).

## SaaS engagement template

`report/templates/saas-engagement.json` is a starting point for a client engagement. It
pre-fills the 14 assessment domains as `coverage` entries, each with its WSTG / API Top 10 /
ASVS reference and `result: "not-tested"`. The report refuses to build while any entry is still
`not-tested` unless it is marked out of scope with a reason. Coverage can't be left blank by
accident.

## Feedback loop

`npm run test:scripts` covers it: new refusal tests for each validation rule above, and the
golden dogfood report re-rendered with the v2 fields.
