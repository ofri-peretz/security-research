# What matters in SOC 2, OWASP and CWE

Researched 2026-11-26 from primary sources where they could be reached. **Unverified** marks a
claim that rests on secondary sources; confirm those with a CPA before the report schema depends
on them. Editions move, so every report cites the edition and date it maps to.

## SOC 2

- **Only a licensed CPA firm issues a SOC 2 report** (an attestation). We supply evidence the
  client's auditor relies on. We never call our output a SOC 2 report.
- **Criteria in force:** 2017 Trust Services Criteria with Revised Points of Focus (2022)
  ([AICPA](https://www.aicpa-cima.com/resources/article/2017-trust-services-criteria-with-revised-points-of-focus-2022)).
  The 2022 revision changed points of focus, not the criteria.
- **Five categories:** Security, Availability, Processing Integrity, Confidentiality, Privacy.
  Only **Security** (Common Criteria CC1–CC9) is mandatory; the rest are scoped per engagement.
  *Unverified.*
- **Type I** tests control design at one point in time. **Type II** tests operating
  effectiveness over a period, so evidence has to cover the whole period, not one test date.
  *Unverified.*
- **No criterion requires a pen test.** Auditors commonly expect vulnerability evidence, and a
  pen test is the usual source
  ([Moss Adams](https://www.mossadams.com/articles/2026/04/penetration-test-for-soc-compliance)).
- **Criteria our evidence supports:** CC4.1 (monitoring), CC7.1 (vulnerability detection), CC7.2
  (anomaly monitoring), CC8.1 (change management, i.e. remediation), and CC6.x for access-control
  findings. *Unverified: sources disagree on CC7.1 vs CC7.2 for vulnerability management.*
- **What auditors look for in a pen test**
  ([CSA](https://cloudsecurityalliance.org/articles/soc-2-reports-and-penetration-tests)):
  scope tied to the system boundary and version, methodology, test dates, tester independence,
  severity ratings, remediation per finding, and a **retest** that shows the fix holds.

## OWASP

| Standard | Edition | Use in a report |
|---|---|---|
| [ASVS](https://owasp.org/projects/asvs) | 5.0.0, levels L1–L3 (May 2025, *unverified*) | **The testable one.** Each requirement passes or fails at a stated level, so map checks to ASVS IDs |
| [Top 10](https://top10.owasp.org/2025) | 2025 (A01 Broken Access Control … A10 Mishandling of Exceptional Conditions) | Awareness category, weak as audit criteria |
| [API Security Top 10](https://api-security.owasp.org/editions/2023/en/0x11-t10) | 2023 (API1 BOLA … API10 Unsafe Consumption) | Category for API findings |
| [LLM Top 10](https://genai.owasp.org/llm-top-10/) | 2025 (LLM01 Prompt Injection … LLM10 Unbounded Consumption); a 2026 link exists, unread | Category for AI findings |
| [MCP Top 10](https://owasp.org/www-project-mcp-top-10/) | Beta (MCP01 Token Mismanagement, MCP03 Tool Poisoning, MCP05 Command Injection, MCP07 Insufficient Auth …) | Category for MCP findings; say it's beta |

## CWE

- **[CWE Top 25, 2025](https://cwe.mitre.org/top25/archive/2025/2025_cwe_top25.html)** (top 10):
  79 XSS, 89 SQLi, 352 CSRF, 862 Missing Authorization, 787 OOB Write, 22 Path Traversal,
  416 Use After Free, 125 OOB Read, 78 OS Command Injection, 94 Code Injection.
- **[KEV Top 10](https://cwe.mitre.org/top25/archive/2025/2025_kev_insights.html):** the
  weaknesses behind CISA's actively exploited CVEs. A better priority signal than raw frequency.
- **[Mapping rules](https://cwe.mitre.org/documents/cwe_usage/guidance.html):** map the root
  cause to a **Base or Variant** CWE. Use a Class only when nothing narrower fits. Never use a
  Pillar, a DISCOURAGED entry or a PROHIBITED entry.
- **CVE** names the instance, **CWE** the weakness, **CVSS** the severity. Record the
  [CVSS v4.0](https://www.first.org/cvss/v4-0/) vector and its rationale, not just the score.

## Formats

- **[SARIF 2.1.0](https://docs.oasis-open.org/sarif/sarif/v2.1.0/sarif-v2.1.0.html)** for
  findings. GitHub code scanning ingests it, and ESLint can emit it.
- **[OSV](https://ossf.github.io/osv-schema/)** for advisories. OSV.dev and GHSA use it.

## What the report product must get right, ranked

1. An evidence chain per finding: scope, tester, dates, method, remediation, retest.
2. Scope pinned to a system boundary and a version (commit SHA / package version).
3. The tester's identity and independence, and dated methodology.
4. CWE at Base/Variant level, never Pillar or PROHIBITED.
5. Severity as a CVSS v4.0 vector plus the reasoning.
6. Checks keyed to ASVS requirement IDs at a stated level.
7. SARIF in, OSV out: no hand translation for GitHub or OSV.dev.
8. Edition and date of every standard cited, in the report itself.
9. Reproducible: each finding ships with the exploit, the negative control, and the fix
   (as protocol-ctf already does).
10. Ready for Type II: evidence over a period, not one test.
