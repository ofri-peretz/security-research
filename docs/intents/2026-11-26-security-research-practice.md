---
slug: security-research-practice
opened: 2026-11-26
repo: ofri-peretz/security-research
---

**Status:** accepted 2026-11-26 · **Next:** spec.md (Design), which needs acceptance before Build

## What

One repo for the whole security-research family: bug hunting, bounty submissions,
research write-ups, and a reporting product that turns findings into reports a
client can hand to an auditor.

What lives here:

- **Learning labs**: the 9-challenge protocol-ctf, which already passes.
- **Disclosure policy**: how we report, the embargo window, and when we publish.
- **Published advisories**: write-ups of findings that are **fixed and disclosed**.
  Each one carries its CVE/GHSA ID, CWE, OWASP category and CVSS v4 vector.
- **Report tooling**: a package (not a hosted service) that takes findings in one
  schema and renders pen-test and vulnerability reports mapped to OWASP (Top 10,
  ASVS), CWE, and SOC 2 Trust Services Criteria.

What never lives here: any finding that is unpatched or unfiled. Those stay in
private GitHub Security Advisories until they are fixed and the embargo ends.
Nothing in this repo names an open finding, its target, or its class.

## Why

- Every finding gets filed and credited through GitHub's advisory program. GitHub
  is a CVE Numbering Authority, so a GHSA can carry a CVE.
- The eslint plugins already encode OWASP/CWE knowledge. Findings from real
  packages feed back into those plugins as rules and benchmark cases, and the
  plugins in turn find more bugs.
- A single findings schema makes each finding usable three ways: as an advisory,
  as a lint rule case, and as a line in a client report.

## Constraints

- **We cannot issue SOC 2 reports.** A SOC 2 report is an attestation that only a
  licensed CPA firm can sign. What we can offer is readiness work and pen-test /
  vulnerability evidence mapped to the Trust Services Criteria. The client's
  auditor then relies on that evidence. Product copy must never say "SOC 2
  report" for something we produce.
- **Packages, never services** (PRINCIPLES.md). The report generator ships as an
  npm package/CLI with zero external dependencies. Any paid engagement is
  services *by us*, not a hosted component.
- **Authorized targets only.** We test what a bounty program's scope covers, open
  source we can run locally, or a client system with a signed authorization.
  Every published advisory names the authorization it was found under.
- License is all rights reserved, matching `workshops`.

## Measures

Every claim needs a number:

- Advisories filed / accepted / CVEs assigned (counted from the GHSA API, not by hand)
- Median days from report to maintainer fix
- Findings that became an eslint rule or benchmark case
- Reports generated from the schema without hand edits

## Open questions

1. The findings schema: extend an existing format (SARIF, or OSV for advisories)
   rather than invent one? Leaning SARIF for reports, OSV for advisories.
2. Should the reporting package eventually split into its own repo? It's one repo
   per family, and this is one family, so not for now.
3. Which bounty platforms besides GitHub (HackerOne, huntr) are in scope?
