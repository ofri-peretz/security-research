# Client engagement workflow: decisions

Built 2026-11-26 at the owner's request ("this is what I would like you to build"). It closes the
gaps between the report generator and a first paying SaaS engagement: intake, manual evidence,
retests, SOC 2 Type II, and keeping client data out of git.

1. **Client data lives outside the repo.** Workspaces sit under
   `SR_HOME/clients/<slug>`: directories 0700, files 0600. The repo holds only templates and code.
   The bounty pipeline already works this way.
2. **Intake is two documents the client receives**: a scoping questionnaire and an
   authorization / rules-of-engagement form. The form is a template, not legal advice, and says
   so. Have it reviewed before first use.
3. **Manual results are SARIF too.** `manual.json` entries become a `manual-testing` SARIF run,
   so they go through the same triage gate as scanner output. Nothing ships untriaged, whether a
   tool or a person found it. Locations can be URLs, because SaaS findings often have no file.
4. **Retests target the client's commit, and failures stay on the record.** `retest` refuses the
   originally tested version. Every attempt, pass or fail, goes into `retestHistory`, and the
   retest letter lists the latest attempt per finding.
5. **Type II is a diff between reports.** Building with `--previous` adds new, resolved and
   still-open findings. This requires finding IDs to stay stable for a client across
   engagements, and the README says so.
6. **A separate CLI** (`scripts/engagement.mjs`, using `node:util` `parseArgs`) rather than
   extending `sr.mjs`, whose argument parser only handles boolean flags. Bounty work and client
   work stay apart.

## Needs the owner

- A CPA review of the SOC 2 criteria mapping before the first client report.
- Firm name, logo and contact details for client-facing reports and the authorization form.
- A legal review of `report/templates/authorization.md`.
