# Assessing a SaaS product or platform

How we assess a SaaS product, not just its code, so that the result is evidence a client's SOC 2
auditor can rely on. Researched 2026-11-26. _Unverified_ marks a claim that rests only on
secondary sources.

## Standards we test against

| Standard                                                                                     | Edition                                  | Use                                                                        |
| -------------------------------------------------------------------------------------------- | ---------------------------------------- | -------------------------------------------------------------------------- |
| [OWASP WSTG](https://owasp.org/www-project-web-security-testing-guide/)                      | v4.2 (2020-12-03); v5 not yet released   | Test case IDs (WSTG-ATHN, -SESS, -ATHZ, -INPV, -BUSL, -APIT, -CONF, -CRYP) |
| [OWASP ASVS](https://owasp.org/www-project-application-security-verification-standard/)      | 5.0.0 (2025-05-30)                       | Pass/fail requirements at L1–L3; validated by `report/`                    |
| [OWASP API Security Top 10](https://owasp.org/www-project-api-security/)                     | 2023                                     | API risk categories                                                        |
| [CSA CCM](https://cloudsecurityalliance.org/artifacts/ccm-v4-1) / CAIQ                       | v4.1 (2026-01-27)                        | Cloud control domains, vendor questionnaires                               |
| [CIS Benchmarks](https://www.cisecurity.org/cis-benchmarks/)                                 | AWS 7.1.0, Azure 6.0.0, Kubernetes 2.1.0 | Cloud configuration checks                                                 |
| [SLSA](https://slsa.dev/spec/v1.2/) / [OpenSSF Scorecard](https://github.com/ossf/scorecard) | v1.2 / v5.0.0                            | CI/CD and supply chain                                                     |
| [NIST SP 800-115](https://csrc.nist.gov/pubs/sp/800/115/final)                               | 2008                                     | Test process and evidence handling                                         |

## The 14 domains

Access: **E** means external, black or grey box with test credentials. **C** means it needs
code or configuration access. **D** means document review.

| #   | Domain                                 | Test objectives                                                                                                                                                                        | Reference                    | Access                     | SOC 2 (our mapping, unverified) |
| --- | -------------------------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ---------------------------- | -------------------------- | ------------------------------- |
| 1   | External attack surface                | Subdomains, exposed buckets, staging hosts, TLS and headers, internet-reachable admin panels                                                                                           | WSTG-INFO, WSTG-CONF         | E, C, D                    | CC6.6, CC7.1                    |
| 2   | Authentication, SSO, MFA               | Lockout, MFA bypass via alternate paths, SAML signature wrapping, OIDC `state` / `nonce` / redirect URI, password reset tokens                                                         | WSTG-ATHN                    | E, C, D                    | CC6.1, CC6.2                    |
| 3   | Session management                     | Entropy, rotation on login and privilege change, server-side logout, cookie flags, fixation                                                                                            | WSTG-SESS                    | E                          | CC6.1                           |
| 4   | **Authorization and tenant isolation** | Swap every object ID across two tenants for read, write and delete; role escalation; cross-tenant leaks through search, export and webhooks; async jobs that lose the caller's context | API1, API5, WSTG-ATHZ        | E (2 tenants × 3 roles), C | CC6.1, CC6.3                    |
| 5   | API security                           | BOLA/BFLA, mass assignment, rate limits on costly operations, old or undocumented versions, CORS                                                                                       | API Top 10 2023, WSTG-APIT   | E, C, D                    | CC6.1, CC6.6                    |
| 6   | Input handling                         | Injection (SQL, NoSQL, command, template), stored and DOM XSS, upload checks, XXE, path traversal, SSRF                                                                                | WSTG-INPV, WSTG-CLNT, API7   | E, C                       | CC7.1                           |
| 7   | Business logic                         | Price and coupon abuse, step skipping, races on limits and credits, plan-downgrade abuse                                                                                               | WSTG-BUSL, API6              | E                          | CC7.1                           |
| 8   | Secrets and keys                       | Secrets in repos, images, front-end bundles and logs; rotation; per-tenant and per-environment separation; KMS policy                                                                  | WSTG-CRYP                    | E, C, D                    | CC6.1, CC6.7                    |
| 9   | Cloud configuration                    | IAM wildcards, public storage, exposed security groups, logging and encryption on, MFA on admin roles                                                                                  | CIS, CCM                     | C (read-only audit role)   | CC6.1, CC6.6, CC7.1             |
| 10  | CI/CD and supply chain                 | Branch protection, provenance, pinned actions and dependencies, OIDC instead of static cloud keys, artifact signing                                                                    | SLSA v1.2, Scorecard         | C, D                       | CC8.1, CC7.1                    |
| 11  | Logging, monitoring, IR                | Auth, admin and export events logged; log integrity; alert routing; a credential-leak tabletop                                                                                         | CCM logging domain           | C, D                       | CC7.2–CC7.5                     |
| 12  | Data protection                        | TLS and HSTS, encryption at rest and in backups, tenant deletion on offboarding, retention vs. policy                                                                                  | WSTG-CRYP, CCM data security | E, C, D                    | CC6.5, CC6.7                    |
| 13  | Third parties, webhooks, OAuth apps    | Scope minimization, redirect URI and PKCE, token storage, webhook signatures and replay, revocation on uninstall                                                                       | WSTG-IDNT, API7              | E, C, D                    | CC9.2, CC6.1                    |
| 14  | AI and LLM features                    | See [ai-mcp-assessment.md](ai-mcp-assessment.md)                                                                                                                                       | LLM Top 10 2025, MCP Top 10  | E, C, D                    | CC7.1, CC6.1                    |

Domain 4 finds the most serious SaaS bugs. Never scope an engagement without two tenants.

## Engagement shape

- **Scoping questionnaire:** assets (domains, APIs, cloud accounts, repos, CI); tenancy model;
  identity providers; integrations; AI features; data classes; prod or staging target; test
  windows; compliance drivers; emergency contacts.
- **Rules of engagement:** written authorization signed by a client officer; no DoS or load
  testing without a separate waiver; no social engineering unless listed; how captured data is
  stored and destroyed; stop conditions; an escalation contact; the cloud provider's testing
  policy.
- **Test accounts:** tenants A and B, each with owner, admin and member; one unauthenticated
  user; one deprovisioned user; an identity for each identity provider.
- **Effort (our estimate):**
  - 1–2 days: surface, authentication, data protection, third parties
  - 3–5 days: authorization and tenancy
  - 2–4 days: API, cloud, CI/CD
  - 2–3 days: input, business logic, AI features
  - IR: 1 day of documents plus a tabletop
- **Evidence:** every test in the engagement's `coverage` with a result, including passes, so
  an auditor sees what was found clean. Start from `report/templates/saas-engagement.json`.

## Automation

- **Tooling covers:**
  - TLS: testssl.sh, sslyze
  - surface and misconfiguration: Nuclei, ffuf
  - OpenAPI fuzzing: Schemathesis
  - code: Semgrep, and our ESLint plugins via `npm run hunt`
  - secrets: Gitleaks, TruffleHog
  - infrastructure as code: Checkov
  - cloud and CIS: Prowler, ScoutSuite, kube-bench
  - images and SBOM: Trivy, Grype, Syft
  - repos and provenance: Scorecard, slsa-verifier
  - LLM probing: garak, promptfoo
- **Stays manual:**
  - tenant isolation and authorization, with two accounts in Burp or Caido
  - SAML and OIDC logic
  - business logic and races
  - the IR tabletop
  - retention and deletion review
