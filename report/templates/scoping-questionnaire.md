# Scoping questionnaire

Please fill this in before testing starts. Your answers decide what is tested, what access we
need and how long it takes. Anything marked _(required)_ blocks the start date.

## 1. Organization

- Legal name _(required)_:
- Primary contact (name, role, email) _(required)_:
- Emergency contact during testing, reachable within one hour _(required)_:
- Why are you commissioning this test? (SOC 2 Type I, SOC 2 Type II, customer request, other):
- Your SOC 2 auditor, if known, and the audit period:

## 2. What is in scope

- Product or platform name, and the environment to test (production or staging) _(required)_:
- Version under test: release tag, commit SHA, or deployment ID _(required)_:
- Web applications (URLs):
- APIs (base URLs; attach an OpenAPI / gRPC / GraphQL schema if you have one):
- MCP servers or AI-agent features (describe the tools and data they can reach):
- Cloud accounts for configuration review (provider and account IDs; we need a read-only audit role):
- Source repositories for code review (if code review is in scope):
- CI/CD system:
- Anything explicitly **out** of scope:

## 3. How the product works

- Tenancy model (single tenant, shared database with tenant ID, schema per tenant, …):
- User roles (for example owner / admin / member / read-only):
- Identity providers and sign-in methods (password, SSO/SAML, OIDC, social, MFA):
- Third-party integrations, webhooks and OAuth apps:
- The most sensitive data you hold (PII, payment, health, secrets, customer content):
- Anything you already know is weak, or was found in a previous test:

## 4. Test accounts we need

Two tenants (A and B), each with one user per role, plus one deprovisioned user. List them here,
or tell us how they'll be shared. Don't email passwords: use your password manager's sharing
feature.

## 5. Constraints

- Test windows and blackout dates:
- Rate limits or WAF rules we should know about (or allowlist our test IP):
- Is load or denial-of-service testing allowed? (No by default.)
- Is social engineering allowed? (No by default.)

## 6. Deliverables

- Report audience (engineers, executives, your auditor, your customers):
- Do you need a retest letter after fixes? (Recommended for SOC 2.)
- Should findings be mapped to SOC 2 criteria? (We provide the tester's mapping; your auditor
  decides.)
