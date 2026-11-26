# Assessing AI-agent, MCP and API platforms

Our specialty. Researched 2026-11-26. Pin the MCP spec revision under test, because earlier
revisions differ.

## Standards

| Standard                                                                                                                                | Edition                     | Note                                                                             |
| --------------------------------------------------------------------------------------------------------------------------------------- | --------------------------- | -------------------------------------------------------------------------------- |
| [OWASP Top 10 for LLM Applications](https://genai.owasp.org/llm-top-10/)                                                                | 2025 (LLM01–LLM10)          |                                                                                  |
| [OWASP Top 10 for Agentic Applications](https://genai.owasp.org/resource/owasp-top-10-for-agentic-applications-for-2026/)               | 2026 (published 2025-12-09) | Full ASI list unverified; check before citing anything beyond ASI01–04 and ASI10 |
| [OWASP MCP Top 10](https://owasp.org/projects/mcp-top-10)                                                                               | 2025, beta                  | Say it's beta in reports                                                         |
| [MCP Security Best Practices](https://modelcontextprotocol.io/specification/2025-11-25/basic/security_best_practices)                   | spec 2025-11-25             | Normative MUST / MUST NOT language, the strongest reference                      |
| [OWASP API Security Top 10](https://api-security.owasp.org/editions/2023/en/0x11-t10/)                                                  | 2023                        |                                                                                  |
| [NIST AI 600-1](https://www.nist.gov/publications/artificial-intelligence-risk-management-framework-generative-artificial-intelligence) | 2024-07-26                  | Governance cross-walk, not test IDs                                              |
| [MITRE ATLAS](https://atlas.mitre.org/)                                                                                                 | current                     | Verify technique IDs before citing                                               |

## MCP servers and clients

| Objective                     | Test                                                                                                              | Evidence                              | Reference                       |
| ----------------------------- | ----------------------------------------------------------------------------------------------------------------- | ------------------------------------- | ------------------------------- |
| Tool poisoning                | Hidden instructions in tool descriptions and schemas; a canary description to see whether the model obeys         | Description hash, the induced call    | MCP03, LLM01                    |
| Rug pull                      | Pin `tools/list` at approval, re-list on `list_changed`, diff                                                     | Hash diff across sessions             | MCP03                           |
| Injection through tool output | Instructions in tool results and resources the model reads                                                        | Transcript and resulting action       | LLM01                           |
| Confused deputy               | Second client with an attacker `redirect_uri`, replay with a consent cookie present                               | Whether a code issues without consent | MCP spec, CWE-441               |
| Token passthrough             | Token whose audience is another resource                                                                          | 401 vs. a forwarded call              | MCP spec (MUST NOT), CWE-287    |
| OAuth discovery abuse         | `authorization_endpoint` with shell metacharacters or a non-http scheme (the CVE-2025-6514 pattern)               | Process tree, accepted scheme         | CWE-78, MCP spec URL validation |
| Sessions                      | Entropy, cross-user replay, sessions used as auth                                                                 | Sample, replay result                 | MCP spec, CWE-330, CWE-613      |
| stdio command injection       | Fuzz launch args and one-click configs, `shell: true`                                                             | Captured argv                         | CWE-78                          |
| SSRF                          | `resource_metadata`, `authorization_servers` or tool URLs pointing at `169.254.169.254`, localhost, or a redirect | Egress log                            | CWE-918                         |
| Excessive scopes              | Granted scopes vs. what each tool needs                                                                           | Scope set vs. tool map                | MCP02, CWE-250                  |

## AI-agent features

| Objective                             | Test                                                                            | Evidence                            | Reference           |
| ------------------------------------- | ------------------------------------------------------------------------------- | ----------------------------------- | ------------------- |
| Prompt injection, direct and indirect | Plant instructions in documents, email and tool output, over N trials           | Input, retrieved chunk, action, k/N | LLM01, ASI01        |
| Excessive agency                      | Map tools and permissions; can a low-trust input trigger write, send or delete? | Tool trace, policy decision         | LLM06, ASI02/03     |
| System prompt leakage                 | Canary string in the prompt, never in output                                    | Canary match                        | LLM07               |
| Output into sinks                     | Model output into HTML, SQL, shell or `eval`                                    | Executed payload                    | LLM05, CWE-79/89/94 |
| RAG and data poisoning                | Poisoned document's rank and behavior change                                    | Rank, output diff                   | LLM04, LLM08        |
| Unbounded consumption                 | Token, tool-call and loop budgets; oversized and recursive input                | Cost per request                    | LLM10, API4         |

## Scoring AI findings

Score the capability an attack reaches with CVSS v4.0, for example "an untrusted document can
make the agent call `send_email` to any recipient". Then record **reproducibility** next to the
score (model, version, N trials, successes) in the finding's `reproducibility` field.
CVSS assumes deterministic behavior and has no metric for a success rate, so don't encode the
rate as attack complexity. OWASP AIVSS is an incubator project with no versioned release. Don't
cite it yet.

## What static rules can and can't see

- **Static (our ESLint plugins):** exec with a variable or `shell: true`, URL opened from server
  metadata without a scheme allowlist, fetch of a non-literal URL, request body spread into an
  ORM, signatures compared with `===`, routes without auth middleware, wildcard scopes, model
  output reaching a sink.
- **Dynamic only:** whether an injection succeeds, rug pulls, cross-tenant BOLA, rate limits at
  runtime, session entropy, anything about model behavior.

The rules worth adding are listed in [plugin-backlog.md](../plugin-backlog.md).
