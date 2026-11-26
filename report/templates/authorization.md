# Authorization to test and rules of engagement

This document authorizes **{{tester}}** ("the tester") to perform the security assessment
described below against systems owned or operated by **{{client}}** ("the client"). No testing
starts until it is signed by someone at the client with authority over every system in scope.

> Template, not legal advice. Have it reviewed before first use.

## Engagement

- Engagement ID: {{engagementId}}
- Systems in scope: listed in the attached scoping questionnaire, section 2
- Environment: {{environment}}
- Test window: {{start}} to {{end}}, {{hours}}
- Tester source IP addresses: {{sourceIps}}

## Rules of engagement

1. The tester tests only the systems listed in scope. Anything discovered outside scope is
   reported to the client and not tested further.
2. No denial-of-service or load testing, and no social engineering, unless listed here:
   {{exceptions}}.
3. The tester stops and contacts the emergency contact immediately on any sign of instability,
   of a third party's data, or of an existing compromise.
4. Data the tester sees is used only for this assessment. Evidence that contains client data is
   stored encrypted, access is limited to the testers named here, and it is destroyed
   {{retention}} after the final report.
5. The tester's own findings stay confidential to the client. They aren't published unless the
   client agrees in writing. Vulnerabilities in third-party software found during the test are
   reported to that vendor under coordinated disclosure, after telling the client and without
   identifying the client.
6. The client confirms it may authorize testing of each system in scope, including systems
   hosted by cloud providers, under those providers' testing policies.

## Contacts

- Client primary contact: {{clientContact}}
- Client emergency contact: {{clientEmergency}}
- Tester contact: {{testerContact}}

## Signatures

|        | Name | Title | Signature | Date |
| ------ | ---- | ----- | --------- | ---- |
| Client |      |       |           |      |
| Tester |      |       |           |      |
