# Security policy

Report vulnerabilities privately through GitHub Security Advisories for
`absolutejs/agent-exchange-providers`. Do not include real credentials, tokens,
mailbox identifiers, verification codes, or production conformance output in a
public issue.

The active A2A conformance runner sends requests that can reach the target's
execution path. Run it only against an isolated sandbox with synthetic accounts,
synthetic destinations, non-production credentials, and fresh bounded mandates.
Network isolation and server-side safeguards remain the operator's
responsibility; the `sandbox-only` acknowledgement is a guardrail, not a sandbox.

Conformance results cover only the observable checks in the report. They do not
certify implementation internals, key custody, authorization policy, deployment
security, or freedom from vulnerabilities.

DPoP verification rejects non-canonical base64url before signature acceptance.
Persist and compare the verified proof `jti` and key thumbprint rather than using
the compact JWT string as the sole replay identity.
