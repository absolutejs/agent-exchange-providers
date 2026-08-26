# Security

This adapter deliberately supports only fixed, operator-approved HTTPS endpoints.
Do not construct it from an untrusted request or let users supply its endpoint,
field names, or authorization resolver at execution time.

The request body is held in a mutable byte array and cleared after `fetch`
returns. JavaScript runtimes and network stacks may copy buffers internally, so
this is defense in depth rather than a guarantee of memory erasure.

Email one-time codes remain relayable bearer secrets and are not described as
phishing-resistant. The WebAuthn approval protects the automation request; the
destination verifier must independently enforce code expiry and one-time use.

Report vulnerabilities privately through GitHub Security Advisories for
`absolutejs/agent-exchange-providers`.
