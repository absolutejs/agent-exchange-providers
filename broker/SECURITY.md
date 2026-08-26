# Security

This experimental 0.x package has not been independently audited. Report
vulnerabilities privately through GitHub Security Advisories on the
`absolutejs/agent-exchange-providers` repository.

The broker confines but does not cryptographically sender-constrain upstream
bearer tokens. Process compromise, unsafe provider code, unrestricted egress, or
credential-store compromise can expose them. Production deployments require an
atomic durable store, encrypted credential custody, tenant fences, revocation,
short expiries, rate limits, and secret-free observability.
