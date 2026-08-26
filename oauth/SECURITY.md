# Security

Report vulnerabilities through GitHub Security Advisories for
`absolutejs/agent-exchange-providers`.

Authorization session stores must atomically consume state. DPoP private keys
must be non-exportable or held by a platform KMS/HSM. Never log authorization
codes, PKCE verifiers, DPoP proofs, access tokens, or encoded grant bundles.
