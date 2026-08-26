# Security

Report vulnerabilities privately through GitHub Security Advisories for
`absolutejs/agent-exchange-providers`.

WebAuthn verification is delegated to the configured `@absolutejs/auth` adapter.
Deployers must use a maintained cryptographic implementation, protect the
credential store, map exchange subjects to stable local users, and serve the
verifier only over HTTPS. Authentication failures are deliberately generic.
