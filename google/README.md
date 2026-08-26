# @absolutejs/agent-exchange-google

Capability-declared Google/Gmail OAuth configuration for BYO deployments.

Google supports authorization-code flows, S256 PKCE, RFC 9207 issuer responses,
and a DPoP mode that binds refresh tokens in confidential BFFs. Its documented
access tokens remain bearer tokens and the flow does not expose the complete
PAR/RAR/resource-indicator profile required by AbsoluteJS.

Consequently this adapter intentionally fails the phishing-resistant provider
conformance check. Use it only behind a trusted token-confined broker or PaaS
boundary, and do not expose Gmail tokens to an agent model.
