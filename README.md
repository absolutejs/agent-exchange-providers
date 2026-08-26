# Agent Exchange providers

Interchangeable, security-profiled providers for
[`@absolutejs/agent-exchange`](https://github.com/absolutejs/agent-exchange).

- [`@absolutejs/agent-exchange-webauthn`](./webauthn) verifies a request-bound,
  user-verified WebAuthn approval.
- [`@absolutejs/agent-exchange-oauth`](./oauth) implements a hardened OAuth grant
  handoff using PAR, PKCE, issuer identification, resource indicators, RAR, and
  DPoP.
- [`@absolutejs/agent-exchange-oauth-webcrypto`](./oauth-webcrypto) supplies a
  non-exportable ES256 DPoP signer.
- [`@absolutejs/agent-exchange-oauth-stores`](./oauth-stores) supplies one-time
  memory, Redis, and PostgreSQL authorization-session stores.
- [`@absolutejs/agent-exchange-provider-conformance`](./conformance) evaluates
  provider security capabilities and verifies DPoP proofs.
- [`@absolutejs/agent-exchange-google`](./google) and
  [`@absolutejs/agent-exchange-microsoft`](./microsoft) describe real BYO mailbox
  provider capabilities without upgrading their bearer-token boundaries.

The packages intentionally distinguish confidential delivery from phishing
resistance. Email and other bearer secrets can be protected in transit, but only
the explicit WebAuthn + sender-constrained + purpose-bound assurance profile is
described as phishing-resistant.

Google and Microsoft are useful compatibility providers, but neither currently
meets every requirement of the strict profile documented here. Applications can
use them behind a trusted, token-confined broker; the open adapters fail closed if
asked to claim the stronger profile.

Licensed under Apache-2.0.
