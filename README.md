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
  provider security capabilities, verifies DPoP proofs, and actively tests A2A
  sandboxes for negotiation, preparation, credential separation, replay safety,
  and task/receipt redaction.
- [`@absolutejs/agent-exchange-broker`](./broker) confines an upstream bearer
  token to one tenant, exchange, provider, purpose, and deterministic operation.
- [`@absolutejs/agent-exchange-mandate-webcrypto`](./mandate-webcrypto) signs and
  verifies explicitly typed ES256 JWS standing mandates with non-exportable keys.
- [`@absolutejs/agent-exchange-mandate-stores`](./mandate-stores) provides atomic
  PostgreSQL and Redis registration, use-limit, replay, expiry, and revocation
  storage.
- [`@absolutejs/agent-exchange-destinations`](./destinations) selects one
  destination by exact origin, operation, and secret kind and rejects ambiguous
  or secret-reflecting adapters.
- [`@absolutejs/agent-exchange-http-destination`](./http-destination) submits a
  six-digit code to one deployment-configured HTTPS endpoint without following
  redirects or returning the destination response to an agent.
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
