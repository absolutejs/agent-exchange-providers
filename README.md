# Agent Exchange providers

Interchangeable, security-profiled providers for
[`@absolutejs/agent-exchange`](https://github.com/absolutejs/agent-exchange).

- [`@absolutejs/agent-exchange-webauthn`](./webauthn) verifies a request-bound,
  user-verified WebAuthn approval.
- [`@absolutejs/agent-exchange-oauth`](./oauth) implements a hardened OAuth grant
  handoff using PAR, PKCE, issuer identification, resource indicators, RAR, and
  DPoP.

The packages intentionally distinguish confidential delivery from phishing
resistance. Email and other bearer secrets can be protected in transit, but only
the explicit WebAuthn + sender-constrained + purpose-bound assurance profile is
described as phishing-resistant.

Licensed under Apache-2.0.
