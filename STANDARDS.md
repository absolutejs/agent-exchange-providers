# Standards profile

This repository uses a narrow profile instead of inventing a new cryptographic
protocol. “MUST” below describes what these packages enforce.

| Concern | Normative source | AbsoluteJS rule |
| --- | --- | --- |
| Phishing-resistant approval | [WebAuthn Level 3](https://www.w3.org/TR/webauthn-3/), [NIST SP 800-63B](https://pages.nist.gov/800-63-4/sp800-63b/authenticators/) | Verify the exact challenge, origin, RP ID hash, user presence, and required user verification. OTP and out-of-band codes are never labeled phishing-resistant. |
| OAuth baseline | [RFC 9700](https://www.rfc-editor.org/rfc/rfc9700) | Authorization code flow, no open redirect behavior, S256 PKCE, issuer validation, and sender-constrained access tokens. |
| PKCE | [RFC 7636](https://www.rfc-editor.org/rfc/rfc7636) | Generate a fresh 32-byte verifier per request and use only `S256`; no downgrade path. |
| Protected authorization request | [RFC 9126](https://www.rfc-editor.org/rfc/rfc9126) | Send the complete request through PAR, require a short-lived `request_uri`, and put only that handle and the client ID in the browser authorization URL. |
| Issuer mix-up defense | [RFC 9207](https://www.rfc-editor.org/rfc/rfc9207) | Require and exactly compare the authorization response `iss` value. |
| Least-privilege audience | [RFC 8707](https://www.rfc-editor.org/rfc/rfc8707) | Require one explicit, exact resource URI in authorization and token requests. |
| Fine-grained authorization | [RFC 9396](https://www.rfc-editor.org/rfc/rfc9396) | Require explicit `type`, `actions`, and `locations` and integrity-protect them through PAR. |
| Sender constraint | [RFC 9449](https://www.rfc-editor.org/rfc/rfc9449) | Accept only `token_type=DPoP`, support one server-nonce retry, and require a host-supplied signer whose private key stays outside the package. |
| Delegation semantics | [RFC 8693](https://www.rfc-editor.org/rfc/rfc8693) | Future token-exchange adapters must distinguish delegation from impersonation and preserve the actor chain; this first release does not silently perform token exchange. |
| Authorization-server metadata | [RFC 8414](https://www.rfc-editor.org/rfc/rfc8414) | Treat the configured HTTPS issuer as an exact security boundary. Provider discovery/adapters may populate the profile but may not weaken it. |

## Assurance modes

`policy + bearer + purpose-bound` is the honest profile for an email OTP: it can
be approved, encrypted, single-use, and model-blind, but a phisher can still relay
the bearer value.

`webauthn-verifier-bound + sender-constrained + purpose-bound` is the hardened
profile: approval is bound to the verifier and exact request, the resulting OAuth
credential is bound to a recipient-held key, and execution is bound to the
declared resource and operation.

Security is the minimum of these three dimensions. No adapter may upgrade a weak
dimension merely because another dimension is strong.
