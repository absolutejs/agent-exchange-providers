# Standards profile

This repository uses a narrow profile instead of inventing a new cryptographic
protocol. “MUST” below describes what these packages enforce.

| Concern                         | Normative source                                                                                                                    | AbsoluteJS rule                                                                                                                                                          |
| ------------------------------- | ----------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| Phishing-resistant approval     | [WebAuthn Level 3](https://www.w3.org/TR/webauthn-3/), [NIST SP 800-63B](https://pages.nist.gov/800-63-4/sp800-63b/authenticators/) | Verify the exact challenge, origin, RP ID hash, user presence, and required user verification. OTP and out-of-band codes are never labeled phishing-resistant.           |
| OAuth baseline                  | [RFC 9700](https://www.rfc-editor.org/rfc/rfc9700)                                                                                  | Authorization code flow, no open redirect behavior, S256 PKCE, issuer validation, and sender-constrained access tokens.                                                  |
| PKCE                            | [RFC 7636](https://www.rfc-editor.org/rfc/rfc7636)                                                                                  | Generate a fresh 32-byte verifier per request and use only `S256`; no downgrade path.                                                                                    |
| Protected authorization request | [RFC 9126](https://www.rfc-editor.org/rfc/rfc9126)                                                                                  | Send the complete request through PAR, require a short-lived `request_uri`, and put only that handle and the client ID in the browser authorization URL.                 |
| Issuer mix-up defense           | [RFC 9207](https://www.rfc-editor.org/rfc/rfc9207)                                                                                  | Require and exactly compare the authorization response `iss` value.                                                                                                      |
| Least-privilege audience        | [RFC 8707](https://www.rfc-editor.org/rfc/rfc8707)                                                                                  | Require one explicit, exact resource URI in authorization and token requests.                                                                                            |
| Fine-grained authorization      | [RFC 9396](https://www.rfc-editor.org/rfc/rfc9396)                                                                                  | Require explicit `type`, `actions`, and `locations` and integrity-protect them through PAR.                                                                              |
| Sender constraint               | [RFC 9449](https://www.rfc-editor.org/rfc/rfc9449)                                                                                  | Accept only `token_type=DPoP`, support one server-nonce retry, and require a host-supplied signer whose private key stays outside the package.                           |
| Delegation semantics            | [RFC 8693](https://www.rfc-editor.org/rfc/rfc8693)                                                                                  | Future token-exchange adapters must distinguish delegation from impersonation and preserve the actor chain; this first release does not silently perform token exchange. |
| Signed standing mandates        | [RFC 7515](https://www.rfc-editor.org/rfc/rfc7515), [RFC 8785](https://www.rfc-editor.org/rfc/rfc8785)                              | Use an explicitly typed, ES256 compact JWS over canonical JSON; resolve `kid` only inside the independently trusted issuer boundary and reject algorithm substitution.   |
| Authorization-server metadata   | [RFC 8414](https://www.rfc-editor.org/rfc/rfc8414)                                                                                  | Treat the configured HTTPS issuer as an exact security boundary. Provider discovery/adapters may populate the profile but may not weaken it.                             |
| HTTP semantics                  | [RFC 9110](https://www.rfc-editor.org/rfc/rfc9110)                                                                                  | Destination endpoints are fixed HTTPS deployment configuration; the HTTP adapter uses POST, rejects redirects, omits ambient credentials, and discards response bodies.  |

## Assurance modes

`policy + bearer + purpose-bound` is the honest profile for an email OTP: it can
be approved, encrypted, single-use, and model-blind, but a phisher can still relay
the bearer value.

`webauthn-verifier-bound + sender-constrained + purpose-bound` is the hardened
profile: approval is bound to the verifier and exact request, the resulting OAuth
credential is bound to a recipient-held key, and execution is bound to the
declared resource and operation.

`standing-mandate + token-confined-broker + purpose-bound` is the unattended
automation profile. A user-verified WebAuthn ceremony signs a bounded mandate;
subsequent uses require exact subject, actor, audience, account, action, location,
purpose, risk, and secret-kind matches plus atomic revocation and use accounting.
It is phishing-resistant owner authorization, but it does not turn an upstream
email OTP or bearer token into a phishing-resistant credential.

Security is the minimum of these three dimensions. No adapter may upgrade a weak
dimension merely because another dimension is strong.

## Provider reality

Google documents S256 PKCE, RFC 9207 issuer responses, and DPoP protection for
refresh tokens used by confidential BFF clients. Its documented access token is
still `Bearer`, and its flow does not expose every PAR/RAR/resource-indicator
feature required by this repository's strict profile.

Microsoft Graph documents authorization code + S256 PKCE. Its generally
available documentation does not establish every strict-profile capability;
proof-of-possession token binding is currently documented with important
availability limitations. The adapter therefore reports unknown or unsupported
features instead of inferring them.
