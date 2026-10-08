# @absolutejs/agent-exchange-webauthn

An interchangeable `AgentExchangeApprovalProvider` that binds a user-verified
WebAuthn assertion to the exact Agent Exchange request digest.

It also provides `createWebAuthnAgentExchangeMandateApprovalProvider()` for
standing mandates. That provider recomputes the domain-separated challenge over
the complete mandate draft and requires the issuer authority and subject to match
the verifier before beginning or verifying the ceremony.

```ts
const approvalProvider = createWebAuthnAgentExchangeApprovalProvider({
  adapter,
  credentialStore,
  origin: "https://app.example.com",
  resolveUserId: async ({ subject }) => subject,
  rpId: "example.com",
});
```

The provider requires HTTPS, an RP ID valid for the configured verifier origin,
an exact caller-provided challenge, user verification, credential ownership, and
safe signature-counter progression. It does not persist raw assertions.

Use the resulting provider with the phishing-resistant assurance profile in
`@absolutejs/agent-exchange@0.4`.

For local development only, `allowInsecureLocalhost: true` permits an HTTP
`localhost` origin and RP ID. It does not permit arbitrary HTTP hosts.

## Browser approval

Import `approveAgentExchangeWithPasskey` from
`@absolutejs/agent-exchange-webauthn/client`. Call it from the user's confirmation
button after displaying the exact service, teammate, expiry, and use limit.
Provide `begin()` (returns `approvalId` and WebAuthn `options`) and `verify()`
(receives the same approval ID and the authenticator response). The helper uses
SimpleWebAuthn's browser implementation and does not approve or persist a mandate
itself. The server must consume an Auth challenge bound to purpose, user and
session before using the mandate approval provider.

Version 0.5.0 requires Auth 0.89.x, whose credential stores prevent owner/key
replacement and counter rollback and provide durable one-use challenge stores.
