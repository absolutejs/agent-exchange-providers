# @absolutejs/agent-exchange-webauthn

An interchangeable `AgentExchangeApprovalProvider` that binds a user-verified
WebAuthn assertion to the exact Agent Exchange request digest.

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
`@absolutejs/agent-exchange@0.2`.

For local development only, `allowInsecureLocalhost: true` permits an HTTP
`localhost` origin and RP ID. It does not permit arbitrary HTTP hosts.
