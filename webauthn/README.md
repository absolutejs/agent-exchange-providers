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
