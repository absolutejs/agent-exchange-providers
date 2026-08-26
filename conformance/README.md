# @absolutejs/agent-exchange-provider-conformance

Shared capability checks, cryptographic DPoP verification, and black-box A2A
security tests for Agent Exchange providers. Provider adapters publish facts;
this package decides whether those facts meet the phishing-resistant OAuth
profile. A2A servers are exercised over their public protocol boundary without
depending on their implementation.

Unknown or unavailable features are failures, not optimistic defaults.

## A2A prepared-profile conformance

`evaluateAgentExchangeA2aConformance()` performs eight active checks:

- Agent Card discovery and same-origin A2A 1.0 JSON-RPC routing;
- extension parameters, skill media types, and declared authentication;
- authentication before parsing malformed A2A and preparation requests;
- distinct preparation and A2A credentials;
- `A2A-Extensions` negotiation;
- protected preparation followed by exact-reference execution;
- raw, hexadecimal, base64, and base64url leakage detection in tasks and
  receipts; and
- safe replay rejection or convergence on the original task.

The suite executes the supplied request. It requires the literal
`acknowledgeExecution: "sandbox-only"` and must never be aimed at production or
an endpoint that can submit a real credential:

```ts
import {
  assertAgentExchangeA2aConformance,
  type AgentExchangeA2aConformanceTarget,
} from "@absolutejs/agent-exchange-provider-conformance";

const target: AgentExchangeA2aConformanceTarget = {
  acknowledgeExecution: "sandbox-only",
  additionalSensitiveMarkers: [sandboxVerificationCode],
  a2aHeaders: ({ url }) => a2aTokenFor(url),
  createRequest: (purpose) => sandboxRequest(purpose),
  origin: "https://sandbox-recipient.example",
  preparationHeaders: ({ url }) => preparationTokenFor(url),
};

const report = await assertAgentExchangeA2aConformance(target);
```

`createRequest()` receives a purpose identifier and must return a fresh exchange
each time. The sandbox must use separate audience-bound credentials for the
preparation and A2A URLs. Put any simulated protected value that is not already
part of the request—such as a sandbox six-digit code—in
`additionalSensitiveMarkers`.

The report demonstrates observable protocol behavior for that sandbox run. It is
not a cryptographic audit, production authorization, penetration test, or claim
that an email/SMS bearer code is phishing-resistant.

## OAuth provider conformance

`evaluateOAuthProviderConformance()` evaluates declared authorization-code,
issuer-identification, PAR, S256 PKCE, RAR, resource-indicator, and
sender-constraint capabilities. `verifyDpopProof()` independently validates the
ES256 proof, public key, method, normalized target URI, timestamp, nonce, and
access-token hash.
