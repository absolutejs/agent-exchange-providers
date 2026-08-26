# `@absolutejs/agent-exchange-http-destination`

A fixed-endpoint HTTPS adapter for submitting a six-digit email verification code
without exposing that code to an agent or returning it in the receipt.

```ts
import { createAgentExchangeHttpDestination } from "@absolutejs/agent-exchange-http-destination";

const adapter = createAgentExchangeHttpDestination({
  authorization: ({ tenantId }) => credentials.forTenant(tenantId),
  challengeField: "challenge",
  endpoint: "https://accounts.example.com/api/verify",
  id: "accounts-example",
  operations: ["verification.submit"],
});
```

The endpoint is deployment configuration, never a per-request URL. It must use
HTTPS and cannot contain URL credentials, a query, or a fragment. Requests omit
ambient browser credentials, disable referrers and caching, reject redirects,
carry an idempotency key, and time out. Response bodies are discarded and never
become agent-visible output.

`authorization` is a BYO credential resolver. Paid hosted credential custody
belongs in AbsoluteJS PaaS; the open package does not include third-party secrets.
