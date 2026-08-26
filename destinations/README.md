# `@absolutejs/agent-exchange-destinations`

Deterministic, interchangeable destination adapters for Agent Exchange.

The registry selects exactly one adapter using the request's exact HTTPS origin,
operation, and secret kind. Duplicate routes, origin lookalikes, non-tool-confined
requests, and results that reflect the protected value fail closed.

```ts
import { createAgentExchangeDestinationRegistry } from "@absolutejs/agent-exchange-destinations";

const destinations = createAgentExchangeDestinationRegistry([myAdapter]);
await destinations.submit({ plaintext, request, tenantId });
```

Adapters receive an isolated mutable copy of the protected bytes. The registry
clears that copy after submission; the caller remains responsible for clearing
its own buffer.
