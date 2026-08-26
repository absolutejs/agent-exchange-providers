# `@absolutejs/agent-exchange-a2a`

Interoperable A2A client and server adapters for Agent Exchange. The adapter
discovers an A2A 1.0 Agent Card, requires the Agent Exchange extension to be
advertised as required, activates it through `A2A-Extensions`, and places only
the core package's opaque safe reference in task history.

The server authenticates the caller through the host-supplied A2A authorization
function, then passes that verified caller and opaque reference to a deterministic
executor. The executor must resolve the full request from trusted server state,
verify the OAuth delegation and any signed standing mandate, and authorize it
before source access. Results are projected into a bounded redacted receipt.

```ts
import {
  connectAgentExchangeA2a,
  createAgentExchangeA2aHandler,
} from "@absolutejs/agent-exchange-a2a";
```

The adapter intentionally does not transmit signed mandates, OAuth tokens,
mailbox credentials, encrypted envelopes, account references, or verification
codes through A2A. See the
[extension specification](https://github.com/absolutejs/agent-exchange/blob/main/extensions/a2a/v1.md).

This is an experimental 0.x package and has not been independently audited.
