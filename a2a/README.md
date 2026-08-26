# `@absolutejs/agent-exchange-a2a`

Interoperable A2A client and server adapters for Agent Exchange. The adapter
discovers an A2A 1.0 Agent Card, requires the Agent Exchange extension to be
advertised, activates it through `A2A-Extensions`, and places only the core
package's opaque safe reference in task history. Dedicated cards can require the
extension; shared cards can advertise it as optional.

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

## Prepared exchanges

A recipient that needs the complete request before the opaque A2A signal can
advertise a same-origin preparation endpoint in the extension parameters:

```ts
const handler = createAgentExchangeA2aHandler({
  agentCard,
  authorize,
  execute,
  preparationEndpoint: "https://recipient.example/agent-exchange/requests",
  taskStore,
});
```

`connectAgentExchangeA2a()` discovers that endpoint. Each `send(request)` posts
the complete request there and verifies that the response contains the exact
derived opaque reference before sending anything on A2A. Preparation and A2A
credentials remain separate:

```ts
const client = await connectAgentExchangeA2a({
  headers: () => a2aAuthorizationHeaders(),
  origin: "https://recipient.example",
  preparationHeaders: () => preparationAuthorizationHeaders(),
});

const receipt = await client.send(request);
```

The preparation endpoint uses
`application/vnd.absolutejs.agent-exchange-preparation+json`, accepts
`{ request }`, and returns `{ reference }`. It must authenticate the delegated
caller, validate and durably protect the request, reject replay, and return
`Cache-Control: no-store`. The adapter rejects cross-origin preparation URLs,
redirects, response media-type substitution, extra response fields, and any
reference that differs from the request.

Hosts with an existing trusted preparation channel can instead supply a
`prepare(request, context)` callback. Omitting both an advertised endpoint and a
callback retains out-of-band preparation mode.

The adapter intentionally does not transmit signed mandates, OAuth tokens,
mailbox credentials, encrypted envelopes, account references, or verification
codes through A2A. See the
[extension specification](https://github.com/absolutejs/agent-exchange/blob/main/extensions/a2a/v1.md).

This is an experimental 0.x package and has not been independently audited.
