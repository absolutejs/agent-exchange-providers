# `@absolutejs/agent-exchange-secure-messaging`

An interchangeable Agent Exchange transport over authenticated AbsoluteJS
secure messaging. It carries the complete request, the already protected Agent
Exchange envelope, and a standing-mandate JWS inside a `strict-e2ee` conversation.
Only a redacted receipt returns.

```ts
const receipts = createMemoryAgentExchangeSecureMessagingReceiptStore();

const transport = createAgentExchangeSecureMessagingTransport({
  client: requesterMessaging,
  receipts,
  resolveRoute: (request) => ({
    conversationId: conversationFor(request.recipient),
    recipientDeviceId: request.recipient.deviceId!,
  }),
  resolveSignedMandate: (request) => mandates.get(request.mandateId!),
});

const handler = createAgentExchangeSecureMessagingHandler({
  authorizeRequest: ({ delivery, signedMandate }) =>
    mandateAuthority.authorize({
      expectedIssuer: owner,
      request: delivery.request,
      signedMandate,
    }),
  localDeviceId: "recipient-device",
  receipts,
  receiver,
});

await recipientMessaging.receiveAndHandle(handler);
await requesterMessaging.receiveAndHandle(handler);
```

Both request and receipt purposes are fixed authenticated MLS metadata. The
adapter requires `request.requester.deviceId` and `request.recipient.deviceId`,
checks them against the authenticated sending and local devices, validates a
strict no-extension wire format, and bounds every identifier, JWS, envelope, and
frame lifetime.

`createMemoryAgentExchangeSecureMessagingReceiptStore()` is for examples and
tests. Production deployments should implement the same receipt-store contract
with tenant-scoped durable storage and conflict detection.

The recipient must use `receiveAndHandle()`, not ordinary `receive()`. This
atomically queues the encrypted receipt with the inbound replay receipt and
advanced MLS state before acknowledging delivery. Deterministic sinks must use
the exchange ID as their downstream idempotency key so a crash immediately
before that commit remains safe.

Licensed under Apache-2.0.
