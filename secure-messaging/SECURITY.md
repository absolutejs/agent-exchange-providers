# Security

This adapter requires an authenticated `strict-e2ee` secure-messaging
conversation. It does not turn a bearer email code into a phishing-resistant
credential. A standing mandate or request-bound WebAuthn approval authorizes the
automation; the recipient agent still executes only one exact purpose-bound
operation through a deterministic sink.

Bind every requester's and recipient's Agent Exchange `deviceId` to the
authenticated messaging device. Reject requests before opening the inner Agent
Exchange envelope when mandate verification, conversation routing, identity,
expiry, or purpose does not match exactly.

Use `SecureMessagingClient.receiveAndHandle()` to process this protocol. Calling
ordinary `receive()` acknowledges before Agent Exchange processing and therefore
does not provide the required crash boundary. Handler side effects must use the
exchange ID as an idempotency key. A crash before the atomic secure-messaging
state/outbox commit deliberately retries the request.

Production receipt stores must be durable and tenant-scoped. They must reject a
second, different receipt for the same exchange ID. Message plaintext buffers
are transferred to the handler and wiped by secure messaging; never log decoded
requests, inner ciphertext, mandate JWS values, or receipts from an untrusted
parser error.

Report vulnerabilities privately through GitHub Security Advisories for
`absolutejs/agent-exchange-providers`.
