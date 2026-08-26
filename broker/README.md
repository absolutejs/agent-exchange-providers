# `@absolutejs/agent-exchange-broker`

Executes one passkey-approved, purpose-bound Agent Exchange operation while
confining an upstream bearer access token to deterministic provider code. The
token is never returned to either agent, placed in the request, or serialized in
the receipt.

This assurance is deliberately weaker than a DPoP or mTLS sender-constrained
access token: compromise of the broker process can expose a live bearer token.
Use tenant-isolated encrypted credential storage, an atomic durable store,
restricted egress, short expiries, revocation, and aggressive rate limits.
