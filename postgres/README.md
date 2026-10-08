# @absolutejs/agent-exchange-postgres

PostgreSQL persistence for Agent Exchange request metadata, receipts, recipient
replay protection, and token-confined broker execution claims.

Apply `AGENT_EXCHANGE_POSTGRES_MIGRATION` during deployment. Create stores with
`createPostgresAgentExchangeStores({ client, tenantId })`; the client implements
`query(sql, parameters)` returning `{ rows, rowCount }`. All operations bind the
configured tenant. Broker calls for another tenant fail closed.

The application must authorize requests with Agency and verify standing mandates
before executing a broker. These stores are persistence, not authorization.
Use `@absolutejs/agent-exchange-mandate-stores` for signed mandate use limits and
revocation, and the Agency PostgreSQL adapter for execution leases.

Requests and receipts are immutable first-writer records. Replay protection rejects
any second delivery for the same exchange, even with a different nonce. Broker
claims are never automatically retried after an error or an unknown outcome;
create a newly authorized exchange instead. Revocation before a claim leaves a
tombstone so a later claim cannot start execution. Revocation cannot cancel a
provider operation that has already begun.

Only declared metadata is persisted. Do not put tokens, codes, message bodies or
other secrets in declared metadata fields. Optional free-form receipt references
are deliberately omitted. The stores do not persist payloads or provider tokens.
Expired metadata and tombstones may be pruned only after all corresponding leases,
requests and envelopes have expired; no automatic deletion is enabled.

Run `bun run check:package`. Set `AGENT_EXCHANGE_TEST_DATABASE_URL` to run the real
PostgreSQL concurrency tests in an isolated temporary schema.
