# `@absolutejs/agent-exchange-secure-messaging-stores`

Tenant-scoped, atomic receipt stores for
`@absolutejs/agent-exchange-secure-messaging`. The package provides memory,
Redis, and PostgreSQL implementations behind the same receipt-store contract.

```ts
const receipts = createRedisAgentExchangeReceiptStore({
  client: redisAdapter,
  tenantId: authenticatedTenant.id,
});
```

The tenant is bound when a store is constructed; callers cannot select a tenant
per operation. Tenant and exchange identifiers are SHA-256 digested before use
in keys. Receipts are strictly parsed, size bounded, expiration aware, and
compared as canonical JSON. Saving an identical receipt and expiry returns
`duplicate`; any different receipt or expiry for that live key returns
`conflict`.

## Redis adapter

Implement `get(key)` and `eval(script, keys, arguments_)` with the official
client of your choice. The exported Lua script performs compare-or-insert and
absolute expiration (`PXAT`) as one Redis operation. Do not replace it with a
client-side `GET` followed by `SET`.

## PostgreSQL adapter and migration

Run `AGENT_EXCHANGE_RECEIPT_POSTGRES_MIGRATION` through your normal migration
system before constructing the store. The same idempotent SQL ships at the
exported `./migrations/postgres.sql` package subpath for migration tools. Pass a
client with a parameterized `query(text, values)` method. Save uses one `INSERT ... ON CONFLICT ...
RETURNING` statement, including a random per-attempt token, to distinguish a new
write from duplicate and conflicting concurrent writes without a read/write
race.

Call `deleteExpired({ now })` from a repeatable maintenance job until it returns
zero. It deletes at most 1,000 rows per call by default; `batchSize` is bounded
to 10,000. Redis expiry is automatic.

The memory store is process-local and intended for tests and examples only.

Licensed under Apache-2.0.
