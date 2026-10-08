# Security

Create one store instance per authenticated tenant and never derive `tenantId`
from an unverified request field. Use separate database credentials or Redis
namespaces as an additional boundary for deployments requiring hard tenant
isolation.

Apply the exported PostgreSQL migration before serving traffic and run bounded
expiry cleanup repeatedly. Alert on cleanup lag and on any `conflict` result;
both are security-relevant operational signals. Redis deployments must enable
persistence and replication appropriate to their delivery guarantees. An
evicted receipt can cause a request retry, so downstream execution must still
use the exchange ID as its idempotency key.

Back up and restore the receipt table together with secure-messaging state and
outbox data. Never log receipt payloads, tenant IDs, exchange IDs, Redis values,
or database query parameters. The stored receipt is redacted but remains
security metadata.

Report vulnerabilities privately through GitHub Security Advisories for
`absolutejs/agent-exchange-providers`.
