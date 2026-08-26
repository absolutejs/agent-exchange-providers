# `@absolutejs/agent-exchange-mandate-stores`

Atomic PostgreSQL and Redis implementations of the
`AgentExchangeMandateStore` contract. They register signed mandates, reject
unknown or expired records, consume each exchange ID once, enforce total use
limits, and make revocation effective before later execution.

Apply `AGENT_EXCHANGE_MANDATE_POSTGRES_MIGRATION` before constructing the
PostgreSQL adapter. The Redis adapter uses single Lua scripts for each state
transition and expiry at the mandate deadline.

This is an experimental `0.x` package and has not been independently audited.
