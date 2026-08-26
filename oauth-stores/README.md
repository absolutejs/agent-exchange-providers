# @absolutejs/agent-exchange-oauth-stores

One-time authorization session stores for the hardened OAuth flow:

- in-memory for tests and single-process development;
- Redis through a minimal atomic `putIfAbsent` / `take` client;
- PostgreSQL through a minimal parameterized query client.

Durable stores require a session sealer. State values are hashed before becoming
storage keys, and code verifiers are sealed before persistence.
