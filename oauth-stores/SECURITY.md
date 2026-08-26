# Security

Redis `take` and PostgreSQL `DELETE ... RETURNING` must be atomic. Never emulate
consumption with separate read and delete operations. Keep the session-sealing key
outside the database and cache, preferably in a KMS/HSM or non-exportable platform
key store.
