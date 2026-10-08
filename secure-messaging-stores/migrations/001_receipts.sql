CREATE TABLE IF NOT EXISTS absolute_agent_exchange_secure_messaging_receipts (
  tenant_digest TEXT NOT NULL,
  exchange_digest TEXT NOT NULL,
  receipt_json TEXT NOT NULL,
  expires_at BIGINT NOT NULL,
  save_token TEXT NOT NULL,
  created_at BIGINT NOT NULL,
  PRIMARY KEY (tenant_digest, exchange_digest),
  CHECK (octet_length(receipt_json) BETWEEN 1 AND 16384),
  CHECK (expires_at > created_at)
);
CREATE INDEX IF NOT EXISTS absolute_agent_exchange_sm_receipts_expiry_idx
  ON absolute_agent_exchange_secure_messaging_receipts (expires_at);
