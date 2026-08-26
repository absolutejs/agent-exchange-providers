import type {
  AgentExchangeMandateConsumeResult,
  AgentExchangeMandateStore,
} from "@absolutejs/agent-exchange";

const encoder = new TextEncoder();

export type MandatePostgresClient = {
  readonly query: <Row = Record<string, unknown>>(
    text: string,
    values: readonly unknown[],
  ) => Promise<{ readonly rowCount: number; readonly rows: readonly Row[] }>;
};

export type MandateRedisClient = {
  readonly eval: (
    script: string,
    keys: readonly string[],
    arguments_: readonly string[],
  ) => Promise<unknown>;
};

export const AGENT_EXCHANGE_MANDATE_POSTGRES_MIGRATION = `
CREATE TABLE IF NOT EXISTS absolute_agent_exchange_mandates (
  mandate_id TEXT PRIMARY KEY,
  issuer_authority TEXT NOT NULL,
  issuer_subject TEXT NOT NULL,
  maximum_uses INTEGER NOT NULL CHECK (maximum_uses > 0),
  use_count INTEGER NOT NULL DEFAULT 0 CHECK (use_count >= 0),
  consumed_exchange_digests TEXT[] NOT NULL DEFAULT '{}',
  expires_at BIGINT NOT NULL,
  revoked_at BIGINT
);
CREATE INDEX IF NOT EXISTS absolute_agent_exchange_mandates_expiry_idx
  ON absolute_agent_exchange_mandates (expires_at);
`.trim();

const POSTGRES_CONSUME = `
WITH updated AS (
  UPDATE absolute_agent_exchange_mandates
  SET use_count = use_count + 1,
      consumed_exchange_digests = array_append(consumed_exchange_digests, $2)
  WHERE mandate_id = $1
    AND expires_at > $3
    AND revoked_at IS NULL
    AND use_count < maximum_uses
    AND NOT ($2 = ANY(consumed_exchange_digests))
  RETURNING 1
), current AS (
  SELECT maximum_uses, use_count, consumed_exchange_digests, revoked_at
  FROM absolute_agent_exchange_mandates
  WHERE mandate_id = $1 AND expires_at > $3
)
SELECT CASE
  WHEN EXISTS (SELECT 1 FROM updated) THEN 'consumed'
  WHEN NOT EXISTS (SELECT 1 FROM current) THEN 'unknown'
  WHEN (SELECT revoked_at FROM current) IS NOT NULL THEN 'revoked'
  WHEN $2 = ANY((SELECT consumed_exchange_digests FROM current)) THEN 'replay'
  WHEN (SELECT use_count FROM current) >= (SELECT maximum_uses FROM current) THEN 'exhausted'
  ELSE 'unknown'
END AS status
`.trim();

const consumeResult = (value: unknown): AgentExchangeMandateConsumeResult => {
  if (
    value === "consumed" ||
    value === "exhausted" ||
    value === "replay" ||
    value === "revoked" ||
    value === "unknown"
  )
    return value;
  throw new Error("mandate store returned an invalid result");
};

export const createPostgresAgentExchangeMandateStore = (options: {
  readonly client: MandatePostgresClient;
}): AgentExchangeMandateStore =>
  Object.freeze({
    consume: async ({ exchangeId, mandateId, now }) => {
      const result = await options.client.query<{ readonly status: unknown }>(
        POSTGRES_CONSUME,
        [mandateId, await digest(exchangeId), now],
      );
      return consumeResult(result.rows[0]?.status);
    },
    register: async ({ expiresAt, issuer, mandateId, maximumUses }) => {
      const result = await options.client.query(
        "INSERT INTO absolute_agent_exchange_mandates (mandate_id, issuer_authority, issuer_subject, maximum_uses, expires_at) VALUES ($1, $2, $3, $4, $5) ON CONFLICT (mandate_id) DO NOTHING",
        [mandateId, issuer.authority, issuer.subject, maximumUses, expiresAt],
      );
      return result.rowCount === 1;
    },
    revoke: async ({ issuer, mandateId, now }) => {
      const result = await options.client.query(
        "UPDATE absolute_agent_exchange_mandates SET revoked_at = COALESCE(revoked_at, $4) WHERE mandate_id = $1 AND issuer_authority = $2 AND issuer_subject = $3",
        [mandateId, issuer.authority, issuer.subject, now],
      );
      return result.rowCount === 1;
    },
  });

export const AGENT_EXCHANGE_MANDATE_REDIS_REGISTER_SCRIPT = `
if redis.call('EXISTS', KEYS[1]) == 1 then return 0 end
redis.call('HSET', KEYS[1],
  'issuer_authority', ARGV[1],
  'issuer_subject', ARGV[2],
  'expires_at', ARGV[3],
  'maximum_uses', ARGV[4],
  'uses', '0',
  'revoked_at', '')
redis.call('PEXPIREAT', KEYS[1], ARGV[3])
return 1
`.trim();

export const AGENT_EXCHANGE_MANDATE_REDIS_CONSUME_SCRIPT = `
if redis.call('EXISTS', KEYS[1]) == 0 then return 'unknown' end
local expires_at = tonumber(redis.call('HGET', KEYS[1], 'expires_at'))
if not expires_at or expires_at <= tonumber(ARGV[1]) then return 'unknown' end
if redis.call('HGET', KEYS[1], 'revoked_at') ~= '' then return 'revoked' end
local use_key = 'exchange:' .. ARGV[2]
if redis.call('HEXISTS', KEYS[1], use_key) == 1 then return 'replay' end
local uses = tonumber(redis.call('HGET', KEYS[1], 'uses'))
local maximum_uses = tonumber(redis.call('HGET', KEYS[1], 'maximum_uses'))
if not uses or not maximum_uses or uses >= maximum_uses then return 'exhausted' end
redis.call('HSET', KEYS[1], use_key, ARGV[1])
redis.call('HINCRBY', KEYS[1], 'uses', 1)
return 'consumed'
`.trim();

export const AGENT_EXCHANGE_MANDATE_REDIS_REVOKE_SCRIPT = `
if redis.call('EXISTS', KEYS[1]) == 0 then return 0 end
if redis.call('HGET', KEYS[1], 'issuer_authority') ~= ARGV[1] then return 0 end
if redis.call('HGET', KEYS[1], 'issuer_subject') ~= ARGV[2] then return 0 end
if redis.call('HGET', KEYS[1], 'revoked_at') == '' then
  redis.call('HSET', KEYS[1], 'revoked_at', ARGV[3])
end
return 1
`.trim();

const digest = async (value: string): Promise<string> => {
  const bytes = new Uint8Array(
    await crypto.subtle.digest("SHA-256", encoder.encode(value)),
  );
  let binary = "";
  for (const byte of bytes) binary += String.fromCharCode(byte);
  return btoa(binary)
    .replaceAll("+", "-")
    .replaceAll("/", "_")
    .replace(/=+$/u, "");
};

export const createRedisAgentExchangeMandateStore = (options: {
  readonly client: MandateRedisClient;
  readonly keyPrefix?: string;
}): AgentExchangeMandateStore => {
  const prefix = options.keyPrefix ?? "absolute:agent-exchange:mandate:";
  if (prefix.length < 1 || prefix.length > 256)
    throw new Error("invalid mandate Redis key prefix");
  const key = async (mandateId: string) =>
    `${prefix}${await digest(mandateId)}`;

  return Object.freeze({
    consume: async ({ exchangeId, mandateId, now }) =>
      consumeResult(
        await options.client.eval(
          AGENT_EXCHANGE_MANDATE_REDIS_CONSUME_SCRIPT,
          [await key(mandateId)],
          [String(now), await digest(exchangeId)],
        ),
      ),
    register: async ({ expiresAt, issuer, mandateId, maximumUses }) =>
      (await options.client.eval(
        AGENT_EXCHANGE_MANDATE_REDIS_REGISTER_SCRIPT,
        [await key(mandateId)],
        [
          issuer.authority,
          issuer.subject,
          String(expiresAt),
          String(maximumUses),
        ],
      )) === 1,
    revoke: async ({ issuer, mandateId, now }) =>
      (await options.client.eval(
        AGENT_EXCHANGE_MANDATE_REDIS_REVOKE_SCRIPT,
        [await key(mandateId)],
        [issuer.authority, issuer.subject, String(now)],
      )) === 1,
  });
};
