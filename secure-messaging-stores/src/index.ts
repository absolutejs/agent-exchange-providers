import type { AgentExchangeReceipt } from "@absolutejs/agent-exchange";
import type {
  AgentExchangeSecureMessagingReceiptSaveResult,
  AgentExchangeSecureMessagingReceiptStore,
} from "@absolutejs/agent-exchange-secure-messaging";

const encoder = new TextEncoder();
const MAXIMUM_IDENTIFIER_BYTES = 512;
const MAXIMUM_PAYLOAD_BYTES = 16 * 1024;

export type AgentExchangeReceiptRedisClient = {
  readonly eval: (
    script: string,
    keys: readonly string[],
    arguments_: readonly string[],
  ) => Promise<unknown>;
  readonly get: (key: string) => Promise<string | undefined | null>;
};

export type AgentExchangeReceiptPostgresClient = {
  readonly query: <Row = Record<string, unknown>>(
    text: string,
    values: readonly unknown[],
  ) => Promise<{ readonly rowCount: number; readonly rows: readonly Row[] }>;
};

export type AgentExchangeReceiptPostgresStore =
  AgentExchangeSecureMessagingReceiptStore & {
    readonly deleteExpired: (input: {
      readonly batchSize?: number;
      readonly now: number;
    }) => Promise<number>;
  };

export const AGENT_EXCHANGE_RECEIPT_POSTGRES_MIGRATION = `
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
`.trim();

export const AGENT_EXCHANGE_RECEIPT_REDIS_SAVE_SCRIPT = `
local current = redis.call('GET', KEYS[1])
if current then
  if current == ARGV[1] then return 'duplicate' end
  return 'conflict'
end
redis.call('SET', KEYS[1], ARGV[1], 'PXAT', ARGV[2])
return 'saved'
`.trim();

const POSTGRES_SAVE = `
INSERT INTO absolute_agent_exchange_secure_messaging_receipts
  (tenant_digest, exchange_digest, receipt_json, expires_at, save_token, created_at)
VALUES ($1, $2, $3, $4, $5, $6)
ON CONFLICT (tenant_digest, exchange_digest) DO UPDATE
  SET tenant_digest = absolute_agent_exchange_secure_messaging_receipts.tenant_digest
RETURNING receipt_json, expires_at, save_token
`.trim();

const POSTGRES_DELETE_EXPIRED = `
DELETE FROM absolute_agent_exchange_secure_messaging_receipts
WHERE ctid IN (
  SELECT ctid
  FROM absolute_agent_exchange_secure_messaging_receipts
  WHERE expires_at <= $1
  ORDER BY expires_at
  LIMIT $2
)
`.trim();

const fail = (): never => {
  throw new Error("Agent Exchange receipt store failed");
};

const boundedIdentifier = (value: string) => {
  if (
    value.length === 0 ||
    encoder.encode(value).byteLength > MAXIMUM_IDENTIFIER_BYTES
  )
    fail();
  return value;
};

const exactKeys = (
  value: Record<string, unknown>,
  allowed: readonly string[],
) => {
  const names = new Set(allowed);
  if (Object.keys(value).some((key) => !names.has(key))) fail();
};

const objectValue = (value: unknown): Record<string, unknown> => {
  if (typeof value !== "object" || value === null || Array.isArray(value))
    fail();
  return value as Record<string, unknown>;
};

const validateReceipt = (value: unknown): AgentExchangeReceipt => {
  const receipt = objectValue(value);
  exactKeys(receipt, [
    "assurance",
    "completedAt",
    "consentId",
    "exchangeId",
    "maximumUses",
    "modelObservedSecret",
    "processingMode",
    "reference",
    "status",
  ]);
  const assurance = objectValue(receipt.assurance);
  exactKeys(assurance, ["approval", "credential", "execution"]);
  const validAssurance =
    (assurance.approval === "standing-mandate" &&
      assurance.credential === "token-confined-broker" &&
      assurance.execution === "purpose-bound") ||
    (assurance.approval === "webauthn-verifier-bound" &&
      (assurance.credential === "origin-bound" ||
        assurance.credential === "sender-constrained" ||
        assurance.credential === "token-confined-broker") &&
      assurance.execution === "purpose-bound") ||
    (assurance.approval === "policy" &&
      (assurance.credential === "bearer" ||
        assurance.credential === "origin-bound" ||
        assurance.credential === "sender-constrained") &&
      (assurance.execution === "general" ||
        assurance.execution === "purpose-bound"));
  if (
    !validAssurance ||
    !Number.isSafeInteger(receipt.completedAt) ||
    typeof receipt.consentId !== "string" ||
    typeof receipt.exchangeId !== "string" ||
    receipt.maximumUses !== 1 ||
    receipt.modelObservedSecret !== false ||
    receipt.processingMode !== "tool-confined" ||
    (receipt.reference !== undefined &&
      typeof receipt.reference !== "string") ||
    receipt.status !== "submitted"
  )
    fail();
  boundedIdentifier(receipt.consentId as string);
  boundedIdentifier(receipt.exchangeId as string);
  if (
    typeof receipt.reference === "string" &&
    (encoder.encode(receipt.reference).byteLength === 0 ||
      encoder.encode(receipt.reference).byteLength > 2_048)
  )
    fail();
  return receipt as AgentExchangeReceipt;
};

const serialize = (receipt: AgentExchangeReceipt) => {
  validateReceipt(receipt);
  const serialized = JSON.stringify({
    assurance: {
      approval: receipt.assurance.approval,
      credential: receipt.assurance.credential,
      execution: receipt.assurance.execution,
    },
    completedAt: receipt.completedAt,
    consentId: receipt.consentId,
    exchangeId: receipt.exchangeId,
    maximumUses: receipt.maximumUses,
    modelObservedSecret: receipt.modelObservedSecret,
    processingMode: receipt.processingMode,
    ...(receipt.reference === undefined
      ? {}
      : { reference: receipt.reference }),
    status: receipt.status,
  });
  if (encoder.encode(serialized).byteLength > MAXIMUM_PAYLOAD_BYTES) fail();
  return serialized;
};

const deserialize = (serialized: string, expectedExchangeId: string) => {
  if (
    serialized.length === 0 ||
    encoder.encode(serialized).byteLength > MAXIMUM_PAYLOAD_BYTES
  )
    fail();
  try {
    const receipt = validateReceipt(JSON.parse(serialized));
    if (receipt.exchangeId !== expectedExchangeId) fail();
    return Object.freeze({
      ...receipt,
      assurance: Object.freeze({ ...receipt.assurance }),
    });
  } catch {
    return fail();
  }
};

const redisRecord = (stored: string) => {
  try {
    const record = objectValue(JSON.parse(stored));
    exactKeys(record, ["expiresAt", "receipt"]);
    if (!Number.isSafeInteger(record.expiresAt)) fail();
    return record;
  } catch {
    return fail();
  }
};

const databaseTimestamp = (value: unknown) => {
  const timestamp =
    typeof value === "string" && /^(?:0|[1-9][0-9]*)$/u.test(value)
      ? Number(value)
      : value;
  if (!Number.isSafeInteger(timestamp)) fail();
  return timestamp as number;
};

const base64url = (bytes: Uint8Array) => {
  let binary = "";
  for (const byte of bytes) binary += String.fromCharCode(byte);
  return btoa(binary)
    .replaceAll("+", "-")
    .replaceAll("/", "_")
    .replace(/=+$/u, "");
};

const digest = async (value: string) =>
  base64url(
    new Uint8Array(
      await crypto.subtle.digest("SHA-256", encoder.encode(value)),
    ),
  );

const storageIdentity = async (tenantId: string, exchangeId: string) => ({
  exchangeDigest: await digest(exchangeId),
  tenantDigest: await digest(tenantId),
});

const validateTimes = (expiresAt: number, now: number) => {
  if (
    !Number.isSafeInteger(expiresAt) ||
    !Number.isSafeInteger(now) ||
    expiresAt <= now
  )
    fail();
};

const saveResult = (
  value: unknown,
): AgentExchangeSecureMessagingReceiptSaveResult => {
  if (value === "saved" || value === "duplicate" || value === "conflict")
    return value;
  return fail();
};

export const createMemoryAgentExchangeReceiptStore = (options: {
  readonly tenantId: string;
}): AgentExchangeSecureMessagingReceiptStore => {
  boundedIdentifier(options.tenantId);
  const records = new Map<
    string,
    { readonly expiresAt: number; readonly serialized: string }
  >();
  return Object.freeze({
    get: async ({ exchangeId, now }) => {
      boundedIdentifier(exchangeId);
      if (!Number.isSafeInteger(now)) fail();
      const current = records.get(exchangeId);
      if (current === undefined) return undefined;
      if (current.expiresAt <= now) {
        records.delete(exchangeId);
        return undefined;
      }
      return Object.freeze({
        expiresAt: current.expiresAt,
        receipt: deserialize(current.serialized, exchangeId),
      });
    },
    save: async ({ expiresAt, now, receipt }) => {
      validateTimes(expiresAt, now);
      const serialized = serialize(receipt);
      const current = records.get(receipt.exchangeId);
      if (current !== undefined && current.expiresAt <= now)
        records.delete(receipt.exchangeId);
      const live = records.get(receipt.exchangeId);
      if (live !== undefined)
        return live.expiresAt === expiresAt && live.serialized === serialized
          ? "duplicate"
          : "conflict";
      records.set(receipt.exchangeId, { expiresAt, serialized });
      return "saved";
    },
  });
};

export const createRedisAgentExchangeReceiptStore = (options: {
  readonly client: AgentExchangeReceiptRedisClient;
  readonly keyPrefix?: string;
  readonly tenantId: string;
}): AgentExchangeSecureMessagingReceiptStore => {
  boundedIdentifier(options.tenantId);
  const prefix = options.keyPrefix ?? "absolute:agent-exchange:sm-receipt:";
  if (prefix.length === 0 || prefix.length > 256) fail();
  const key = async (exchangeId: string) => {
    boundedIdentifier(exchangeId);
    const identity = await storageIdentity(options.tenantId, exchangeId);
    return `${prefix}${identity.tenantDigest}:${identity.exchangeDigest}`;
  };
  return Object.freeze({
    get: async ({ exchangeId, now }) => {
      if (!Number.isSafeInteger(now)) fail();
      const stored = await options.client.get(await key(exchangeId));
      if (stored === undefined || stored === null) return undefined;
      const record = redisRecord(stored);
      if ((record.expiresAt as number) <= now) return undefined;
      return Object.freeze({
        expiresAt: record.expiresAt as number,
        receipt: deserialize(JSON.stringify(record.receipt), exchangeId),
      });
    },
    save: async ({ expiresAt, now, receipt }) => {
      validateTimes(expiresAt, now);
      const serialized = JSON.stringify({
        expiresAt,
        receipt: JSON.parse(serialize(receipt)) as unknown,
      });
      return saveResult(
        await options.client.eval(
          AGENT_EXCHANGE_RECEIPT_REDIS_SAVE_SCRIPT,
          [await key(receipt.exchangeId)],
          [serialized, String(expiresAt)],
        ),
      );
    },
  });
};

export const createPostgresAgentExchangeReceiptStore = (options: {
  readonly client: AgentExchangeReceiptPostgresClient;
  readonly tenantId: string;
}): AgentExchangeReceiptPostgresStore => {
  boundedIdentifier(options.tenantId);
  return Object.freeze({
    deleteExpired: async ({ batchSize = 1_000, now }) => {
      if (
        !Number.isSafeInteger(now) ||
        !Number.isSafeInteger(batchSize) ||
        batchSize < 1 ||
        batchSize > 10_000
      )
        fail();
      const result = await options.client.query(POSTGRES_DELETE_EXPIRED, [
        now,
        batchSize,
      ]);
      return result.rowCount;
    },
    get: async ({ exchangeId, now }) => {
      boundedIdentifier(exchangeId);
      if (!Number.isSafeInteger(now)) fail();
      const identity = await storageIdentity(options.tenantId, exchangeId);
      const result = await options.client.query<{
        readonly expires_at: unknown;
        readonly receipt_json: unknown;
      }>(
        "SELECT receipt_json, expires_at FROM absolute_agent_exchange_secure_messaging_receipts WHERE tenant_digest = $1 AND exchange_digest = $2 AND expires_at > $3",
        [identity.tenantDigest, identity.exchangeDigest, now],
      );
      const stored = result.rows[0]?.receipt_json;
      if (stored === undefined) return undefined;
      if (typeof stored !== "string") return fail();
      return Object.freeze({
        expiresAt: databaseTimestamp(result.rows[0]?.expires_at),
        receipt: deserialize(stored, exchangeId),
      });
    },
    save: async ({ expiresAt, now, receipt }) => {
      validateTimes(expiresAt, now);
      const serialized = serialize(receipt);
      const identity = await storageIdentity(
        options.tenantId,
        receipt.exchangeId,
      );
      const saveToken = base64url(crypto.getRandomValues(new Uint8Array(32)));
      const result = await options.client.query<{
        readonly expires_at: unknown;
        readonly receipt_json: unknown;
        readonly save_token: unknown;
      }>(POSTGRES_SAVE, [
        identity.tenantDigest,
        identity.exchangeDigest,
        serialized,
        expiresAt,
        saveToken,
        now,
      ]);
      const row = result.rows[0] ?? fail();
      if (row.save_token === saveToken) return "saved";
      if (typeof row.receipt_json !== "string") fail();
      return databaseTimestamp(row.expires_at) === expiresAt &&
        row.receipt_json === serialized
        ? "duplicate"
        : "conflict";
    },
  });
};
