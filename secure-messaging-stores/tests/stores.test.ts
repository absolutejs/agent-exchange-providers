import type { AgentExchangeReceipt } from "@absolutejs/agent-exchange";
import { describe, expect, test } from "bun:test";
import {
  AGENT_EXCHANGE_RECEIPT_POSTGRES_MIGRATION,
  AGENT_EXCHANGE_RECEIPT_REDIS_SAVE_SCRIPT,
  createMemoryAgentExchangeReceiptStore,
  createPostgresAgentExchangeReceiptStore,
  createRedisAgentExchangeReceiptStore,
  type AgentExchangeReceiptPostgresClient,
  type AgentExchangeReceiptRedisClient,
} from "../src";

const now = 1_800_000_000_000;
const expiresAt = now + 60_000;
const receipt = (completedAt = now + 1): AgentExchangeReceipt => ({
  assurance: {
    approval: "standing-mandate",
    credential: "token-confined-broker",
    execution: "purpose-bound",
  },
  completedAt,
  consentId: "mandate-1",
  exchangeId: "exchange-1",
  maximumUses: 1,
  modelObservedSecret: false,
  processingMode: "tool-confined",
  reference: "accepted",
  status: "submitted",
});

describe("memory receipt store", () => {
  test("atomically classifies concurrent saves and expires records", async () => {
    const store = createMemoryAgentExchangeReceiptStore({
      tenantId: "tenant-a",
    });
    const results = await Promise.all(
      Array.from({ length: 20 }, () =>
        store.save({ expiresAt, now, receipt: receipt() }),
      ),
    );
    expect(results.filter((result) => result === "saved")).toHaveLength(1);
    expect(results.filter((result) => result === "duplicate")).toHaveLength(19);
    await expect(
      store.save({ expiresAt, now, receipt: receipt(now + 2) }),
    ).resolves.toBe("conflict");
    await expect(
      store.get({ exchangeId: "exchange-1", now: expiresAt }),
    ).resolves.toBeUndefined();
  });
});

test("Redis hashes tenant and exchange IDs and saves with one Lua operation", async () => {
  const calls: {
    arguments_: readonly string[];
    keys: readonly string[];
    script: string;
  }[] = [];
  let stored: string | undefined;
  const client: AgentExchangeReceiptRedisClient = {
    eval: async (script, keys, arguments_) => {
      calls.push({ arguments_, keys, script });
      if (stored === undefined) {
        stored = arguments_[0];
        return "saved";
      }
      return stored === arguments_[0] ? "duplicate" : "conflict";
    },
    get: async () => stored,
  };
  const store = createRedisAgentExchangeReceiptStore({
    client,
    tenantId: "tenant-private",
  });
  await expect(
    store.save({ expiresAt, now, receipt: receipt() }),
  ).resolves.toBe("saved");
  await expect(
    store.save({ expiresAt, now, receipt: receipt() }),
  ).resolves.toBe("duplicate");
  expect(calls[0]?.script).toBe(AGENT_EXCHANGE_RECEIPT_REDIS_SAVE_SCRIPT);
  expect(calls[0]?.keys[0]).not.toContain("tenant-private");
  expect(calls[0]?.keys[0]).not.toContain("exchange-1");
  expect(calls[0]?.arguments_[1]).toBe(String(expiresAt));
  await expect(store.get({ exchangeId: "exchange-1", now })).resolves.toEqual({
    expiresAt,
    receipt: receipt(),
  });
});

test("PostgreSQL uses tenant-scoped atomic upsert and bounded cleanup", async () => {
  const queries: {
    readonly text: string;
    readonly values: readonly unknown[];
  }[] = [];
  let firstToken: unknown;
  let firstPayload: unknown;
  const client: AgentExchangeReceiptPostgresClient = {
    query: async <Row>(text: string, values: readonly unknown[]) => {
      queries.push({ text, values });
      if (text.startsWith("INSERT")) {
        firstPayload ??= values[2];
        firstToken ??= values[4];
        return {
          rowCount: 1,
          rows: [
            {
              expires_at: String(expiresAt),
              receipt_json: firstPayload,
              save_token: firstToken,
            },
          ] as Row[],
        };
      }
      return { rowCount: text.startsWith("DELETE") ? 3 : 0, rows: [] };
    },
  };
  const store = createPostgresAgentExchangeReceiptStore({
    client,
    tenantId: "tenant-private",
  });
  await expect(
    store.save({ expiresAt, now, receipt: receipt() }),
  ).resolves.toBe("saved");
  await expect(
    store.save({ expiresAt, now, receipt: receipt() }),
  ).resolves.toBe("duplicate");
  await expect(store.deleteExpired({ batchSize: 50, now })).resolves.toBe(3);
  expect(queries[0]?.text).toContain("ON CONFLICT");
  expect(queries[0]?.text).toContain("RETURNING");
  expect(queries[0]?.values[0]).not.toBe("tenant-private");
  expect(queries[0]?.values[1]).not.toBe("exchange-1");
  expect(queries[2]?.values).toEqual([now, 50]);
  expect(AGENT_EXCHANGE_RECEIPT_POSTGRES_MIGRATION).toContain(
    "PRIMARY KEY (tenant_digest, exchange_digest)",
  );
});

test("rejects expired writes and malformed durable records", async () => {
  const memory = createMemoryAgentExchangeReceiptStore({
    tenantId: "tenant-a",
  });
  await expect(
    memory.save({ expiresAt: now, now, receipt: receipt() }),
  ).rejects.toThrow("receipt store failed");
  const redis = createRedisAgentExchangeReceiptStore({
    client: { eval: async () => "saved", get: async () => "{bad" },
    tenantId: "tenant-a",
  });
  await expect(redis.get({ exchangeId: "exchange-1", now })).rejects.toThrow(
    "receipt store failed",
  );
});

test("shipped PostgreSQL migration matches the exported repeatable SQL", async () => {
  const shipped = await Bun.file(
    new URL("../migrations/001_receipts.sql", import.meta.url),
  ).text();
  expect(shipped.trim()).toBe(AGENT_EXCHANGE_RECEIPT_POSTGRES_MIGRATION);
  expect(shipped).toContain("CREATE TABLE IF NOT EXISTS");
  expect(shipped).toContain("CREATE INDEX IF NOT EXISTS");
});
