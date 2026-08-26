import { expect, test } from "bun:test";
import {
  AGENT_EXCHANGE_MANDATE_POSTGRES_MIGRATION,
  AGENT_EXCHANGE_MANDATE_REDIS_CONSUME_SCRIPT,
  createPostgresAgentExchangeMandateStore,
  createRedisAgentExchangeMandateStore,
  type MandatePostgresClient,
  type MandateRedisClient,
} from "../src";

const registration = {
  expiresAt: 1_900_000_000_000,
  issuer: { authority: "https://owner.example", subject: "owner-1" },
  mandateId: "mandate-1",
  maximumUses: 2,
};

test("PostgreSQL store uses one locked statement for atomic consumption", async () => {
  const queries: { text: string; values: readonly unknown[] }[] = [];
  const client: MandatePostgresClient = {
    query: async <Row>(text: string, values: readonly unknown[]) => {
      queries.push({ text, values });
      return {
        rowCount: 1,
        rows: (text.includes("WITH updated")
          ? [{ status: "consumed" }]
          : []) as Row[],
      };
    },
  };
  const store = createPostgresAgentExchangeMandateStore({ client });
  await expect(store.register(registration)).resolves.toBe(true);
  await expect(
    store.consume({ exchangeId: "exchange-1", mandateId: "mandate-1", now: 1 }),
  ).resolves.toBe("consumed");
  await expect(
    store.revoke({
      issuer: registration.issuer,
      mandateId: "mandate-1",
      now: 2,
    }),
  ).resolves.toBe(true);
  expect(queries[1]?.text).toContain("use_count = use_count + 1");
  expect(queries[1]?.text).toContain("NOT ($2 = ANY");
  expect(AGENT_EXCHANGE_MANDATE_POSTGRES_MIGRATION).toContain(
    "consumed_exchange_digests TEXT[]",
  );
});

test("Redis store hashes identifiers and delegates transitions to Lua", async () => {
  const calls: {
    script: string;
    keys: readonly string[];
    arguments_: readonly string[];
  }[] = [];
  const client: MandateRedisClient = {
    eval: async (script, keys, arguments_) => {
      calls.push({ script, keys, arguments_ });
      if (script === AGENT_EXCHANGE_MANDATE_REDIS_CONSUME_SCRIPT)
        return "consumed";
      return 1;
    },
  };
  const store = createRedisAgentExchangeMandateStore({ client });
  await store.register(registration);
  await expect(
    store.consume({ exchangeId: "exchange-1", mandateId: "mandate-1", now: 1 }),
  ).resolves.toBe("consumed");
  await store.revoke({
    issuer: registration.issuer,
    mandateId: "mandate-1",
    now: 2,
  });
  expect(calls).toHaveLength(3);
  expect(calls[0]?.keys[0]).not.toContain("mandate-1");
  expect(calls[1]?.arguments_[1]).not.toBe("exchange-1");
});
