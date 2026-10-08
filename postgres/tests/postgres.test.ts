import type {
  AgentExchangeRequest,
  AgentExchangeReceipt,
} from "@absolutejs/agent-exchange";
import { describe, expect, test } from "bun:test";
import { SQL } from "bun";
import {
  AGENT_EXCHANGE_POSTGRES_MIGRATION,
  createPostgresAgentExchangeStores,
  type AgentExchangeSqlClient,
} from "../src";

const databaseUrl = process.env.AGENT_EXCHANGE_TEST_DATABASE_URL?.replace(
  "-pooler.",
  ".",
);
const databaseTest = databaseUrl ? test : test.skip;
describe("Postgres exchange persistence", () => {
  test("rejects cross-tenant and expired claims without touching the database", async () => {
    const client: AgentExchangeSqlClient = {
      query: async () => {
        throw new Error("Unexpected database access");
      },
    };
    const { broker, replay } = createPostgresAgentExchangeStores({
      client,
      tenantId: "a",
      now: () => 100,
    });
    expect(
      await broker.claim({
        tenantId: "b",
        exchangeId: "exchange",
        provider: "test",
        expiresAt: 200,
      }),
    ).toBe("conflict");
    expect(
      await broker.claim({
        tenantId: "a",
        exchangeId: "exchange",
        provider: "test",
        expiresAt: 100,
      }),
    ).toBe("conflict");
    expect(
      await broker.complete({ tenantId: "b", exchangeId: "exchange" }),
    ).toBe(false);
    expect(await broker.revoke({ tenantId: "b", exchangeId: "exchange" })).toBe(
      false,
    );
    expect(
      await replay.consume({
        exchangeId: "exchange",
        nonce: "nonce",
        expiresAt: 100,
        now: 100,
      }),
    ).toBe(false);
  });
  databaseTest(
    "racing connections, restarts, tenant isolation and preemptive revocation",
    async () => {
      const schema = `exchange_test_${crypto.randomUUID().replaceAll("-", "")}`;
      const admin = new SQL(databaseUrl!, { max: 1 });
      const connections: SQL[] = [];
      try {
        await admin.unsafe(`CREATE SCHEMA ${schema}`);
        const clients: AgentExchangeSqlClient[] = [];
        for (let index = 0; index < 4; index++) {
          const connection = new SQL(databaseUrl!, { max: 1 });
          connections.push(connection);
          await connection.unsafe(`SET search_path TO ${schema}`);
          clients.push({
            query: async <Row>(sql: string, parameters: readonly unknown[]) => {
              const rows = await connection.unsafe(sql, [...parameters]);
              return { rows: [...rows] as Row[], rowCount: rows.count };
            },
          });
        }
        await connections[0]!.unsafe(AGENT_EXCHANGE_POSTGRES_MIGRATION);
        const stores = clients.map((client) =>
          createPostgresAgentExchangeStores({
            client,
            tenantId: "a",
            now: () => 100,
          }),
        );
        const request: AgentExchangeRequest = {
          actionId: "action",
          exchangeId: "exchange",
          createdAt: 90,
          expiresAt: 200,
          assurance: {
            approval: "standing-mandate",
            credential: "token-confined-broker",
            execution: "purpose-bound",
          },
          maximumUses: 1,
          processingMode: "tool-confined",
          purpose: "verification-test",
          risk: "routine",
          secretKind: "otp",
          nonce: "nonce",
          requester: {
            agentId: "requester",
            authority: "https://example.com",
            subject: "alice",
          },
          recipient: {
            agentId: "recipient",
            authority: "https://example.com",
            subject: "bob",
          },
          resource: {
            accountRef: "account",
            operation: "verify-test",
            origin: "https://example.com",
            provider: "test",
          },
        };
        expect(
          (await Promise.all(stores.map((s) => s.store.save(request)))).filter(
            Boolean,
          ),
        ).toHaveLength(1);
        expect(
          await stores[1]!.store.save({ ...request, purpose: "changed" }),
        ).toBe(false);
        expect(await stores[0]!.store.get("exchange")).toEqual(request);
        expect(await stores[0]!.store.getByActionId("action")).toEqual(request);
        const receipt: AgentExchangeReceipt = {
          assurance: request.assurance,
          completedAt: 150,
          consentId: "consent",
          exchangeId: "exchange",
          maximumUses: 1,
          modelObservedSecret: false,
          processingMode: "tool-confined",
          status: "submitted",
          reference: "must-not-be-persisted",
        };
        expect(await stores[0]!.store.saveReceipt(receipt)).toBe(true);
        expect(await stores[1]!.store.saveReceipt(receipt)).toBe(false);
        expect(
          (await stores[0]!.store.getReceipt("exchange"))?.reference,
        ).toBeUndefined();
        const claim = {
          tenantId: "a",
          exchangeId: "exchange",
          provider: "test",
          expiresAt: 200,
        };
        const claims = await Promise.all(
          stores.map((s) => s.broker.claim(claim)),
        );
        expect(claims.filter((c) => c === "claimed")).toHaveLength(1);
        expect(claims.filter((c) => c === "conflict")).toHaveLength(3);
        const delivery = {
          exchangeId: "exchange",
          nonce: "nonce",
          expiresAt: 200,
          now: 100,
        };
        expect(
          (
            await Promise.all(stores.map((s) => s.replay.consume(delivery)))
          ).filter(Boolean),
        ).toHaveLength(1);
        expect(
          await stores[0]!.replay.consume({ ...delivery, nonce: "different" }),
        ).toBe(false);
        const restarted = createPostgresAgentExchangeStores({
          client: clients[0]!,
          tenantId: "a",
          now: () => 100,
        });
        expect(await restarted.broker.claim(claim)).toBe("conflict");
        await restarted.broker.fail(claim);
        expect(await restarted.broker.claim(claim)).toBe("conflict");
        expect(await restarted.broker.complete(claim)).toBe(false);
        expect(
          await restarted.broker.revoke({
            tenantId: "a",
            exchangeId: "future",
          }),
        ).toBe(true);
        expect(
          await restarted.broker.claim({ ...claim, exchangeId: "future" }),
        ).toBe("revoked");
        const other = createPostgresAgentExchangeStores({
          client: clients[1]!,
          tenantId: "b",
          now: () => 100,
        });
        expect(await other.store.get("exchange")).toBeUndefined();
        expect(await other.store.getReceipt("exchange")).toBeUndefined();
        expect(await other.broker.claim({ ...claim, tenantId: "b" })).toBe(
          "claimed",
        );
        expect(await other.broker.complete({ ...claim, tenantId: "b" })).toBe(
          true,
        );
        expect(await other.broker.revoke({ ...claim, tenantId: "b" })).toBe(
          false,
        );
        expect(await other.broker.claim({ ...claim, tenantId: "b" })).toBe(
          "completed",
        );
      } finally {
        await Promise.all(connections.map((connection) => connection.close()));
        await admin.unsafe(`DROP SCHEMA ${schema} CASCADE`);
        await admin.close();
      }
    },
    30000,
  );
});
