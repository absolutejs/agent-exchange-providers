import { expect, test } from "bun:test";
import { SQL } from "bun";
import {
  AGENT_EXCHANGE_MANDATE_POSTGRES_MIGRATION,
  createPostgresAgentExchangeMandateStore,
  type MandatePostgresClient,
} from "../src";
const url = process.env.AGENT_EXCHANGE_TEST_DATABASE_URL?.replace(
  "-pooler.",
  ".",
);
const databaseTest = url ? test : test.skip;
databaseTest(
  "Postgres mandate use limits, replay, and revocation execute against real SQL",
  async () => {
    const schema = `mandate_test_${crypto.randomUUID().replaceAll("-", "")}`;
    const admin = new SQL(url!, { max: 1 });
    const connections: SQL[] = [];
    try {
      await admin.unsafe(`CREATE SCHEMA ${schema}`);
      const clients: MandatePostgresClient[] = [];
      for (let index = 0; index < 4; index++) {
        const connection = new SQL(url!, { max: 1 });
        connections.push(connection);
        await connection.unsafe(`SET search_path TO ${schema}`);
        clients.push({
          query: async <Row>(text: string, values: readonly unknown[]) => {
            const rows = await connection.unsafe(text, [...values]);
            return { rows: [...rows] as Row[], rowCount: rows.count };
          },
        });
      }
      await connections[0]!.unsafe(AGENT_EXCHANGE_MANDATE_POSTGRES_MIGRATION);
      const stores = clients.map((client) =>
        createPostgresAgentExchangeMandateStore({ client }),
      );
      const issuer = { authority: "https://example.com", subject: "owner" };
      expect(
        await stores[0]!.register({
          mandateId: "mandate",
          issuer,
          expiresAt: 200,
          maximumUses: 1,
        }),
      ).toBe(true);
      const outcomes = await Promise.all(
        stores.map((store, index) =>
          store.consume({
            mandateId: "mandate",
            exchangeId: `exchange-${index}`,
            now: 100,
          }),
        ),
      );
      expect(outcomes.filter((result) => result === "consumed")).toHaveLength(
        1,
      );
      const winner = outcomes.indexOf("consumed");
      expect(
        await stores[0]!.consume({
          mandateId: "mandate",
          exchangeId: `exchange-${winner}`,
          now: 100,
        }),
      ).toBe("replay");
      expect(
        await stores[1]!.consume({
          mandateId: "mandate",
          exchangeId: "different",
          now: 100,
        }),
      ).toBe("exhausted");
      expect(
        await stores[0]!.revoke({
          mandateId: "mandate",
          issuer: { ...issuer, subject: "other" },
          now: 100,
        }),
      ).toBe(false);
      expect(
        await stores[0]!.revoke({ mandateId: "mandate", issuer, now: 100 }),
      ).toBe(true);
      expect(
        await stores[1]!.consume({
          mandateId: "mandate",
          exchangeId: "different",
          now: 100,
        }),
      ).toBe("revoked");
      expect(
        await stores[0]!.consume({
          mandateId: "mandate",
          exchangeId: "different",
          now: 200,
        }),
      ).toBe("unknown");
    } finally {
      await Promise.all(connections.map((connection) => connection.close()));
      await admin.unsafe(`DROP SCHEMA ${schema} CASCADE`);
      await admin.close();
    }
  },
  30000,
);
