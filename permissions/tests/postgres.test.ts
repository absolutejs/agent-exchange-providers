import { test, expect } from "bun:test";
import { SQL } from "bun";
import {
  createPostgresAgentExchangePermissionStore,
  createAgentExchangePermissionManager,
  AGENT_EXCHANGE_PERMISSIONS_POSTGRES_MIGRATION,
} from "../src";
import {
  AGENT_EXCHANGE_MANDATE_POSTGRES_MIGRATION,
  createPostgresAgentExchangeMandateStore,
} from "@absolutejs/agent-exchange-mandate-stores";
import type { AgentExchangeStandingMandateAuthority } from "@absolutejs/agent-exchange";
test.skipIf(!process.env.DATABASE_URL)(
  "real PostgreSQL: isolation, competing decisions, exhausted grants and reconstructed stores",
  async () => {
    const sql = new SQL(process.env.DATABASE_URL!.replace("-pooler.", "."), {
      max: 1,
    });
    const schema =
      "permission_check_" + crypto.randomUUID().replaceAll("-", "");
    try {
      await sql.unsafe(`CREATE SCHEMA "${schema}"`);
      await sql.unsafe(`SET search_path TO "${schema}"`);
      await sql.unsafe(AGENT_EXCHANGE_PERMISSIONS_POSTGRES_MIGRATION);
      await sql.unsafe(AGENT_EXCHANGE_MANDATE_POSTGRES_MIGRATION);
      const client = {
        query: async <Row>(text: string, values: readonly unknown[]) => {
          const rows = await sql.unsafe(text, [...values] as never);
          return { rows: rows as Row[], rowCount: rows.count };
        },
      };
      const store = createPostgresAgentExchangePermissionStore({
          client,
          tenantId: "one",
        }),
        other = createPostgresAgentExchangePermissionStore({
          client,
          tenantId: "two",
        }),
        mandates = createPostgresAgentExchangeMandateStore({ client });
      const owner = { authority: "https://app.example", subject: "owner" },
        requester = {
          authority: "https://app.example",
          subject: "requester",
          agentId: "a",
        };
      const authority = {
        issue: async (d) => {
          await mandates.register({
            issuer: d.issuer,
            mandateId: d.mandateId,
            expiresAt: d.expiresAt,
            maximumUses: d.maximumUses,
          });
          return {
            mandate: { ...d, version: 1, issuedAt: Date.now() },
            signedMandate: { compactJws: "fixture" },
          };
        },
        revoke: async (i) => mandates.revoke({ ...i, now: Date.now() }),
      } as AgentExchangeStandingMandateAuthority;
      const manager = createAgentExchangePermissionManager({
        store,
        authority,
        profiles: [
          {
            id: "test",
            revision: "1",
            adapterRevision: "1",
            label: "Test",
            allowAlways: true,
            grant: {
              origin: "https://service.example",
              operation: "verify",
              provider: "gmail",
              purpose: "Test",
              risk: "routine",
              secretKind: "email-one-time-code",
            },
          },
        ],
      });
      const input = {
        profileId: "test",
        issuer: owner,
        requester,
        audience: { ...owner, agentId: "b" },
        accountRef: "mailbox",
        mode: "always" as const,
      };
      const r = await manager.prepare(input);
      expect(await other.get(r.id)).toBeUndefined();
      expect(await store.list({ ...owner, subject: "outsider" })).toHaveLength(
        0,
      );
      const approve = {
        credentialIdHash: "sha256:fixture",
        method: "webauthn-verifier-bound" as const,
        rpId: "app.example",
        userVerified: true as const,
        verifiedAt: Date.now(),
        verifierOrigin: "https://app.example",
      };
      await manager.approve(r.id, owner, approve);
      expect((await manager.reusable(input))?.id).toBe(r.id);
      expect(
        (
          await createPostgresAgentExchangePermissionStore({
            client,
            tenantId: "one",
          }).get(r.id)
        )?.state,
      ).toBe("active");
      await sql.unsafe(
        "UPDATE absolute_agent_exchange_mandates SET use_count=maximum_uses WHERE mandate_id=$1",
        [r.id],
      );
      expect(await manager.reusable(input)).toBeUndefined();
      const pending = await manager.prepare(input);
      const results = await Promise.all([
        store.transition(pending.id, owner, ["pending"], "denied"),
        store.transition(pending.id, owner, ["pending"], "revoked"),
      ]);
      expect(results.filter(Boolean)).toHaveLength(1);
      await manager.revoke(r.id, owner);
      await expect(manager.assertActive(r.id, input)).rejects.toThrow();
    } finally {
      await sql.unsafe("SET search_path TO public");
      await sql.unsafe(`DROP SCHEMA IF EXISTS "${schema}" CASCADE`);
      await sql.close();
    }
  },
  30000,
);
