import { test, expect } from "bun:test";
import {
  createAgentExchangePermissionManager,
  type PermissionRecord,
  type PermissionStore,
  type ServiceProfile,
} from "../src";
import type { AgentExchangeStandingMandateAuthority } from "@absolutejs/agent-exchange";
const profile: ServiceProfile = {
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
};
const owner = { authority: "https://app.example", subject: "owner" },
  requester = {
    authority: "https://app.example",
    subject: "teammate",
    agentId: "a",
  },
  audience = { ...owner, agentId: "b" };
const input = {
  profileId: "test",
  issuer: owner,
  requester,
  audience,
  accountRef: "mailbox",
};
const approval = {
  credentialIdHash: "hash",
  method: "webauthn-verifier-bound" as const,
  rpId: "app.example",
  userVerified: true as const,
  verifiedAt: 1000,
  verifierOrigin: "https://app.example",
};
function fixture() {
  const records = new Map<string, PermissionRecord>();
  const revoked: string[] = [];
  let now = 1000;
  const store: PermissionStore = {
    async create(r) {
      records.set(r.id, structuredClone(r));
    },
    async get(id) {
      return records.get(id);
    },
    async list(o) {
      return [...records.values()].filter(
        (r) => r.draft.issuer.subject === o.subject,
      );
    },
    async findReusable(key, at) {
      return [...records.values()].find(
        (r) =>
          r.scopeKey === key &&
          r.mode === "always" &&
          r.state === "active" &&
          r.draft.expiresAt > at,
      );
    },
    async transition(id, o, from, state, signed) {
      const r = records.get(id);
      if (
        !r ||
        r.draft.issuer.subject !== o.subject ||
        r.draft.issuer.authority !== o.authority ||
        !from.includes(r.state)
      )
        return false;
      records.set(id, {
        ...r,
        state,
        signedMandate: signed ?? r.signedMandate,
      });
      return true;
    },
  };
  const authority = {
    async issue(d) {
      return {
        mandate: { ...d, version: 1 as const, issuedAt: now },
        signedMandate: { compactJws: "test-fixture" },
      };
    },
    async revoke({ mandateId }) {
      revoked.push(mandateId);
      return true;
    },
  } as AgentExchangeStandingMandateAuthority;
  const manager = createAgentExchangePermissionManager({
    profiles: [profile],
    store,
    authority,
    now: () => now,
  });
  return {
    manager,
    store,
    authority,
    revoked,
    advance() {
      now += 31 * 86400000;
    },
  };
}
test("saved permission reuses exact scope only and changed service invalidates it", async () => {
  const f = fixture();
  const r = await f.manager.prepare({ ...input, mode: "always" });
  expect(r.draft.maximumUses).toBe(100);
  expect(r.draft.expiresAt - r.draft.notBefore).toBe(30 * 86400000);
  await f.manager.approve(r.id, owner, approval);
  expect((await f.manager.reusable(input))?.id).toBe(r.id);
  for (const different of [
    { ...input, accountRef: "other" },
    { ...input, requester: { ...requester, subject: "outsider" } },
    { ...input, issuer: { ...owner, subject: "outsider" } },
  ])
    expect(await f.manager.reusable(different)).toBeUndefined();
  const changed = createAgentExchangePermissionManager({
    profiles: [{ ...profile, adapterRevision: "2" }],
    store: f.store,
    authority: f.authority,
  });
  expect(await changed.reusable(input)).toBeUndefined();
  await expect(changed.assertActive(r.id, input)).rejects.toThrow();
  f.advance();
  expect(await f.manager.reusable(input)).toBeUndefined();
});
test("one-use approval is never reusable and owner-only deny/revoke are terminal", async () => {
  const f = fixture();
  const r = await f.manager.prepare({ ...input, mode: "once" });
  expect(r.draft.maximumUses).toBe(1);
  await expect(f.manager.deny(r.id, requester)).rejects.toThrow();
  await f.manager.deny(r.id, owner);
  await expect(f.manager.approve(r.id, owner, approval)).rejects.toThrow();
  const next = await f.manager.prepare({ ...input, mode: "once" });
  await f.manager.approve(next.id, owner, approval);
  expect(await f.manager.reusable(input)).toBeUndefined();
  await f.manager.revoke(next.id, owner);
  await expect(f.manager.assertActive(next.id, input)).rejects.toThrow();
});
test("unknown/wildcard services and non-routine saved grants fail closed", async () => {
  const f = fixture();
  await expect(
    f.manager.prepare({ ...input, profileId: "unknown", mode: "once" }),
  ).rejects.toThrow();
  expect(() =>
    createAgentExchangePermissionManager({
      profiles: [
        {
          ...profile,
          grant: { ...profile.grant, origin: "https://*.example" },
        },
      ],
      store: f.store,
      authority: f.authority,
    }),
  ).toThrow();
  expect(() =>
    createAgentExchangePermissionManager({
      profiles: [
        {
          ...profile,
          grant: { ...profile.grant, risk: "account-recovery" as never },
        },
      ],
      store: f.store,
      authority: f.authority,
    }),
  ).toThrow();
});
test("revocation during issuance cannot activate a saved grant", async () => {
  const f = fixture();
  const r = await f.manager.prepare({ ...input, mode: "always" });
  const manager = createAgentExchangePermissionManager({
    profiles: [profile],
    store: f.store,
    now: () => 1000,
    authority: {
      ...f.authority,
      issue: async (d) => {
        await f.manager.revoke(r.id, owner);
        return f.authority.issue(d);
      },
    },
  });
  await expect(manager.approve(r.id, owner, approval)).rejects.toThrow();
  expect((await f.store.get(r.id))?.state).toBe("revoked");
  expect(f.revoked).toContain(r.id);
});

test("explicit authentication profiles support scoped saved approval; recovery stays excluded", async () => {
  const f = fixture();
  const manager = createAgentExchangePermissionManager({
    profiles: [
      { ...profile, grant: { ...profile.grant, risk: "authentication" } },
    ],
    store: f.store,
    authority: f.authority,
  });
  const permission = await manager.prepare({ ...input, mode: "always" });
  expect(permission.draft.grants[0]?.risk).toBe("authentication");
  expect(permission.draft.maximumUses).toBe(100);
  expect(permission.profile.allowAlways).toBe(true);
});
