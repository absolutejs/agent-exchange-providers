import type {
  AgentExchangeMandateActor,
  AgentExchangeMandateGrant,
  AgentExchangeMandatePrincipal,
  AgentExchangeStandingMandateDraft,
  AgentExchangeStandingMandateInput,
  AgentExchangeStandingMandateAuthority,
  SignedAgentExchangeStandingMandate,
} from "@absolutejs/agent-exchange";

export type PermissionMode = "once" | "always";
export type ServiceProfile = {
  readonly id: string;
  readonly revision: string;
  readonly label: string;
  readonly grant: Omit<AgentExchangeMandateGrant, "accountRef">;
  /** Version of the trusted source/destination configuration. Change when either changes. */
  readonly adapterRevision: string;
  readonly allowAlways: boolean;
};
export type PermissionRecord = {
  readonly id: string;
  readonly scopeKey: string;
  readonly profile: ServiceProfile;
  readonly mode: PermissionMode;
  readonly state: "pending" | "active" | "denied" | "revoked";
  readonly draft: AgentExchangeStandingMandateDraft;
  readonly signedMandate: SignedAgentExchangeStandingMandate | null;
  readonly createdAt: number;
};
export type PermissionStore = {
  create(record: PermissionRecord): Promise<void>;
  get(id: string): Promise<PermissionRecord | undefined>;
  list(
    owner: AgentExchangeMandatePrincipal,
  ): Promise<readonly PermissionRecord[]>;
  findReusable(
    scopeKey: string,
    now: number,
  ): Promise<PermissionRecord | undefined>;
  transition(
    id: string,
    owner: AgentExchangeMandatePrincipal,
    from: readonly PermissionRecord["state"][],
    state: PermissionRecord["state"],
    signed?: SignedAgentExchangeStandingMandate,
  ): Promise<boolean>;
};
export type PermissionScope = {
  profileId: string;
  issuer: AgentExchangeMandatePrincipal;
  requester: AgentExchangeMandatePrincipal;
  accountRef: string;
};
const samePrincipal = (
  a: AgentExchangeMandatePrincipal,
  b: AgentExchangeMandatePrincipal,
) => a.authority === b.authority && a.subject === b.subject;
const checkedString = (s: string) => {
  if (typeof s !== "string" || !s.trim() || s.length > 2048 || s.includes("*"))
    throw Error("Invalid permission scope");
  return s;
};
const checkedOrigin = (s: string) => {
  const u = new URL(s);
  if (u.origin !== s || u.protocol !== "https:")
    throw Error("Exact HTTPS origin required");
  return s;
};
const principal = (p: AgentExchangeMandatePrincipal) => [
  checkedOrigin(p.authority),
  checkedString(p.subject),
];
const profileValues = (p: ServiceProfile) => [
  p.id,
  p.revision,
  p.label,
  p.adapterRevision,
  p.grant.origin,
  p.grant.operation,
  p.grant.provider,
  p.grant.purpose,
  p.grant.risk,
  p.grant.secretKind,
  p.allowAlways,
];
/** Catalog entries are trusted application configuration, never email/model supplied. */
export function createAgentExchangePermissionManager(options: {
  profiles: readonly ServiceProfile[];
  store: PermissionStore;
  authority: AgentExchangeStandingMandateAuthority;
  now?: () => number;
}) {
  const now = options.now ?? Date.now;
  const profiles = new Map<string, ServiceProfile>();
  for (const value of options.profiles) {
    const p = structuredClone(value);
    for (const s of profileValues(p).slice(0, -1)) checkedString(s as string);
    checkedOrigin(p.grant.origin);
    if (profiles.has(p.id) || typeof p.allowAlways !== "boolean")
      throw Error("Invalid service catalog");
    // Recovery/security operations must never silently inherit routine grants.
    if (p.allowAlways && !["routine", "authentication"].includes(p.grant.risk))
      throw Error(
        "Only routine or authentication profiles support saved permission",
      );
    profiles.set(p.id, p);
  }
  const scopeKey = (input: PermissionScope) => {
    const p = profiles.get(input.profileId);
    if (!p)
      throw Error("Unknown service; configure and validate its adapter first");
    return JSON.stringify([
      profileValues(p),
      principal(input.issuer),
      principal(input.requester),
      checkedString(input.accountRef),
    ]);
  };
  const assertCurrent = (record: PermissionRecord, input?: PermissionScope) => {
    const expected = input ?? {
      profileId: record.profile.id,
      issuer: record.draft.issuer,
      requester: record.draft.requester,
      accountRef: record.draft.grants[0]!.accountRef,
    };
    if (
      record.scopeKey !== scopeKey(expected) ||
      record.draft.expiresAt <= now()
    )
      throw Error("Permission expired or service changed");
    return record;
  };
  return {
    profiles: () => [...profiles.values()].map((p) => structuredClone(p)),
    async reusable(input: PermissionScope) {
      const row = await options.store.findReusable(scopeKey(input), now());
      return row ? assertCurrent(row, input) : undefined;
    },
    async prepare(
      input: PermissionScope & {
        mode: PermissionMode;
        requester: AgentExchangeMandateActor;
        audience: AgentExchangeMandateActor;
      },
    ) {
      const key = scopeKey(input),
        p = profiles.get(input.profileId)!;
      if (
        !["once", "always"].includes(input.mode) ||
        (input.mode === "always" && !p.allowAlways) ||
        !samePrincipal(input.issuer, input.audience)
      )
        throw Error("Permission choice unavailable");
      checkedString(input.requester.agentId);
      checkedString(input.audience.agentId);
      const at = now(),
        id = crypto.randomUUID();
      const record: PermissionRecord = {
        id,
        scopeKey: key,
        profile: structuredClone(p),
        mode: input.mode,
        state: "pending",
        signedMandate: null,
        createdAt: at,
        draft: {
          issuer: structuredClone(input.issuer),
          requester: structuredClone(input.requester),
          audience: structuredClone(input.audience),
          mandateId: id,
          notBefore: at,
          expiresAt:
            at + (input.mode === "always" ? 30 * 86400000 : 15 * 60000),
          maximumUses: input.mode === "always" ? 100 : 1,
          grants: [{ ...p.grant, accountRef: input.accountRef }],
        },
      };
      await options.store.create(record);
      return structuredClone(record);
    },
    async get(id: string, owner: AgentExchangeMandatePrincipal) {
      const r = await options.store.get(id);
      if (!r || !samePrincipal(r.draft.issuer, owner))
        throw Error("Permission unavailable");
      return r;
    },
    async assertActive(id: string, input: PermissionScope) {
      const r = await options.store.get(id);
      if (!r || r.state !== "active" || !r.signedMandate)
        throw Error("Permission unavailable");
      return assertCurrent(r, input);
    },
    async approve(
      id: string,
      owner: AgentExchangeMandatePrincipal,
      approval: AgentExchangeStandingMandateInput["approval"],
    ) {
      const r = await options.store.get(id);
      if (!r || r.state !== "pending" || !samePrincipal(r.draft.issuer, owner))
        throw Error("Approval unavailable");
      assertCurrent(r);
      const issued = await options.authority.issue({ ...r.draft, approval });
      if (
        !(await options.store.transition(
          id,
          owner,
          ["pending"],
          "active",
          issued.signedMandate,
        ))
      ) {
        await options.authority.revoke({ issuer: owner, mandateId: id });
        throw Error("Approval changed");
      }
      return {
        ...r,
        state: "active" as const,
        signedMandate: issued.signedMandate,
      };
    },
    async deny(id: string, owner: AgentExchangeMandatePrincipal) {
      if (!(await options.store.transition(id, owner, ["pending"], "denied")))
        throw Error("Request changed");
      await options.authority.revoke({ issuer: owner, mandateId: id });
    },
    async revoke(id: string, owner: AgentExchangeMandatePrincipal) {
      if (
        !(await options.store.transition(
          id,
          owner,
          ["pending", "active"],
          "revoked",
        ))
      )
        throw Error("Permission unavailable");
      await options.authority.revoke({ issuer: owner, mandateId: id });
    },
  };
}

export type PermissionPostgresClient = {
  query<Row = Record<string, unknown>>(
    text: string,
    values: readonly unknown[],
  ): Promise<{ rows: readonly Row[]; rowCount: number }>;
};
export const AGENT_EXCHANGE_PERMISSIONS_POSTGRES_MIGRATION = `
CREATE TABLE IF NOT EXISTS absolute_agent_exchange_permissions (
 tenant_id TEXT NOT NULL, id TEXT NOT NULL, owner_authority TEXT NOT NULL, owner_subject TEXT NOT NULL,
 scope_key TEXT NOT NULL, mode TEXT NOT NULL CHECK(mode IN ('once','always')),
 state TEXT NOT NULL CHECK(state IN ('pending','active','denied','revoked')),
 expires_at BIGINT NOT NULL, created_at BIGINT NOT NULL, record JSONB NOT NULL,
 PRIMARY KEY(tenant_id,id)
);
CREATE INDEX IF NOT EXISTS absolute_agent_exchange_permissions_owner_idx ON absolute_agent_exchange_permissions(tenant_id,owner_authority,owner_subject);
CREATE INDEX IF NOT EXISTS absolute_agent_exchange_permissions_scope_idx ON absolute_agent_exchange_permissions(tenant_id,md5(scope_key),state);
`.trim();
export function createPostgresAgentExchangePermissionStore(options: {
  client: PermissionPostgresClient;
  tenantId: string;
}): PermissionStore {
  const { client, tenantId } = options;
  checkedString(tenantId);
  const decode = (r: { record: PermissionRecord } | undefined) => r?.record;
  return {
    async create(r) {
      await client.query(
        "INSERT INTO absolute_agent_exchange_permissions (tenant_id,id,owner_authority,owner_subject,scope_key,mode,state,expires_at,created_at,record) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10::text::jsonb)",
        [
          tenantId,
          r.id,
          r.draft.issuer.authority,
          r.draft.issuer.subject,
          r.scopeKey,
          r.mode,
          r.state,
          r.draft.expiresAt,
          r.createdAt,
          JSON.stringify(r),
        ],
      );
    },
    async get(id) {
      return decode(
        (
          await client.query<{ record: PermissionRecord }>(
            "SELECT record FROM absolute_agent_exchange_permissions WHERE tenant_id=$1 AND id=$2",
            [tenantId, id],
          )
        ).rows[0],
      );
    },
    async list(owner) {
      return (
        await client.query<{ record: PermissionRecord }>(
          "SELECT record FROM absolute_agent_exchange_permissions WHERE tenant_id=$1 AND owner_authority=$2 AND owner_subject=$3 ORDER BY created_at DESC LIMIT 200",
          [tenantId, owner.authority, owner.subject],
        )
      ).rows.map((r) => r.record);
    },
    async findReusable(key, now) {
      return decode(
        (
          await client.query<{ record: PermissionRecord }>(
            `SELECT p.record FROM absolute_agent_exchange_permissions p JOIN absolute_agent_exchange_mandates m ON m.mandate_id=p.id WHERE p.tenant_id=$1 AND md5(p.scope_key)=md5($2) AND p.scope_key=$2 AND p.mode='always' AND p.state='active' AND p.expires_at>$3 AND m.revoked_at IS NULL AND m.use_count<m.maximum_uses AND m.expires_at>$3 ORDER BY p.created_at DESC LIMIT 1`,
            [tenantId, key, now],
          )
        ).rows[0],
      );
    },
    async transition(id, owner, from, state, signed) {
      return (
        (
          await client.query(
            `UPDATE absolute_agent_exchange_permissions SET state=$6, record=record || jsonb_build_object('state',$6::text) || $7::text::jsonb WHERE tenant_id=$1 AND id=$2 AND owner_authority=$3 AND owner_subject=$4 AND state IN (SELECT jsonb_array_elements_text($5::text::jsonb))`,
            [
              tenantId,
              id,
              owner.authority,
              owner.subject,
              JSON.stringify(from),
              state,
              JSON.stringify(signed ? { signedMandate: signed } : {}),
            ],
          )
        ).rowCount === 1
      );
    },
  };
}
