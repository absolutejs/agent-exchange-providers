import type {
  AgentExchangeRequest,
  AgentExchangeReceipt,
  AgentExchangeStore,
  AgentExchangeReplayStore,
} from "@absolutejs/agent-exchange";
import type { TokenConfinedBrokerStore } from "@absolutejs/agent-exchange-broker";
export type AgentExchangeSqlClient = {
  readonly query: <Row = Record<string, unknown>>(
    sql: string,
    parameters: readonly unknown[],
  ) => Promise<{ readonly rows: readonly Row[]; readonly rowCount: number }>;
};
export const AGENT_EXCHANGE_POSTGRES_MIGRATION = `
CREATE TABLE IF NOT EXISTS absolute_agent_exchange_requests (
 tenant_id text NOT NULL, exchange_id text NOT NULL, action_id text NOT NULL,
 expires_at bigint NOT NULL, data jsonb NOT NULL,
 PRIMARY KEY(tenant_id, exchange_id), UNIQUE(tenant_id, action_id)
);
CREATE TABLE IF NOT EXISTS absolute_agent_exchange_receipts (
 tenant_id text NOT NULL, exchange_id text NOT NULL, data jsonb NOT NULL,
 PRIMARY KEY(tenant_id, exchange_id),
 FOREIGN KEY(tenant_id,exchange_id) REFERENCES absolute_agent_exchange_requests(tenant_id,exchange_id)
);
CREATE TABLE IF NOT EXISTS absolute_agent_exchange_replay (
 tenant_id text NOT NULL, exchange_id text NOT NULL, nonce text NOT NULL, expires_at bigint NOT NULL,
 PRIMARY KEY(tenant_id,exchange_id)
);
CREATE TABLE IF NOT EXISTS absolute_agent_exchange_broker_claims (
 tenant_id text NOT NULL, exchange_id text NOT NULL, provider text NOT NULL, expires_at bigint NOT NULL,
 state text NOT NULL CHECK(state IN ('claimed','completed','failed','revoked')),
 PRIMARY KEY(tenant_id,exchange_id)
);
`.trim();
const identifier = (value: string) => {
  if (typeof value !== "string" || !value.trim() || value.length > 512)
    throw Error("Invalid Agent Exchange identifier");
  return value;
};
// Select contract fields explicitly. Extra runtime fields (tokens, ciphertext,
// provider bodies, source evidence) are never persisted by these stores.
const principal = (p: AgentExchangeRequest["requester"]) => ({
  agentId: identifier(p.agentId),
  authority: p.authority,
  subject: identifier(p.subject),
  ...(p.delegationId === undefined ? {} : { delegationId: p.delegationId }),
  ...(p.deviceId === undefined ? {} : { deviceId: p.deviceId }),
});
const requestRecord = (r: AgentExchangeRequest): AgentExchangeRequest => ({
  actionId: identifier(r.actionId),
  exchangeId: identifier(r.exchangeId),
  createdAt: r.createdAt,
  expiresAt: r.expiresAt,
  assurance: {
    approval: r.assurance.approval,
    credential: r.assurance.credential,
    execution: r.assurance.execution,
  } as AgentExchangeRequest["assurance"],
  maximumUses: 1,
  processingMode: r.processingMode,
  purpose: r.purpose,
  risk: r.risk,
  secretKind: r.secretKind,
  nonce: identifier(r.nonce),
  requester: principal(r.requester),
  recipient: principal(r.recipient),
  resource: {
    accountRef: r.resource.accountRef,
    operation: r.resource.operation,
    origin: r.resource.origin,
    provider: r.resource.provider,
    ...(r.resource.challengeId === undefined
      ? {}
      : { challengeId: r.resource.challengeId }),
  },
  ...(r.mandateId === undefined ? {} : { mandateId: r.mandateId }),
  ...(r.idempotencyKey === undefined
    ? {}
    : { idempotencyKey: r.idempotencyKey }),
});
/** Request metadata is caller-authorized by Agency. Never pass secrets in the
 * declared metadata fields. Receipts deliberately omit free-form sink references. */
export const createPostgresAgentExchangeStores = ({
  client,
  tenantId,
  now = Date.now,
}: {
  client: AgentExchangeSqlClient;
  tenantId: string;
  now?: () => number;
}): {
  store: AgentExchangeStore;
  replay: AgentExchangeReplayStore;
  broker: TokenConfinedBrokerStore;
} => {
  identifier(tenantId);
  const one = async <T>(sql: string, parameters: readonly unknown[]) =>
    (await client.query<{ data: T }>(sql, parameters)).rows[0]?.data;
  return {
    store: {
      get: (id) =>
        one<AgentExchangeRequest>(
          "SELECT data FROM absolute_agent_exchange_requests WHERE tenant_id=$1 AND exchange_id=$2",
          [tenantId, identifier(id)],
        ),
      getByActionId: (id) =>
        one<AgentExchangeRequest>(
          "SELECT data FROM absolute_agent_exchange_requests WHERE tenant_id=$1 AND action_id=$2",
          [tenantId, identifier(id)],
        ),
      getReceipt: (id) =>
        one<AgentExchangeReceipt>(
          "SELECT data FROM absolute_agent_exchange_receipts WHERE tenant_id=$1 AND exchange_id=$2",
          [tenantId, identifier(id)],
        ),
      save: async (request) => {
        const data = requestRecord(request);
        if (
          !Number.isSafeInteger(data.expiresAt) ||
          !Number.isSafeInteger(data.createdAt) ||
          data.expiresAt <= data.createdAt ||
          data.expiresAt <= now() ||
          request.maximumUses !== 1 ||
          data.processingMode !== "tool-confined"
        )
          throw Error("Invalid Agent Exchange request");
        return (
          (
            await client.query(
              "INSERT INTO absolute_agent_exchange_requests(tenant_id,exchange_id,action_id,expires_at,data) VALUES($1,$2,$3,$4,$5::text::jsonb) ON CONFLICT DO NOTHING",
              [
                tenantId,
                data.exchangeId,
                data.actionId,
                data.expiresAt,
                JSON.stringify(data),
              ],
            )
          ).rowCount === 1
        );
      },
      saveReceipt: async (receipt) => {
        if (
          receipt.status !== "submitted" ||
          receipt.maximumUses !== 1 ||
          receipt.modelObservedSecret !== false ||
          receipt.processingMode !== "tool-confined" ||
          !Number.isSafeInteger(receipt.completedAt)
        )
          throw Error("Invalid Agent Exchange receipt");
        const data = {
          assurance: {
            approval: receipt.assurance.approval,
            credential: receipt.assurance.credential,
            execution: receipt.assurance.execution,
          },
          completedAt: receipt.completedAt,
          consentId: identifier(receipt.consentId),
          exchangeId: identifier(receipt.exchangeId),
          maximumUses: 1,
          modelObservedSecret: false,
          processingMode: "tool-confined",
          status: "submitted",
        };
        return (
          (
            await client.query(
              "INSERT INTO absolute_agent_exchange_receipts(tenant_id,exchange_id,data) SELECT $1,$2,$3::text::jsonb FROM absolute_agent_exchange_requests WHERE tenant_id=$1 AND exchange_id=$2 AND expires_at >= $4 ON CONFLICT DO NOTHING",
              [
                tenantId,
                data.exchangeId,
                JSON.stringify(data),
                data.completedAt,
              ],
            )
          ).rowCount === 1
        );
      },
    },
    replay: {
      consume: async (input) => {
        if (
          !Number.isSafeInteger(input.now) ||
          !Number.isSafeInteger(input.expiresAt) ||
          input.expiresAt <= Math.max(input.now, now())
        )
          return false;
        return (
          (
            await client.query(
              "INSERT INTO absolute_agent_exchange_replay(tenant_id,exchange_id,nonce,expires_at) VALUES($1,$2,$3,$4) ON CONFLICT DO NOTHING",
              [
                tenantId,
                identifier(input.exchangeId),
                identifier(input.nonce),
                input.expiresAt,
              ],
            )
          ).rowCount === 1
        );
      },
    },
    broker: {
      claim: async (claim) => {
        if (
          claim.tenantId !== tenantId ||
          !Number.isSafeInteger(claim.expiresAt) ||
          claim.expiresAt <= now()
        )
          return "conflict";
        const inserted = await client.query(
          "INSERT INTO absolute_agent_exchange_broker_claims(tenant_id,exchange_id,provider,expires_at,state) VALUES($1,$2,$3,$4,'claimed') ON CONFLICT DO NOTHING",
          [
            tenantId,
            identifier(claim.exchangeId),
            identifier(claim.provider),
            claim.expiresAt,
          ],
        );
        if (inserted.rowCount === 1) return "claimed";
        const current = (
          await client.query<{ state: string }>(
            "SELECT state FROM absolute_agent_exchange_broker_claims WHERE tenant_id=$1 AND exchange_id=$2",
            [tenantId, claim.exchangeId],
          )
        ).rows[0];
        return current?.state === "completed"
          ? "completed"
          : current?.state === "revoked"
            ? "revoked"
            : "conflict";
      },
      complete: async (input) =>
        input.tenantId === tenantId &&
        (
          await client.query(
            "UPDATE absolute_agent_exchange_broker_claims SET state='completed' WHERE tenant_id=$1 AND exchange_id=$2 AND state='claimed' AND expires_at>$3",
            [tenantId, identifier(input.exchangeId), now()],
          )
        ).rowCount === 1,
      fail: async (input) => {
        if (input.tenantId === tenantId)
          await client.query(
            "UPDATE absolute_agent_exchange_broker_claims SET state='failed' WHERE tenant_id=$1 AND exchange_id=$2 AND state='claimed'",
            [tenantId, identifier(input.exchangeId)],
          );
      },
      revoke: async (input) =>
        input.tenantId === tenantId &&
        (
          await client.query(
            "INSERT INTO absolute_agent_exchange_broker_claims(tenant_id,exchange_id,provider,expires_at,state) VALUES($1,$2,'',0,'revoked') ON CONFLICT(tenant_id,exchange_id) DO UPDATE SET state='revoked' WHERE absolute_agent_exchange_broker_claims.state<>'completed'",
            [tenantId, identifier(input.exchangeId)],
          )
        ).rowCount === 1,
    },
  };
};
