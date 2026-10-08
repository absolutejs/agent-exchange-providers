import type {
  AgentExchangeDelivery,
  AgentExchangeReceipt,
} from "@absolutejs/agent-exchange";

export type LocalDeliveryWire = Omit<AgentExchangeDelivery, "envelope"> & {
  envelope: string;
};
export function encodeLocalDelivery(
  delivery: AgentExchangeDelivery,
): LocalDeliveryWire {
  if (delivery.envelope.length > 32768) throw Error("Local envelope too large");
  return {
    ...delivery,
    envelope: Buffer.from(delivery.envelope).toString("base64url"),
  };
}
export function decodeLocalDelivery(
  wire: LocalDeliveryWire,
): AgentExchangeDelivery {
  if (
    JSON.stringify(wire).length > 65536 ||
    typeof wire.envelope !== "string" ||
    !/^[A-Za-z0-9_-]{1,44000}$/.test(wire.envelope)
  )
    throw Error("Invalid local envelope");
  return {
    ...wire,
    envelope: new Uint8Array(Buffer.from(wire.envelope, "base64url")),
  };
}
export type LocalRelaySql = {
  query<Row>(
    text: string,
    values: readonly unknown[],
  ): Promise<{ rows: Row[] }>;
};
export const LOCAL_DELIVERY_MIGRATION = `CREATE TABLE IF NOT EXISTS absolute_agent_exchange_local_delivery (
  id text PRIMARY KEY, owner_ref text NOT NULL, key_id text NOT NULL, public_key text NOT NULL,
  expires_at bigint NOT NULL, envelope jsonb, receipt jsonb, failed boolean NOT NULL DEFAULT false
);`;
export type LocalDeliveryRecord = {
  id: string;
  owner_ref: string;
  key_id: string;
  public_key: string;
  expires_at: number;
  envelope: LocalDeliveryWire | null;
  receipt: AgentExchangeReceipt | null;
  failed: boolean;
};
/** Authenticated hosts supply ownerRef from credentials, never the request body.
 * Storage contains public keys, ciphertext and redacted receipts only. A request
 * may register a key only once; reconnect cannot redirect an in-flight envelope.
 */
export function createPostgresLocalDeliveryStore(sql: LocalRelaySql) {
  return {
    async create(input: {
      id: string;
      ownerRef: string;
      keyId: string;
      publicKey: string;
      expiresAt: number;
    }) {
      if (
        ![input.id, input.ownerRef, input.keyId].every(
          (s) => typeof s === "string" && s.length > 0 && s.length <= 512,
        ) ||
        !/^[A-Za-z0-9_-]{40,200}$/.test(input.publicKey) ||
        input.expiresAt <= Date.now() ||
        input.expiresAt > Date.now() + 120000
      )
        throw Error("Invalid local recipient");
      await sql.query(
        "INSERT INTO absolute_agent_exchange_local_delivery (id,owner_ref,key_id,public_key,expires_at) VALUES ($1,$2,$3,$4,$5)",
        [
          input.id,
          input.ownerRef,
          input.keyId,
          input.publicKey,
          input.expiresAt,
        ],
      );
    },
    async get(id: string, ownerRef: string) {
      return (
        await sql.query<LocalDeliveryRecord>(
          "SELECT * FROM absolute_agent_exchange_local_delivery WHERE id=$1 AND owner_ref=$2 AND expires_at>$3",
          [id, ownerRef, Date.now()],
        )
      ).rows[0];
    },
    async publish(
      id: string,
      ownerRef: string,
      delivery: AgentExchangeDelivery,
    ) {
      const wire = encodeLocalDelivery(delivery);
      const result = await sql.query(
        "UPDATE absolute_agent_exchange_local_delivery SET envelope=$3::jsonb WHERE id=$1 AND owner_ref=$2 AND key_id=$4 AND envelope IS NULL AND NOT failed AND expires_at>$5 RETURNING id",
        [
          id,
          ownerRef,
          JSON.stringify(wire),
          delivery.recipientKeyId,
          Date.now(),
        ],
      );
      if (!result.rows.length) throw Error("Local delivery unavailable");
    },
    async acknowledge(
      id: string,
      ownerRef: string,
      receipt: AgentExchangeReceipt,
    ) {
      const result = await sql.query(
        "UPDATE absolute_agent_exchange_local_delivery SET receipt=$3::jsonb WHERE id=$1 AND owner_ref=$2 AND envelope IS NOT NULL AND receipt IS NULL AND NOT failed AND expires_at>$4 AND envelope->'request'->>'exchangeId'=$5 RETURNING id",
        [id, ownerRef, JSON.stringify(receipt), Date.now(), receipt.exchangeId],
      );
      if (!result.rows.length) throw Error("Local delivery unavailable");
    },
    async fail(id: string, ownerRef: string) {
      await sql.query(
        "UPDATE absolute_agent_exchange_local_delivery SET failed=true,envelope=NULL WHERE id=$1 AND owner_ref=$2",
        [id, ownerRef],
      );
    },
    async prune() {
      await sql.query(
        "DELETE FROM absolute_agent_exchange_local_delivery WHERE expires_at<$1",
        [Date.now()],
      );
    },
  };
}
