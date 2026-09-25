import {
  createAgentExchangeReceiver,
  createMemoryAgentExchangeReplayStore,
  type AgentExchangeDelivery,
  type AgentExchangeReceipt,
  type AgentExchangeRequest,
} from "@absolutejs/agent-exchange";
import {
  createWebCryptoEnvelopeProvider,
  generateWebCryptoRecipientKeyPair,
} from "@absolutejs/e2ee-webcrypto";
export * from "./relay";

export const LOCAL_CLIPBOARD_OPERATION =
  "verification-code.disclose-to-requester-clipboard";
export type PrivateClipboard = {
  /** Copy without stdout/history/cloud sync; clear only this write after ttlMs. */
  copy(bytes: Uint8Array, ttlMs: number): Promise<void>;
};
/** A separate permission: browser-bound sign-in grants never cover disclosure. */
export function clipboardServiceProfile<
  T extends {
    permission: {
      id: string;
      revision: string;
      adapterRevision: string;
      label: string;
      grant: { operation: string; purpose: string };
    };
    email: { id: string; operations: readonly string[] };
  },
>(source: T): T {
  return {
    ...source,
    permission: {
      ...source.permission,
      id: source.permission.id + "-clipboard",
      revision: source.permission.revision + "-clipboard-v1",
      adapterRevision: source.permission.adapterRevision + "-clipboard-v1",
      label: source.permission.label + " — private clipboard",
      grant: {
        ...source.permission.grant,
        operation: LOCAL_CLIPBOARD_OPERATION,
        purpose:
          "Disclose this service’s email sign-in code to the approved requester’s local clipboard for manual use; this does not restrict where they paste it",
      },
    },
    email: {
      ...source.email,
      id: source.email.id + "-clipboard",
      operations: [LOCAL_CLIPBOARD_OPERATION],
    },
  };
}

/** Per-request keys live only in this process. Returned metadata is safe for the
 * authenticated backend, but neither envelopes nor receipts belong in MCP output.
 */
export async function createLocalCodeRecipient(options: {
  requestId: string;
  requester: { authority: string; subject: string };
  serviceOrigin: string;
  accountRef: string;
  clipboard: PrivateClipboard;
  /** Recheck remote approval/revocation immediately before writing the clipboard. */
  assertAuthorized(request: AgentExchangeRequest): Promise<void>;
}) {
  const keyId = crypto.randomUUID();
  const keys = await generateWebCryptoRecipientKeyPair();
  let used = false;
  const receiver = createAgentExchangeReceiver({
    e2ee: createWebCryptoEnvelopeProvider({
      resolveRecipientPrivateKey: async (id) =>
        id === keyId ? keys.keyMaterial : undefined,
    }),
    replay: createMemoryAgentExchangeReplayStore(),
    consent: {
      assertAllows: async (request) => {
        if (
          used ||
          request.resource.challengeId !== options.requestId ||
          request.requester.subject !== options.requester.subject ||
          request.requester.authority !== options.requester.authority ||
          request.resource.origin !== options.serviceOrigin ||
          request.resource.accountRef !== options.accountRef ||
          request.resource.operation !== LOCAL_CLIPBOARD_OPERATION ||
          request.secretKind !== "email-one-time-code"
        )
          throw Error("Local delivery not authorized");
        await options.assertAuthorized(request);
        return { consentId: options.requestId, expiresAt: request.expiresAt };
      },
    },
    sink: {
      submit: async ({ plaintext, request }) => {
        if (
          used ||
          plaintext.length !== 6 ||
          plaintext.some((byte) => byte < 48 || byte > 57)
        )
          throw Error("Invalid local code delivery");
        await options.assertAuthorized(request);
        const ttlMs = Math.min(30000, request.expiresAt - Date.now());
        if (ttlMs < 1000) throw Error("Local code delivery expired");
        used = true; // Never retry an ambiguous clipboard write automatically.
        await options.clipboard.copy(plaintext, ttlMs);
        return { status: "submitted" };
      },
    },
  });
  return {
    keyId,
    publicKey: keys.publicKey,
    receive: async (
      delivery: AgentExchangeDelivery,
    ): Promise<AgentExchangeReceipt> => {
      if (delivery.recipientKeyId !== keyId)
        throw Error("Local delivery key mismatch");
      return receiver.receive(delivery);
    },
  };
}
