import {
  AgentExchangeError,
  validateAgentExchangeRequest,
  type AgentExchangeDelivery,
  type AgentExchangeReceipt,
  type AgentExchangeReceiver,
  type AgentExchangeRequest,
  type AgentExchangeTransport,
  type SignedAgentExchangeStandingMandate,
} from "@absolutejs/agent-exchange";
import type {
  SecureMessagingApplicationHandler,
  SecureMessagingClient,
} from "@absolutejs/secure-messaging";

export const AGENT_EXCHANGE_SECURE_MESSAGING_CONTRACT = 1 as const;
export const AGENT_EXCHANGE_SECURE_MESSAGING_REQUEST_PURPOSE =
  "org.absolutejs.agent-exchange.request.v1" as const;
export const AGENT_EXCHANGE_SECURE_MESSAGING_RECEIPT_PURPOSE =
  "org.absolutejs.agent-exchange.receipt.v1" as const;

const DEFAULT_MAXIMUM_ENVELOPE_BYTES = 1_048_576;
const DEFAULT_MAXIMUM_JWS_BYTES = 65_536;
const DEFAULT_MAXIMUM_TTL_MS = 300_000;
const DEFAULT_OUTER_EXPIRY_SKEW_MS = 5_000;
const DEFAULT_POLL_INTERVAL_MS = 250;
const MAXIMUM_IDENTIFIER_BYTES = 512;
const encoder = new TextEncoder();

type JsonObject = Record<string, unknown>;

export type AgentExchangeSecureMessagingRoute = {
  readonly conversationId: string;
  readonly recipientDeviceId: string;
};

export type AgentExchangeSecureMessagingReceiptSaveResult =
  "conflict" | "duplicate" | "saved";

export type AgentExchangeSecureMessagingReceiptStore = {
  readonly get: (
    exchangeId: string,
  ) => Promise<AgentExchangeReceipt | undefined>;
  readonly save: (
    receipt: AgentExchangeReceipt,
  ) => Promise<AgentExchangeSecureMessagingReceiptSaveResult>;
};

export type AgentExchangeSecureMessagingTransportOptions = {
  readonly client: Pick<SecureMessagingClient, "send">;
  readonly maximumEnvelopeBytes?: number;
  readonly maximumJwsBytes?: number;
  readonly maximumTtlMs?: number;
  readonly now?: () => number;
  readonly pollIntervalMs?: number;
  readonly receipts: AgentExchangeSecureMessagingReceiptStore;
  readonly resolveRoute: (
    request: AgentExchangeRequest,
  ) =>
    | Promise<AgentExchangeSecureMessagingRoute>
    | AgentExchangeSecureMessagingRoute;
  readonly resolveSignedMandate?: (
    request: AgentExchangeRequest,
  ) =>
    | Promise<SignedAgentExchangeStandingMandate | undefined>
    | SignedAgentExchangeStandingMandate
    | undefined;
  readonly sleep?: (milliseconds: number) => Promise<void>;
};

export type AgentExchangeSecureMessagingRequestAuthorization = {
  readonly conversationId: string;
  readonly delivery: AgentExchangeDelivery;
  readonly senderCredential: Uint8Array;
  readonly senderDeviceId: string;
  readonly signedMandate?: SignedAgentExchangeStandingMandate;
};

export type AgentExchangeSecureMessagingHandlerOptions = {
  readonly allowInsecureLocalhost?: boolean;
  readonly authorizeRequest: (
    input: AgentExchangeSecureMessagingRequestAuthorization,
  ) => Promise<unknown> | unknown;
  readonly localDeviceId: string;
  readonly maximumEnvelopeBytes?: number;
  readonly maximumJwsBytes?: number;
  readonly maximumOuterExpirySkewMs?: number;
  readonly maximumTtlMs?: number;
  readonly now?: () => number;
  readonly receipts: AgentExchangeSecureMessagingReceiptStore;
  readonly receiver: AgentExchangeReceiver;
};

type RequestWireMessage = {
  readonly contract: typeof AGENT_EXCHANGE_SECURE_MESSAGING_CONTRACT;
  readonly delivery: {
    readonly authenticatedContext: AgentExchangeDelivery["authenticatedContext"];
    readonly envelope: Uint8Array;
    readonly recipientKeyId: string;
    readonly request: AgentExchangeRequest;
  };
  readonly kind: "request";
  readonly mandateJws?: string;
};

type ReceiptWireMessage = {
  readonly contract: typeof AGENT_EXCHANGE_SECURE_MESSAGING_CONTRACT;
  readonly kind: "receipt";
  readonly receipt: AgentExchangeReceipt;
  readonly recipientDeviceId: string;
  readonly requesterDeviceId: string;
};

type WireMessage = ReceiptWireMessage | RequestWireMessage;

const isObject = (value: unknown): value is JsonObject =>
  typeof value === "object" && value !== null && !Array.isArray(value);

const exactKeys = (value: JsonObject, allowed: readonly string[]) => {
  const names = new Set(allowed);
  if (Object.keys(value).some((key) => !names.has(key)))
    throw new Error("Agent Exchange secure-messaging message was rejected");
};

const objectValue = (value: unknown) => {
  if (!isObject(value))
    throw new Error("Agent Exchange secure-messaging message was rejected");
  return value;
};

const boundedString = (value: unknown, maximumBytes: number) => {
  if (
    typeof value !== "string" ||
    value.length === 0 ||
    encoder.encode(value).byteLength > maximumBytes
  )
    throw new Error("Agent Exchange secure-messaging message was rejected");
  return value;
};

const base64urlEncode = (bytes: Uint8Array) => {
  let binary = "";
  for (const byte of bytes) binary += String.fromCharCode(byte);
  return btoa(binary)
    .replaceAll("+", "-")
    .replaceAll("/", "_")
    .replace(/=+$/u, "");
};

const base64urlDecode = (value: unknown, maximumBytes: number) => {
  const encoded = boundedString(value, Math.ceil((maximumBytes * 4) / 3) + 4);
  if (!/^[A-Za-z0-9_-]+$/u.test(encoded))
    throw new Error("Agent Exchange secure-messaging message was rejected");
  const padding = "=".repeat((4 - (encoded.length % 4)) % 4);
  let binary: string;
  try {
    binary = atob(encoded.replaceAll("-", "+").replaceAll("_", "/") + padding);
  } catch {
    throw new Error("Agent Exchange secure-messaging message was rejected");
  }
  if (binary.length === 0 || binary.length > maximumBytes)
    throw new Error("Agent Exchange secure-messaging message was rejected");
  return Uint8Array.from(binary, (character) => character.charCodeAt(0));
};

const assertIdentityShape = (value: unknown) => {
  const identity = objectValue(value);
  exactKeys(identity, [
    "agentId",
    "authority",
    "delegationId",
    "deviceId",
    "subject",
  ]);
};

const assertAssuranceShape = (value: unknown) => {
  const assurance = objectValue(value);
  exactKeys(assurance, ["approval", "credential", "execution"]);
};

const assertRequestShape = (value: unknown) => {
  const request = objectValue(value);
  exactKeys(request, [
    "actionId",
    "assurance",
    "createdAt",
    "exchangeId",
    "expiresAt",
    "idempotencyKey",
    "mandateId",
    "maximumUses",
    "nonce",
    "processingMode",
    "purpose",
    "recipient",
    "requester",
    "resource",
    "risk",
    "secretKind",
  ]);
  assertAssuranceShape(request.assurance);
  assertIdentityShape(request.recipient);
  assertIdentityShape(request.requester);
  const resource = objectValue(request.resource);
  exactKeys(resource, [
    "accountRef",
    "challengeId",
    "operation",
    "origin",
    "provider",
  ]);
};

const assertContextShape = (value: unknown) => {
  const context = objectValue(value);
  exactKeys(context, [
    "conversationId",
    "expiresAt",
    "purpose",
    "securityEpoch",
    "senderId",
  ]);
};

const parseReceipt = (value: unknown): AgentExchangeReceipt => {
  const receipt = objectValue(value);
  exactKeys(receipt, [
    "assurance",
    "completedAt",
    "consentId",
    "exchangeId",
    "maximumUses",
    "modelObservedSecret",
    "processingMode",
    "reference",
    "status",
  ]);
  assertAssuranceShape(receipt.assurance);
  if (
    !Number.isSafeInteger(receipt.completedAt) ||
    boundedString(receipt.consentId, MAXIMUM_IDENTIFIER_BYTES).length === 0 ||
    boundedString(receipt.exchangeId, MAXIMUM_IDENTIFIER_BYTES).length === 0 ||
    receipt.maximumUses !== 1 ||
    receipt.modelObservedSecret !== false ||
    receipt.processingMode !== "tool-confined" ||
    (receipt.reference !== undefined &&
      boundedString(receipt.reference, 2_048).length === 0) ||
    receipt.status !== "submitted"
  )
    throw new Error("Agent Exchange secure-messaging receipt was rejected");
  return receipt as AgentExchangeReceipt;
};

const parseWireMessage = (
  bytes: Uint8Array,
  options: {
    readonly allowInsecureLocalhost: boolean;
    readonly maximumEnvelopeBytes: number;
    readonly maximumJwsBytes: number;
    readonly maximumTtlMs: number;
    readonly now: number;
  },
): WireMessage => {
  let value: unknown;
  try {
    value = JSON.parse(new TextDecoder("utf-8", { fatal: true }).decode(bytes));
  } catch {
    throw new Error("Agent Exchange secure-messaging message was rejected");
  }
  const message = objectValue(value);
  if (message.contract !== AGENT_EXCHANGE_SECURE_MESSAGING_CONTRACT)
    throw new Error("Agent Exchange secure-messaging message was rejected");
  if (message.kind === "request") {
    exactKeys(message, ["contract", "delivery", "kind", "mandateJws"]);
    const delivery = objectValue(message.delivery);
    exactKeys(delivery, [
      "authenticatedContext",
      "envelope",
      "recipientKeyId",
      "request",
    ]);
    assertContextShape(delivery.authenticatedContext);
    assertRequestShape(delivery.request);
    const request = delivery.request as AgentExchangeRequest;
    validateAgentExchangeRequest(request, {
      allowInsecureLocalhost: options.allowInsecureLocalhost,
      maxTtlMs: options.maximumTtlMs,
      now: options.now,
    });
    const mandateJws =
      message.mandateJws === undefined
        ? undefined
        : boundedString(message.mandateJws, options.maximumJwsBytes);
    if (
      (request.assurance.approval === "standing-mandate") !==
      (mandateJws !== undefined)
    )
      throw new Error("Agent Exchange secure-messaging mandate was rejected");
    return Object.freeze({
      contract: AGENT_EXCHANGE_SECURE_MESSAGING_CONTRACT,
      delivery: Object.freeze({
        authenticatedContext:
          delivery.authenticatedContext as AgentExchangeDelivery["authenticatedContext"],
        envelope: base64urlDecode(
          delivery.envelope,
          options.maximumEnvelopeBytes,
        ),
        recipientKeyId: boundedString(
          delivery.recipientKeyId,
          MAXIMUM_IDENTIFIER_BYTES,
        ),
        request,
      }),
      kind: "request",
      ...(mandateJws === undefined ? {} : { mandateJws }),
    });
  }
  if (message.kind === "receipt") {
    exactKeys(message, [
      "contract",
      "kind",
      "receipt",
      "recipientDeviceId",
      "requesterDeviceId",
    ]);
    return Object.freeze({
      contract: AGENT_EXCHANGE_SECURE_MESSAGING_CONTRACT,
      kind: "receipt",
      receipt: parseReceipt(message.receipt),
      recipientDeviceId: boundedString(
        message.recipientDeviceId,
        MAXIMUM_IDENTIFIER_BYTES,
      ),
      requesterDeviceId: boundedString(
        message.requesterDeviceId,
        MAXIMUM_IDENTIFIER_BYTES,
      ),
    });
  }
  throw new Error("Agent Exchange secure-messaging message was rejected");
};

const encode = (value: unknown) => encoder.encode(JSON.stringify(value));

const encodeRequest = (
  delivery: AgentExchangeDelivery,
  signedMandate: SignedAgentExchangeStandingMandate | undefined,
) =>
  encode({
    contract: AGENT_EXCHANGE_SECURE_MESSAGING_CONTRACT,
    delivery: {
      authenticatedContext: delivery.authenticatedContext,
      envelope: base64urlEncode(delivery.envelope),
      recipientKeyId: delivery.recipientKeyId,
      request: delivery.request,
    },
    kind: "request",
    ...(signedMandate === undefined
      ? {}
      : { mandateJws: signedMandate.compactJws }),
  });

const encodeReceipt = (
  receipt: AgentExchangeReceipt,
  requesterDeviceId: string,
  recipientDeviceId: string,
) =>
  encode({
    contract: AGENT_EXCHANGE_SECURE_MESSAGING_CONTRACT,
    kind: "receipt",
    receipt,
    recipientDeviceId,
    requesterDeviceId,
  });

const sameAssurance = (
  left: AgentExchangeReceipt["assurance"],
  right: AgentExchangeReceipt["assurance"],
) =>
  left.approval === right.approval &&
  left.credential === right.credential &&
  left.execution === right.execution;

const sameReceipt = (left: AgentExchangeReceipt, right: AgentExchangeReceipt) =>
  sameAssurance(left.assurance, right.assurance) &&
  left.completedAt === right.completedAt &&
  left.consentId === right.consentId &&
  left.exchangeId === right.exchangeId &&
  left.maximumUses === right.maximumUses &&
  left.modelObservedSecret === right.modelObservedSecret &&
  left.processingMode === right.processingMode &&
  left.reference === right.reference &&
  left.status === right.status;

const validReceiptFor = (
  receipt: AgentExchangeReceipt,
  request: AgentExchangeRequest,
) =>
  receipt.exchangeId === request.exchangeId &&
  sameAssurance(receipt.assurance, request.assurance) &&
  receipt.completedAt >= request.createdAt &&
  receipt.completedAt <= request.expiresAt &&
  receipt.maximumUses === 1 &&
  receipt.modelObservedSecret === false &&
  receipt.processingMode === "tool-confined" &&
  receipt.status === "submitted";

const positiveLimit = (value: number, label: string) => {
  if (!Number.isSafeInteger(value) || value < 1)
    throw new Error(`${label} must be a positive safe integer`);
  return value;
};

export const createMemoryAgentExchangeSecureMessagingReceiptStore =
  (): AgentExchangeSecureMessagingReceiptStore => {
    const receipts = new Map<string, AgentExchangeReceipt>();
    return Object.freeze({
      get: async (exchangeId) => receipts.get(exchangeId),
      save: async (receipt) => {
        const existing = receipts.get(receipt.exchangeId);
        if (existing !== undefined)
          return sameReceipt(existing, receipt) ? "duplicate" : "conflict";
        receipts.set(receipt.exchangeId, Object.freeze({ ...receipt }));
        return "saved";
      },
    });
  };

export const createAgentExchangeSecureMessagingTransport = (
  options: AgentExchangeSecureMessagingTransportOptions,
): AgentExchangeTransport => {
  const now = options.now ?? Date.now;
  const sleep =
    options.sleep ??
    ((milliseconds: number) =>
      new Promise<void>((resolve) => setTimeout(resolve, milliseconds)));
  const pollIntervalMs = positiveLimit(
    options.pollIntervalMs ?? DEFAULT_POLL_INTERVAL_MS,
    "Receipt polling interval",
  );
  const maximumTtlMs = positiveLimit(
    options.maximumTtlMs ?? DEFAULT_MAXIMUM_TTL_MS,
    "Maximum transport lifetime",
  );
  const maximumEnvelopeBytes = positiveLimit(
    options.maximumEnvelopeBytes ?? DEFAULT_MAXIMUM_ENVELOPE_BYTES,
    "Maximum envelope size",
  );
  const maximumJwsBytes = positiveLimit(
    options.maximumJwsBytes ?? DEFAULT_MAXIMUM_JWS_BYTES,
    "Maximum mandate size",
  );

  return Object.freeze({
    deliver: async (delivery) => {
      const request = delivery.request;
      const requesterDeviceId = request.requester.deviceId;
      const recipientDeviceId = request.recipient.deviceId;
      if (!requesterDeviceId || !recipientDeviceId)
        throw new AgentExchangeError("transport_failed");
      const existing = await options.receipts.get(request.exchangeId);
      if (existing !== undefined) {
        if (!validReceiptFor(existing, request))
          throw new AgentExchangeError("transport_failed");
        return existing;
      }
      const currentTime = now();
      const ttlMs = request.expiresAt - currentTime;
      if (ttlMs < 1 || ttlMs > maximumTtlMs)
        throw new AgentExchangeError("transport_failed");
      const route = await options.resolveRoute(request);
      if (
        route.recipientDeviceId !== recipientDeviceId ||
        route.conversationId.length === 0
      )
        throw new AgentExchangeError("transport_failed");
      const signedMandate = await options.resolveSignedMandate?.(request);
      if (
        (request.assurance.approval === "standing-mandate") !==
          (signedMandate !== undefined) ||
        (signedMandate !== undefined &&
          encoder.encode(signedMandate.compactJws).byteLength > maximumJwsBytes)
      )
        throw new AgentExchangeError("transport_failed");
      if (delivery.envelope.byteLength > maximumEnvelopeBytes)
        throw new AgentExchangeError("transport_failed");
      const plaintext = encodeRequest(delivery, signedMandate);
      try {
        await options.client.send({
          conversationId: route.conversationId,
          id: `${request.exchangeId}:request`,
          plaintext,
          purpose: AGENT_EXCHANGE_SECURE_MESSAGING_REQUEST_PURPOSE,
          recipientDeviceId,
          ttlMs,
        });
      } finally {
        plaintext.fill(0);
      }
      while (now() < request.expiresAt) {
        const receipt = await options.receipts.get(request.exchangeId);
        if (receipt !== undefined) {
          if (!validReceiptFor(receipt, request))
            throw new AgentExchangeError("transport_failed");
          return receipt;
        }
        await sleep(Math.min(pollIntervalMs, request.expiresAt - now()));
      }
      throw new AgentExchangeError("transport_failed");
    },
  });
};

export const createAgentExchangeSecureMessagingHandler = (
  options: AgentExchangeSecureMessagingHandlerOptions,
): SecureMessagingApplicationHandler => {
  const now = options.now ?? Date.now;
  const maximumTtlMs = positiveLimit(
    options.maximumTtlMs ?? DEFAULT_MAXIMUM_TTL_MS,
    "Maximum handler lifetime",
  );
  const maximumEnvelopeBytes = positiveLimit(
    options.maximumEnvelopeBytes ?? DEFAULT_MAXIMUM_ENVELOPE_BYTES,
    "Maximum envelope size",
  );
  const maximumJwsBytes = positiveLimit(
    options.maximumJwsBytes ?? DEFAULT_MAXIMUM_JWS_BYTES,
    "Maximum mandate size",
  );
  const maximumOuterExpirySkewMs = positiveLimit(
    options.maximumOuterExpirySkewMs ?? DEFAULT_OUTER_EXPIRY_SKEW_MS,
    "Maximum outer expiry skew",
  );
  boundedString(options.localDeviceId, MAXIMUM_IDENTIFIER_BYTES);

  return async ({ message }) => {
    const wire = parseWireMessage(message.plaintext, {
      allowInsecureLocalhost: options.allowInsecureLocalhost ?? false,
      maximumEnvelopeBytes,
      maximumJwsBytes,
      maximumTtlMs,
      now: now(),
    });
    if (wire.kind === "receipt") {
      if (
        message.authenticatedContext.purpose !==
          AGENT_EXCHANGE_SECURE_MESSAGING_RECEIPT_PURPOSE ||
        message.authenticatedContext.senderId !== wire.recipientDeviceId ||
        wire.requesterDeviceId !== options.localDeviceId
      )
        throw new Error("Agent Exchange secure-messaging receipt was rejected");
      const saved = await options.receipts.save(wire.receipt);
      if (saved === "conflict")
        throw new Error("Agent Exchange secure-messaging receipt conflicted");
      return [];
    }

    const delivery: AgentExchangeDelivery = wire.delivery;
    const request = delivery.request;
    const requesterDeviceId = request.requester.deviceId;
    const recipientDeviceId = request.recipient.deviceId;
    const outerExpiry = message.authenticatedContext.expiresAt;
    if (
      message.authenticatedContext.purpose !==
        AGENT_EXCHANGE_SECURE_MESSAGING_REQUEST_PURPOSE ||
      message.authenticatedContext.senderId !== requesterDeviceId ||
      recipientDeviceId !== options.localDeviceId ||
      outerExpiry === undefined ||
      outerExpiry < request.expiresAt ||
      outerExpiry - request.expiresAt > maximumOuterExpirySkewMs
    )
      throw new Error("Agent Exchange secure-messaging request was rejected");
    const signedMandate =
      wire.mandateJws === undefined
        ? undefined
        : Object.freeze({ compactJws: wire.mandateJws });
    try {
      await options.authorizeRequest({
        conversationId: message.authenticatedContext.conversationId,
        delivery,
        senderCredential: message.senderCredential,
        senderDeviceId: message.authenticatedContext.senderId,
        ...(signedMandate === undefined ? {} : { signedMandate }),
      });
      const receipt = await options.receiver.receive(delivery);
      const ttlMs = request.expiresAt - now();
      if (ttlMs < 1)
        throw new Error("Agent Exchange secure-messaging request expired");
      return [
        {
          id: `${request.exchangeId}:receipt`,
          plaintext: encodeReceipt(
            receipt,
            requesterDeviceId,
            recipientDeviceId,
          ),
          purpose: AGENT_EXCHANGE_SECURE_MESSAGING_RECEIPT_PURPOSE,
          recipientDeviceId: requesterDeviceId,
          ttlMs,
        },
      ];
    } finally {
      delivery.envelope.fill(0);
    }
  };
};
