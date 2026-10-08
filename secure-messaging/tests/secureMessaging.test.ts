import {
  agentExchangeContext,
  type AgentExchangeDelivery,
  type AgentExchangeReceipt,
  type AgentExchangeRequest,
} from "@absolutejs/agent-exchange";
import type {
  SecureMessagingApplicationHandler,
  SecureMessagingSendInput,
} from "@absolutejs/secure-messaging";
import { describe, expect, test } from "bun:test";
import {
  AGENT_EXCHANGE_SECURE_MESSAGING_REQUEST_PURPOSE,
  createAgentExchangeSecureMessagingHandler,
  createAgentExchangeSecureMessagingTransport,
  createMemoryAgentExchangeSecureMessagingReceiptStore,
} from "../src";

const now = 1_800_000_000_000;
const requesterDeviceId = "requester-device";
const recipientDeviceId = "recipient-device";

const request = (): AgentExchangeRequest => ({
  actionId: "action-1",
  assurance: {
    approval: "standing-mandate",
    credential: "token-confined-broker",
    execution: "purpose-bound",
  },
  createdAt: now,
  exchangeId: "exchange-1",
  expiresAt: now + 60_000,
  idempotencyKey: "exchange-1",
  mandateId: "mandate-1",
  maximumUses: 1,
  nonce: "nonce-1",
  processingMode: "tool-confined",
  purpose: "Submit one correlated verification code",
  recipient: {
    agentId: "recipient-agent",
    authority: "https://recipient.example",
    deviceId: recipientDeviceId,
    subject: "recipient-user",
  },
  requester: {
    agentId: "requester-agent",
    authority: "https://requester.example",
    delegationId: "delegation-1",
    deviceId: requesterDeviceId,
    subject: "requester-user",
  },
  resource: {
    accountRef: "mailbox-private",
    challengeId: "challenge-private",
    operation: "verification.submit",
    origin: "https://accounts.example",
    provider: "gmail",
  },
  risk: "authentication",
  secretKind: "email-one-time-code",
});

const receipt = (): AgentExchangeReceipt => ({
  assurance: request().assurance,
  completedAt: now + 1,
  consentId: "mandate-1",
  exchangeId: "exchange-1",
  maximumUses: 1,
  modelObservedSecret: false,
  processingMode: "tool-confined",
  reference: "accounts-example:accepted",
  status: "submitted",
});

type Queued = {
  readonly input: SecureMessagingSendInput;
  readonly senderDeviceId: string;
};

const network = () => {
  const queues = new Map<string, Queued[]>();
  const observedBuffers: Uint8Array[] = [];
  const client = (senderDeviceId: string) => ({
    send: async (input: SecureMessagingSendInput) => {
      observedBuffers.push(input.plaintext);
      const recipient = input.recipientDeviceId;
      if (!recipient) throw new Error("Recipient device is required");
      queues.set(recipient, [
        ...(queues.get(recipient) ?? []),
        {
          input: { ...input, plaintext: input.plaintext.slice() },
          senderDeviceId,
        },
      ]);
      return { delivery: "delivered" as const, id: input.id, securityEpoch: 7 };
    },
  });
  const drain = async (
    deviceId: string,
    handler: SecureMessagingApplicationHandler,
  ) => {
    const queued = queues.get(deviceId) ?? [];
    queues.set(deviceId, []);
    for (const entry of queued) {
      const replies = await handler({
        id: entry.input.id,
        message: {
          authenticatedContext: {
            conversationId: entry.input.conversationId,
            expiresAt: now + entry.input.ttlMs,
            purpose: entry.input.purpose,
            securityEpoch: 7,
            senderId: entry.senderDeviceId,
          },
          plaintext: entry.input.plaintext,
          senderCredential: new TextEncoder().encode(entry.senderDeviceId),
        },
      });
      for (const reply of replies) {
        await client(deviceId).send({
          ...reply,
          conversationId: entry.input.conversationId,
        });
        reply.plaintext.fill(0);
      }
      entry.input.plaintext.fill(0);
    }
  };
  return { client, drain, observedBuffers };
};

describe("Agent Exchange secure-messaging provider", () => {
  test("runs a device-bound encrypted request and redacted receipt round trip", async () => {
    const messaging = network();
    const receipts = createMemoryAgentExchangeSecureMessagingReceiptStore();
    let authorized = false;
    let openedEnvelope: Uint8Array | undefined;
    const recipientHandler = createAgentExchangeSecureMessagingHandler({
      authorizeRequest: ({
        delivery,
        senderCredential,
        senderDeviceId,
        signedMandate,
      }) => {
        authorized = true;
        expect(delivery.request.exchangeId).toBe("exchange-1");
        expect(senderDeviceId).toBe(requesterDeviceId);
        expect(new TextDecoder().decode(senderCredential)).toBe(
          requesterDeviceId,
        );
        expect(signedMandate?.compactJws).toBe("signed-standing-mandate");
      },
      localDeviceId: recipientDeviceId,
      maximumTtlMs: 60_000,
      now: () => now,
      receipts,
      receiver: {
        receive: async (delivery) => {
          openedEnvelope = delivery.envelope;
          expect(delivery.envelope).toEqual(Uint8Array.of(7, 8, 9));
          return receipt();
        },
      },
    });
    const requesterHandler = createAgentExchangeSecureMessagingHandler({
      authorizeRequest: () => {
        throw new Error("Requester must not authorize a receipt");
      },
      localDeviceId: requesterDeviceId,
      maximumTtlMs: 60_000,
      now: () => now,
      receipts,
      receiver: {
        receive: async () => {
          throw new Error("Requester must not open a receipt");
        },
      },
    });
    let drained = false;
    const transport = createAgentExchangeSecureMessagingTransport({
      client: messaging.client(requesterDeviceId),
      maximumTtlMs: 60_000,
      now: () => now,
      pollIntervalMs: 1,
      receipts,
      resolveRoute: () => ({
        conversationId: "opaque-conversation-1",
        recipientDeviceId,
      }),
      resolveSignedMandate: () => ({
        compactJws: "signed-standing-mandate",
      }),
      sleep: async () => {
        if (drained) return;
        drained = true;
        await messaging.drain(recipientDeviceId, recipientHandler);
        await messaging.drain(requesterDeviceId, requesterHandler);
      },
    });
    const exchange = request();
    const delivery: AgentExchangeDelivery = {
      authenticatedContext: await agentExchangeContext(exchange),
      envelope: Uint8Array.of(7, 8, 9),
      recipientKeyId: "recipient-key-1",
      request: exchange,
    };

    await expect(transport.deliver(delivery)).resolves.toEqual(receipt());
    expect(authorized).toBeTrue();
    expect(openedEnvelope).toEqual(new Uint8Array(3));
    expect(
      messaging.observedBuffers.every((buffer) =>
        buffer.every((byte) => byte === 0),
      ),
    ).toBeTrue();
  });

  test("rejects an authenticated sender that does not match the requester device", async () => {
    const receipts = createMemoryAgentExchangeSecureMessagingReceiptStore();
    let received = false;
    const handler = createAgentExchangeSecureMessagingHandler({
      authorizeRequest: () => undefined,
      localDeviceId: recipientDeviceId,
      maximumTtlMs: 60_000,
      now: () => now,
      receipts,
      receiver: {
        receive: async () => {
          received = true;
          return receipt();
        },
      },
    });
    const exchange = request();
    const value = {
      contract: 2,
      delivery: {
        authenticatedContext: await agentExchangeContext(exchange),
        envelope: "BwgJ",
        recipientKeyId: "recipient-key-1",
        request: exchange,
      },
      kind: "request",
      mandateJws: "signed-standing-mandate",
    };

    await expect(
      handler({
        id: "exchange-1:request",
        message: {
          authenticatedContext: {
            conversationId: "opaque-conversation-1",
            expiresAt: now + 60_000,
            purpose: AGENT_EXCHANGE_SECURE_MESSAGING_REQUEST_PURPOSE,
            securityEpoch: 7,
            senderId: "attacker-device",
          },
          plaintext: new TextEncoder().encode(JSON.stringify(value)),
          senderCredential: Uint8Array.of(1),
        },
      }),
    ).rejects.toThrow("request was rejected");
    expect(received).toBeFalse();
  });

  test("rejects a non-canonical base64url envelope", async () => {
    let received = false;
    const handler = createAgentExchangeSecureMessagingHandler({
      authorizeRequest: () => undefined,
      localDeviceId: recipientDeviceId,
      maximumTtlMs: 60_000,
      now: () => now,
      receipts: createMemoryAgentExchangeSecureMessagingReceiptStore(),
      receiver: {
        receive: async () => {
          received = true;
          return receipt();
        },
      },
    });
    const exchange = request();
    await expect(
      handler({
        id: "exchange-1:request",
        message: {
          authenticatedContext: {
            conversationId: "opaque-conversation-1",
            expiresAt: now + 60_000,
            purpose: AGENT_EXCHANGE_SECURE_MESSAGING_REQUEST_PURPOSE,
            securityEpoch: 7,
            senderId: requesterDeviceId,
          },
          plaintext: new TextEncoder().encode(
            JSON.stringify({
              contract: 2,
              delivery: {
                authenticatedContext: await agentExchangeContext(exchange),
                envelope: "Bx",
                recipientKeyId: "recipient-key-1",
                request: exchange,
              },
              kind: "request",
              mandateJws: "signed-standing-mandate",
            }),
          ),
          senderCredential: Uint8Array.of(1),
        },
      }),
    ).rejects.toThrow("message was rejected");
    expect(received).toBeFalse();
  });

  test("rejects wire extensions and conflicting durable receipts", async () => {
    const receipts = createMemoryAgentExchangeSecureMessagingReceiptStore();
    const save = (value: AgentExchangeReceipt, expiresAt = now + 60_000) =>
      receipts.save({ expiresAt, now, receipt: value });
    expect(await save(receipt())).toBe("saved");
    expect(await save(receipt())).toBe("duplicate");
    expect(await save({ ...receipt(), completedAt: now + 2 })).toBe("conflict");
    expect(await save(receipt(), now + 59_999)).toBe("conflict");

    const handler = createAgentExchangeSecureMessagingHandler({
      authorizeRequest: () => undefined,
      localDeviceId: recipientDeviceId,
      maximumTtlMs: 60_000,
      now: () => now,
      receipts,
      receiver: { receive: async () => receipt() },
    });
    await expect(
      handler({
        id: "smuggled",
        message: {
          authenticatedContext: {
            conversationId: "opaque-conversation-1",
            expiresAt: now + 60_000,
            purpose: AGENT_EXCHANGE_SECURE_MESSAGING_REQUEST_PURPOSE,
            securityEpoch: 7,
            senderId: requesterDeviceId,
          },
          plaintext: new TextEncoder().encode(
            JSON.stringify({
              contract: 1,
              kind: "request",
              plaintext: "482193",
            }),
          ),
          senderCredential: Uint8Array.of(1),
        },
      }),
    ).rejects.toThrow("message was rejected");
  });

  test("rejects a durable receipt whose expiry is not request-bound", async () => {
    const receipts = createMemoryAgentExchangeSecureMessagingReceiptStore();
    await receipts.save({
      expiresAt: now + 59_999,
      now,
      receipt: receipt(),
    });
    const transport = createAgentExchangeSecureMessagingTransport({
      client: {
        send: async () => {
          throw new Error("must not send");
        },
      },
      maximumTtlMs: 60_000,
      now: () => now,
      receipts,
      resolveRoute: () => ({
        conversationId: "opaque-conversation-1",
        recipientDeviceId,
      }),
    });
    const exchange = request();
    await expect(
      transport.deliver({
        authenticatedContext: await agentExchangeContext(exchange),
        envelope: Uint8Array.of(7),
        recipientKeyId: "recipient-key-1",
        request: exchange,
      }),
    ).rejects.toThrow("Protected exchange delivery failed");
  });
});
