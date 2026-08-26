import { describe, expect, test } from "bun:test";
import type { AgentExchangeRequest } from "@absolutejs/agent-exchange";
import {
  createMemoryTokenConfinedBrokerStore,
  createTokenConfinedBroker,
} from "../src";

const request = (exchangeId = "xchg_1"): AgentExchangeRequest => ({
  actionId: "act_1",
  assurance: {
    approval: "webauthn-verifier-bound",
    credential: "token-confined-broker",
    execution: "purpose-bound",
  },
  createdAt: 1_000,
  exchangeId,
  expiresAt: 20_000,
  maximumUses: 1,
  nonce: "nonce_1",
  processingMode: "tool-confined",
  purpose: "Submit one verification challenge",
  recipient: {
    agentId: "recipient",
    authority: "https://broker.absolutejs.com",
    subject: "user-1",
  },
  requester: {
    agentId: "requester",
    authority: "https://app.example",
    subject: "user-1",
  },
  resource: {
    accountRef: "mailbox-1",
    operation: "verification.submit",
    origin: "https://accounts.example",
    provider: "google",
  },
  risk: "authentication",
  secretKind: "email-one-time-code",
});

describe("token-confined broker", () => {
  test("fences the credential and permits one tenant-scoped execution", async () => {
    const accesses: string[] = [];
    const broker = createTokenConfinedBroker({
      credentials: {
        resolve: async ({ tenantId }) => {
          expect(tenantId).toBe("tenant-1");
          return { accessToken: "provider-bearer-secret", expiresAt: 15_000 };
        },
      },
      now: () => 2_000,
      providers: {
        google: {
          execute: async ({ accessToken }) => {
            accesses.push(accessToken);
            return { reference: "submitted-1", status: "submitted" };
          },
        },
      },
      store: createMemoryTokenConfinedBrokerStore(),
    });
    const receipt = await broker.execute({
      request: request(),
      tenantId: "tenant-1",
    });
    expect(accesses).toEqual(["provider-bearer-secret"]);
    expect(JSON.stringify(receipt)).not.toContain("provider-bearer-secret");
    await expect(
      broker.execute({ request: request(), tenantId: "tenant-1" }),
    ).rejects.toThrow("rejected");
  });

  test("does not let a receipt exfiltrate the bearer token", async () => {
    const broker = createTokenConfinedBroker({
      credentials: {
        resolve: async () => ({ accessToken: "provider-bearer-secret" }),
      },
      now: () => 2_000,
      providers: {
        google: {
          execute: async () => ({
            reference: "provider-bearer-secret",
            status: "submitted",
          }),
        },
      },
      store: createMemoryTokenConfinedBrokerStore(),
    });
    await expect(
      broker.execute({ request: request("xchg_leak"), tenantId: "tenant-1" }),
    ).rejects.toThrow("operation failed");
  });

  test("rejects sender-constrained and policy assurance at this boundary", async () => {
    const broker = createTokenConfinedBroker({
      credentials: { resolve: async () => ({ accessToken: "secret" }) },
      now: () => 2_000,
      providers: {},
      store: createMemoryTokenConfinedBrokerStore(),
    });
    for (const assurance of [
      {
        approval: "webauthn-verifier-bound",
        credential: "sender-constrained",
        execution: "purpose-bound",
      },
      { approval: "policy", credential: "bearer", execution: "purpose-bound" },
    ] as const) {
      await expect(
        broker.execute({
          request: { ...request(crypto.randomUUID()), assurance },
          tenantId: "tenant-1",
        }),
      ).rejects.toThrow("rejected");
    }
  });
});
