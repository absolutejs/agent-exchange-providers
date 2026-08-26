import type { AgentExchangeRequest } from "@absolutejs/agent-exchange";
import { describe, expect, test } from "bun:test";
import {
  createAgentExchangeDestinationRegistry,
  type AgentExchangeDestinationAdapter,
} from "../src";

const request = (
  overrides: Partial<AgentExchangeRequest> = {},
): AgentExchangeRequest => ({
  actionId: "action-1",
  assurance: {
    approval: "webauthn-verifier-bound",
    credential: "token-confined-broker",
    execution: "purpose-bound",
  },
  createdAt: 1,
  exchangeId: "exchange-1",
  expiresAt: Date.now() + 60_000,
  maximumUses: 1,
  nonce: "nonce-1",
  processingMode: "tool-confined",
  purpose: "Submit the requested verification code",
  recipient: {
    agentId: "recipient-agent",
    authority: "https://recipient.example",
    subject: "recipient-user",
  },
  requester: {
    agentId: "requester-agent",
    authority: "https://requester.example",
    subject: "requester-user",
  },
  resource: {
    accountRef: "mailbox-1",
    challengeId: "challenge-1",
    operation: "verification.submit",
    origin: "https://accounts.example.com",
    provider: "gmail",
  },
  risk: "authentication",
  secretKind: "email-one-time-code",
  ...overrides,
});

const adapter = (
  submit: AgentExchangeDestinationAdapter["submit"],
): AgentExchangeDestinationAdapter => ({
  descriptor: {
    id: "accounts-example",
    operations: ["verification.submit"],
    origin: "https://accounts.example.com",
    secretKinds: ["email-one-time-code"],
  },
  submit,
});

describe("Agent Exchange destination registry", () => {
  test("routes by exact origin, operation, and secret kind and clears its copy", async () => {
    let observed: Uint8Array | undefined;
    const registry = createAgentExchangeDestinationRegistry([
      adapter(({ plaintext }) => {
        observed = plaintext;
        return { reference: "submission-1", status: "submitted" };
      }),
    ]);
    const callerBytes = new TextEncoder().encode("482193");
    await expect(
      registry.submit({
        plaintext: callerBytes,
        request: request(),
        tenantId: "tenant-1",
      }),
    ).resolves.toEqual({ reference: "submission-1", status: "submitted" });
    expect(callerBytes).toEqual(new TextEncoder().encode("482193"));
    expect(observed).toEqual(new Uint8Array(6));
  });

  test("rejects unknown and confusable routes", async () => {
    const registry = createAgentExchangeDestinationRegistry([
      adapter(() => ({ status: "submitted" })),
    ]);
    for (const origin of [
      "https://accounts.example.com.evil.test",
      "https://accounts.example.com/",
      "http://accounts.example.com",
    ]) {
      await expect(
        registry.submit({
          plaintext: new TextEncoder().encode("482193"),
          request: request({ resource: { ...request().resource, origin } }),
          tenantId: "tenant-1",
        }),
      ).rejects.toThrow();
    }
  });

  test("rejects overlapping routes at construction", () => {
    expect(() =>
      createAgentExchangeDestinationRegistry([
        adapter(() => ({ status: "submitted" })),
        {
          ...adapter(() => ({ status: "submitted" })),
          descriptor: {
            ...adapter(() => ({ status: "submitted" })).descriptor,
            id: "second",
          },
        },
      ]),
    ).toThrow("unambiguous");
  });

  test("rejects results that reflect the secret", async () => {
    const registry = createAgentExchangeDestinationRegistry([
      adapter(({ plaintext }) => ({
        reference: `submitted-${new TextDecoder().decode(plaintext)}`,
        status: "submitted",
      })),
    ]);
    await expect(
      registry.submit({
        plaintext: new TextEncoder().encode("482193"),
        request: request(),
        tenantId: "tenant-1",
      }),
    ).rejects.toThrow("submission failed");
  });
});
