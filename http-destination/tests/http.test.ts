import type { AgentExchangeRequest } from "@absolutejs/agent-exchange";
import { describe, expect, test } from "bun:test";
import { createAgentExchangeHttpDestination } from "../src";

const request = (): AgentExchangeRequest => ({
  actionId: "action-1",
  assurance: {
    approval: "webauthn-verifier-bound",
    credential: "token-confined-broker",
    execution: "purpose-bound",
  },
  createdAt: 1,
  exchangeId: "exchange-1",
  expiresAt: Date.now() + 60_000,
  idempotencyKey: "idempotency-1",
  maximumUses: 1,
  nonce: "nonce-1",
  processingMode: "tool-confined",
  purpose: "Submit verification code",
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
    challengeId: "challenge 1",
    operation: "verification.submit",
    origin: "https://accounts.example.com",
    provider: "gmail",
  },
  risk: "authentication",
  secretKind: "email-one-time-code",
});

describe("fixed HTTP destination", () => {
  test("posts only to the configured endpoint with hardened fetch options", async () => {
    let observedUrl = "";
    let observedInit: RequestInit | undefined;
    const destination = createAgentExchangeHttpDestination({
      authorization: ({ tenantId }) => `Bearer credential-for-${tenantId}`,
      challengeField: "challenge",
      endpoint: "https://accounts.example.com/api/verify",
      fetcher: async (url, init) => {
        expect(new TextDecoder().decode(init?.body as Uint8Array)).toBe(
          "code=482193&challenge=challenge+1",
        );
        observedUrl = String(url);
        observedInit = init;
        return new Response(null, { status: 204 });
      },
      id: "accounts-example",
      operations: ["verification.submit"],
      reference: "accounts-verification",
    });
    const plaintext = new TextEncoder().encode("482193");
    await expect(
      destination.submit({
        plaintext,
        request: request(),
        tenantId: "tenant-1",
      }),
    ).resolves.toEqual({
      reference: "accounts-verification",
      status: "submitted",
    });
    expect(observedUrl).toBe("https://accounts.example.com/api/verify");
    expect(observedInit?.method).toBe("POST");
    expect(observedInit?.redirect).toBe("error");
    expect(observedInit?.credentials).toBe("omit");
    expect([...(observedInit?.body as Uint8Array)]).toEqual(
      Array((observedInit?.body as Uint8Array).byteLength).fill(0),
    );
    const headers = new Headers(observedInit?.headers);
    expect(headers.get("authorization")).toBe("Bearer credential-for-tenant-1");
    expect(headers.get("x-idempotency-key")).toBe("idempotency-1");
    expect(plaintext).toEqual(new TextEncoder().encode("482193"));
  });

  test("rejects unsafe deployment endpoints", () => {
    for (const endpoint of [
      "http://accounts.example.com/verify",
      "https://user:pass@accounts.example.com/verify",
      "https://accounts.example.com/verify?next=https://evil.test",
      "https://accounts.example.com/verify#fragment",
    ]) {
      expect(() =>
        createAgentExchangeHttpDestination({
          endpoint,
          id: "accounts-example",
          operations: ["verification.submit"],
        }),
      ).toThrow();
    }
  });

  test("rejects non-six-digit values before network access", async () => {
    let called = false;
    const destination = createAgentExchangeHttpDestination({
      endpoint: "https://accounts.example.com/verify",
      fetcher: async () => {
        called = true;
        return new Response(null, { status: 204 });
      },
      id: "accounts-example",
      operations: ["verification.submit"],
    });
    for (const value of ["12345", "1234567", "12a456", "１２３４５６"]) {
      await expect(
        destination.submit({
          plaintext: new TextEncoder().encode(value),
          request: request(),
          tenantId: "tenant-1",
        }),
      ).rejects.toThrow();
    }
    expect(called).toBeFalse();
  });

  test("does not follow redirects", async () => {
    const destination = createAgentExchangeHttpDestination({
      endpoint: "https://accounts.example.com/verify",
      fetcher: async (_url, init) => {
        expect(init?.redirect).toBe("error");
        throw new TypeError("redirect blocked");
      },
      id: "accounts-example",
      operations: ["verification.submit"],
    });
    await expect(
      destination.submit({
        plaintext: new TextEncoder().encode("482193"),
        request: request(),
        tenantId: "tenant-1",
      }),
    ).rejects.toThrow("submission failed");
  });
});
