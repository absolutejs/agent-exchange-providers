import { test, expect } from "bun:test";
import {
  createBrowserVerificationDestination,
  type VerificationPage,
} from "../src";
import type { AgentExchangeRequest } from "@absolutejs/agent-exchange";
const request = (): AgentExchangeRequest => ({
  actionId: "action",
  assurance: {
    approval: "standing-mandate",
    credential: "token-confined-broker",
    execution: "purpose-bound",
  },
  createdAt: Date.now(),
  exchangeId: "exchange",
  expiresAt: Date.now() + 60000,
  maximumUses: 1,
  nonce: "nonce",
  processingMode: "tool-confined",
  purpose: "Login",
  recipient: {
    agentId: "owner-agent",
    authority: "https://app.example",
    subject: "owner",
  },
  requester: {
    agentId: "requester-agent",
    authority: "https://app.example",
    subject: "requester",
  },
  resource: {
    accountRef: "mailbox",
    challengeId: "challenge",
    operation: "login",
    origin: "https://service.example",
    provider: "gmail",
  },
  risk: "authentication",
  secretKind: "email-one-time-code",
});
const profile = {
  id: "fixture",
  origin: "https://service.example",
  operation: "login",
  pathnames: ["/verify"],
  formActionPathnames: ["/verify"],
  formSelector: "form",
  codeSelector: "input[name=code]",
  submitSelector: "button[type=submit]",
};
function fixture() {
  let listener: ((frame: unknown) => void) | undefined,
    submits = 0;
  const frame = {};
  const page: VerificationPage = {
    mainFrame: () => frame,
    on: (_, fn) => {
      listener = fn;
    },
    off: () => {
      listener = undefined;
    },
    evaluate: async (_, arg: any) => {
      if (arg.code) submits++;
      return (arg.code ? "submitted" : "snapshot") as never;
    },
  };
  return { page, navigate: () => listener?.(frame), submits: () => submits };
}
test("exact binding and concurrent single claim; caller bytes remain owned by caller", async () => {
  const f = fixture(),
    r = request();
  const d = await createBrowserVerificationDestination({
    page: f.page,
    profile,
    request: r,
    tenantId: "one",
    verifySuccess: async () => true,
    assertAuthorized: async () => {},
  });
  const plaintext = new TextEncoder().encode("482193");
  const results = await Promise.allSettled([
    d.submit({ plaintext, request: r, tenantId: "one" }),
    d.submit({ plaintext, request: r, tenantId: "one" }),
  ]);
  expect(results.filter((r) => r.status === "fulfilled")).toHaveLength(1);
  expect(f.submits()).toBe(1);
  expect(new TextDecoder().decode(plaintext)).toBe("482193");
});
test("navigation, revocation, expiry, wrong tenant and changed challenge reject before submission", async () => {
  for (const mode of [
    "navigation",
    "revocation",
    "expiry",
    "tenant",
    "challenge",
    "closed",
  ]) {
    const f = fixture(),
      r = request();
    let now = Date.now();
    const d = await createBrowserVerificationDestination({
      page: f.page,
      profile,
      request: r,
      tenantId: "one",
      verifySuccess: async () => true,
      now: () => now,
      assertAuthorized: async () => {
        if (mode === "revocation") throw Error("private");
      },
    });
    if (mode === "navigation") f.navigate();
    if (mode === "expiry") now = r.expiresAt;
    if (mode === "closed") d.close();
    let incoming = structuredClone(r);
    if (mode === "challenge")
      incoming = {
        ...incoming,
        resource: { ...incoming.resource, challengeId: "other" },
      };
    await expect(
      d.submit({
        plaintext: new TextEncoder().encode("482193"),
        request: incoming,
        tenantId: mode === "tenant" ? "two" : "one",
      }),
    ).rejects.toThrow();
    expect(f.submits()).toBe(0);
  }
});
test("provider error never escapes and an uncertain result cannot retry", async () => {
  const f = fixture(),
    r = request();
  const d = await createBrowserVerificationDestination({
    page: f.page,
    profile,
    request: r,
    tenantId: "one",
    verifySuccess: async () => {
      throw Error("private provider response 482193");
    },
    assertAuthorized: async () => {},
  });
  const input = {
    plaintext: new TextEncoder().encode("482193"),
    request: r,
    tenantId: "one",
  };
  await expect(d.submit(input)).rejects.toThrow("Browser verification failed");
  await expect(d.submit(input)).rejects.toThrow("already attempted");
  expect(f.submits()).toBe(1);
});
