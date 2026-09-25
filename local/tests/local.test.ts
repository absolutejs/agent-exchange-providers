import { expect, test } from "bun:test";
import {
  agentExchangeContext,
  type AgentExchangeRequest,
} from "@absolutejs/agent-exchange";
import { createWebCryptoEnvelopeProvider } from "@absolutejs/e2ee-webcrypto";
import {
  createLocalCodeRecipient,
  LOCAL_CLIPBOARD_OPERATION,
  encodeLocalDelivery,
  decodeLocalDelivery,
  clipboardServiceProfile,
} from "../src";

async function fixture() {
  const copied: Uint8Array[] = [];
  let authorized = true;
  const requester = {
    authority: "https://management.example",
    subject: "requester",
  };
  const local = await createLocalCodeRecipient({
    requestId: "request",
    requester,
    serviceOrigin: "https://service.example",
    accountRef: "mailbox",
    clipboard: {
      copy: async (bytes) => {
        copied.push(bytes.slice());
      },
    },
    assertAuthorized: async () => {
      if (!authorized) throw Error("Revoked");
    },
  });
  const request: AgentExchangeRequest = {
    actionId: "action",
    exchangeId: "exchange",
    nonce: "nonce",
    createdAt: Date.now(),
    expiresAt: Date.now() + 60000,
    maximumUses: 1,
    processingMode: "tool-confined",
    assurance: {
      approval: "standing-mandate",
      credential: "token-confined-broker",
      execution: "purpose-bound",
    },
    mandateId: "mandate",
    purpose: "Disclose code to clipboard",
    risk: "authentication",
    secretKind: "email-one-time-code",
    requester: { ...requester, agentId: "requester-agent" },
    recipient: {
      authority: "https://management.example",
      subject: "owner",
      agentId: "owner-agent",
    },
    resource: {
      origin: "https://service.example",
      operation: LOCAL_CLIPBOARD_OPERATION,
      provider: "gmail",
      accountRef: "mailbox",
      challengeId: "request",
    },
  };
  const authenticatedContext = await agentExchangeContext(request);
  const envelope = await createWebCryptoEnvelopeProvider({
    resolveRecipientPrivateKey: async () => undefined,
  }).seal({
    authenticatedContext,
    plaintext: new TextEncoder().encode("123456"),
    recipientPublicKey: local.publicKey,
  });
  return {
    local,
    request,
    copied,
    revoke: () => {
      authorized = false;
    },
    delivery: {
      request,
      authenticatedContext,
      envelope,
      recipientKeyId: local.keyId,
    },
  };
}
test("only the local recipient decrypts; wire and receipt do not disclose the code; replay fails", async () => {
  const f = await fixture();
  const wire = encodeLocalDelivery(f.delivery);
  expect(JSON.stringify(wire)).not.toContain("123456");
  const receipt = await f.local.receive(decodeLocalDelivery(wire));
  expect(new TextDecoder().decode(f.copied[0])).toBe("123456");
  expect(JSON.stringify(receipt)).not.toContain("123456");
  await expect(f.local.receive(f.delivery)).rejects.toThrow();
  expect(f.copied).toHaveLength(1);
});
test("wrong target, changed request context, key substitution and revoked access fail before clipboard", async () => {
  for (const variant of ["origin", "context", "key", "revoked"]) {
    const f = await fixture();
    const delivery = structuredClone(f.delivery);
    if (variant === "origin")
      (delivery.request.resource as { origin: string }).origin =
        "https://evil.example";
    if (variant === "context")
      (delivery.request as { purpose: string }).purpose = "Different operation";
    if (variant === "key") delivery.recipientKeyId = crypto.randomUUID();
    if (variant === "revoked") f.revoke();
    await expect(f.local.receive(delivery)).rejects.toThrow();
    expect(f.copied).toHaveLength(0);
  }
});
test("clipboard profiles cannot reuse browser permission identity or operation", () => {
  const source = {
    permission: {
      id: "browser",
      revision: "1",
      adapterRevision: "1",
      label: "Service",
      grant: { operation: "login.verify", purpose: "Sign in" },
    },
    email: { id: "mail", operations: ["login.verify"] },
  };
  const profile = clipboardServiceProfile(source);
  expect(profile.permission.id).not.toBe(source.permission.id);
  expect(profile.permission.grant.operation).toBe(LOCAL_CLIPBOARD_OPERATION);
  expect(profile.email.operations).toEqual([LOCAL_CLIPBOARD_OPERATION]);
  expect(source.permission.grant.operation).toBe("login.verify");
});
