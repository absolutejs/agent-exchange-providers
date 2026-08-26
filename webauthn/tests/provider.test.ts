import { describe, expect, test } from "bun:test";
import {
  agentExchangeMandateApprovalChallenge,
  type AgentExchangeRequest,
  type AgentExchangeStandingMandateDraft,
} from "@absolutejs/agent-exchange";
import type {
  WebAuthnAdapter,
  WebAuthnCredential,
  WebAuthnCredentialStore,
} from "@absolutejs/auth";
import {
  createWebAuthnAgentExchangeApprovalProvider,
  createWebAuthnAgentExchangeMandateApprovalProvider,
} from "../src";

const request = {
  actionId: "act_1",
  assurance: {
    approval: "webauthn-verifier-bound",
    credential: "sender-constrained",
    execution: "purpose-bound",
  },
  createdAt: 1,
  exchangeId: "ex_1",
  expiresAt: 10_000,
  maximumUses: 1,
  nonce: "nonce_1",
  processingMode: "tool-confined",
  purpose: "Redeem an exact authorization grant",
  recipient: {
    agentId: "recipient",
    authority: "https://recipient.example",
    subject: "user-1",
  },
  requester: {
    agentId: "requester",
    authority: "https://app.example.com",
    subject: "user-1",
  },
  resource: {
    accountRef: "account-1",
    operation: "authorize",
    origin: "https://api.example.com",
    provider: "example",
  },
  risk: "authentication",
  secretKind: "oauth-authorization-grant",
} as const satisfies AgentExchangeRequest;

const credential: WebAuthnCredential = {
  counter: 4,
  createdAt: 1,
  credentialId: "credential-1",
  publicKey: "public-key",
  userId: "user-1",
};

const setup = (verified = true) => {
  let saved: WebAuthnCredential | undefined;
  const store: WebAuthnCredentialStore = {
    getCredential: async () => credential,
    listCredentialsByUser: async () => [credential],
    removeCredential: async () => {},
    saveCredential: async (value) => {
      saved = value;
    },
  };
  const adapter: WebAuthnAdapter = {
    createAuthenticationOptions: async (input) => ({
      challenge: input.challenge ?? "wrong",
      options: { userVerification: input.userVerification },
    }),
    createRegistrationOptions: async () => ({ challenge: "x", options: {} }),
    verifyAuthentication: async (input) => {
      expect(input.expectedChallenge).toBe("digest-challenge");
      expect(input.expectedOrigin).toBe("https://app.example.com");
      expect(input.expectedRPID).toBe("example.com");
      expect(input.requireUserVerification).toBe(true);
      return { newCounter: 5, verified };
    },
    verifyRegistration: async () => ({ verified: false }),
  };
  const provider = createWebAuthnAgentExchangeApprovalProvider({
    adapter,
    credentialStore: store,
    now: () => 500,
    origin: "https://app.example.com",
    resolveUserId: ({ subject }) => subject,
    rpId: "example.com",
  });
  return { getSaved: () => saved, provider };
};

describe("WebAuthn Agent Exchange approval provider", () => {
  test("requires UV and verifies the exact request challenge", async () => {
    const { getSaved, provider } = setup();
    const begun = await provider.begin({
      challenge: "digest-challenge",
      request,
      subject: "user-1",
      verifierOrigin: "https://app.example.com",
    });
    expect(begun.challenge).toBe("digest-challenge");
    expect(begun.options).toEqual({ userVerification: "required" });

    const result = await provider.verify({
      challenge: "digest-challenge",
      request,
      response: { id: "credential-1" },
      subject: "user-1",
      verifierOrigin: "https://app.example.com",
    });
    expect(result).toEqual({
      credentialId: "credential-1",
      rpId: "example.com",
      subject: "user-1",
      userVerified: true,
      verifierOrigin: "https://app.example.com",
    });
    expect(getSaved()).toMatchObject({ counter: 5, lastUsedAt: 500 });
  });

  test("rejects a mismatched verifier and failed assertions", async () => {
    const { provider } = setup(false);
    await expect(
      provider.begin({
        challenge: "digest-challenge",
        request,
        subject: "user-1",
        verifierOrigin: "https://phish.example",
      }),
    ).rejects.toThrow("WebAuthn approval failed");
    await expect(
      provider.verify({
        challenge: "digest-challenge",
        request,
        response: { id: "credential-1" },
        subject: "user-1",
        verifierOrigin: "https://app.example.com",
      }),
    ).rejects.toThrow("WebAuthn approval failed");
  });

  test("allows HTTP localhost only behind the explicit development flag", () => {
    const options = {
      adapter: {} as WebAuthnAdapter,
      credentialStore: {} as WebAuthnCredentialStore,
      origin: "http://localhost:3000",
      resolveUserId: () => "user-1",
      rpId: "localhost",
    };
    expect(() => createWebAuthnAgentExchangeApprovalProvider(options)).toThrow(
      "HTTPS origin",
    );
    expect(() =>
      createWebAuthnAgentExchangeApprovalProvider({
        ...options,
        allowInsecureLocalhost: true,
      }),
    ).not.toThrow();
  });
});

const mandateDraft: AgentExchangeStandingMandateDraft = {
  audience: {
    agentId: "mailbox-agent",
    authority: "https://recipient.example",
    subject: "user-1",
  },
  expiresAt: 10_000,
  grants: [
    {
      accountRef: "mailbox-1",
      operation: "verification.submit",
      origin: "https://accounts.example",
      provider: "gmail",
      purpose: "Complete sign-in",
      risk: "authentication",
      secretKind: "email-one-time-code",
    },
  ],
  issuer: { authority: "https://app.example.com", subject: "user-1" },
  mandateId: "mandate-1",
  maximumUses: 5,
  notBefore: 500,
  requester: {
    agentId: "requester-agent",
    authority: "https://requester.example",
    subject: "requester-owner",
  },
};

describe("WebAuthn standing mandate approval provider", () => {
  test("recomputes the complete draft challenge and requires UV", async () => {
    let saved: WebAuthnCredential | undefined;
    const adapter: WebAuthnAdapter = {
      createAuthenticationOptions: async (input) => ({
        challenge: input.challenge ?? "wrong",
        options: { userVerification: input.userVerification },
      }),
      createRegistrationOptions: async () => ({ challenge: "x", options: {} }),
      verifyAuthentication: async () => ({ newCounter: 5, verified: true }),
      verifyRegistration: async () => ({ verified: false }),
    };
    const provider = createWebAuthnAgentExchangeMandateApprovalProvider({
      adapter,
      credentialStore: {
        getCredential: async () => credential,
        listCredentialsByUser: async () => [credential],
        removeCredential: async () => {},
        saveCredential: async (value) => {
          saved = value;
        },
      },
      now: () => 500,
      origin: "https://app.example.com",
      resolveUserId: ({ subject }) => subject,
      rpId: "example.com",
    });
    const challenge = await agentExchangeMandateApprovalChallenge(mandateDraft);
    await expect(
      provider.begin({
        challenge,
        draft: mandateDraft,
        subject: "user-1",
        verifierOrigin: "https://app.example.com",
      }),
    ).resolves.toMatchObject({ challenge });
    await expect(
      provider.verify({
        challenge,
        draft: mandateDraft,
        response: { id: "credential-1" },
        subject: "user-1",
        verifierOrigin: "https://app.example.com",
      }),
    ).resolves.toMatchObject({ userVerified: true });
    expect(saved).toMatchObject({ counter: 5, lastUsedAt: 500 });
  });

  test("rejects a challenge for a broader draft", async () => {
    const provider = createWebAuthnAgentExchangeMandateApprovalProvider({
      adapter: {} as WebAuthnAdapter,
      credentialStore: {} as WebAuthnCredentialStore,
      origin: "https://app.example.com",
      resolveUserId: () => "user-1",
      rpId: "example.com",
    });
    const challenge = await agentExchangeMandateApprovalChallenge(mandateDraft);
    await expect(
      provider.begin({
        challenge,
        draft: { ...mandateDraft, maximumUses: 6 },
        subject: "user-1",
        verifierOrigin: "https://app.example.com",
      }),
    ).rejects.toThrow("WebAuthn approval failed");
  });
});
