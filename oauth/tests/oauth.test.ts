import { describe, expect, test } from "bun:test";
import type { AgentExchangeRequest } from "@absolutejs/agent-exchange";
import {
  createHardenedOAuthAuthorizationClient,
  decodeOAuthGrant,
  encodeOAuthGrant,
  redeemOAuthGrant,
  type HardenedOAuthProfile,
  type OAuthAuthorizationSession,
} from "../src";

const profile: HardenedOAuthProfile = {
  authorizationDetails: {
    actions: ["read"],
    identifier: "inbox-code",
    locations: ["https://api.example.com/messages"],
    type: "absolute_agent_action",
  },
  authorizationEndpoint: "https://issuer.example/authorize",
  clientId: "agent-client",
  issuer: "https://issuer.example",
  pushedAuthorizationRequestEndpoint: "https://issuer.example/par",
  redirectUri: "https://app.example.com/oauth/callback",
  resource: "https://api.example.com/messages",
  scopes: ["messages.read"],
  tokenEndpoint: "https://issuer.example/token",
};

const request = {
  actionId: "act_1",
  assurance: {
    approval: "webauthn-verifier-bound",
    credential: "sender-constrained",
    execution: "purpose-bound",
  },
  createdAt: 1,
  exchangeId: "ex_1",
  expiresAt: 20_000,
  maximumUses: 1,
  nonce: "nonce_1",
  processingMode: "tool-confined",
  purpose: "Read the requested mailbox message",
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
    accountRef: "mailbox",
    operation: "read",
    origin: "https://api.example.com",
    provider: "mail",
  },
  risk: "authentication",
  secretKind: "oauth-authorization-grant",
} as const satisfies AgentExchangeRequest;

describe("hardened OAuth Agent Exchange", () => {
  test("uses PAR, S256 PKCE, exact issuer, and one-time state", async () => {
    let saved: OAuthAuthorizationSession | undefined;
    let parBody = "";
    const client = createHardenedOAuthAuthorizationClient({
      fetch: async (_url, init) => {
        parBody = String(init.body);
        return Response.json(
          {
            expires_in: 90,
            request_uri: "https://issuer.example/request/abc",
          },
          { status: 201 },
        );
      },
      now: () => 1_000,
      profile,
      sessionStore: {
        consume: async () => {
          const value = saved;
          saved = undefined;
          return value;
        },
        save: async (value) => {
          saved = value;
          return true;
        },
      },
    });
    const begun = await client.begin(request);
    expect(begun.url).toContain(
      "request_uri=https%3A%2F%2Fissuer.example%2Frequest%2Fabc",
    );
    expect(begun.url).not.toContain("code_challenge");
    const params = new URLSearchParams(parBody);
    expect(params.get("code_challenge_method")).toBe("S256");
    expect(params.get("resource")).toBe(profile.resource);
    expect(saved?.codeVerifier).toHaveLength(43);

    const grant = await client.complete({
      code: "one-time-code",
      iss: profile.issuer,
      state: saved!.state,
    });
    expect(decodeOAuthGrant(encodeOAuthGrant(grant))).toEqual(grant);
    await expect(
      client.complete({
        code: "replay",
        iss: profile.issuer,
        state: saved?.state ?? "used",
      }),
    ).rejects.toThrow();
  });

  test("redeems only a DPoP token and binds it to the exchange", async () => {
    const grant = {
      code: "code",
      codeVerifier: "a".repeat(43),
      exchangeId: "ex_1",
      expiresAt: 10_000,
      issuer: profile.issuer,
    };
    let proofCalls = 0;
    const result = await redeemOAuthGrant({
      dpop: {
        createProof: async ({ accessToken }) => {
          expect(accessToken).toBeUndefined();
          proofCalls += 1;
          return "signed-proof";
        },
      },
      execute: async ({ accessToken }) => `used:${accessToken}`,
      fetch: async (_url, init) => {
        expect(new Headers(init.headers).get("dpop")).toBe("signed-proof");
        return Response.json({
          access_token: "bound-token",
          expires_in: 300,
          token_type: "DPoP",
        });
      },
      grant,
      now: () => 2_000,
      profile,
      request,
    });
    expect(result).toBe("used:bound-token");
    expect(proofCalls).toBe(1);
  });

  test("rejects bearer assurance", async () => {
    const bearer = {
      ...request,
      assurance: {
        approval: "policy",
        credential: "bearer",
        execution: "purpose-bound",
      },
    } as const;
    await expect(
      createHardenedOAuthAuthorizationClient({
        profile,
        sessionStore: {
          consume: async () => undefined,
          save: async () => true,
        },
      }).begin(bearer),
    ).rejects.toThrow("phishing-resistant");
  });
});
