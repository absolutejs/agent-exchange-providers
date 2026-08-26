import { describe, expect, test } from "bun:test";
import {
  assertPhishingResistantOAuthProvider,
  evaluateOAuthProviderConformance,
  type OAuthProviderDescriptor,
} from "../src";

const descriptor: OAuthProviderDescriptor = {
  authorizationEndpoint: "https://issuer.example/authorize",
  capabilities: {
    authorizationCode: "supported",
    issuerIdentification: "supported",
    par: "supported",
    pkceS256: "supported",
    rar: "supported",
    resourceIndicators: "supported",
    senderConstrainedAccessTokens: "dpop",
  },
  documentationUrl: "https://issuer.example/docs",
  issuer: "https://issuer.example",
  provider: "example",
  recommendedScopes: ["messages.read"],
  resource: "https://api.example/messages",
  tokenEndpoint: "https://issuer.example/token",
};

describe("OAuth provider conformance", () => {
  test("accepts only the complete hardened profile", () => {
    expect(evaluateOAuthProviderConformance(descriptor)).toEqual({
      eligibleForPhishingResistantProfile: true,
      failures: [],
      provider: "example",
    });
    expect(() =>
      assertPhishingResistantOAuthProvider(descriptor),
    ).not.toThrow();
  });

  test("fails closed for unknown and unsupported capabilities", () => {
    const weaker = {
      ...descriptor,
      capabilities: {
        ...descriptor.capabilities,
        par: "unknown",
        senderConstrainedAccessTokens: "unsupported",
      },
    } as const;
    expect(evaluateOAuthProviderConformance(weaker)).toMatchObject({
      eligibleForPhishingResistantProfile: false,
      failures: ["par", "senderConstrainedAccessTokens"],
    });
    expect(() => assertPhishingResistantOAuthProvider(weaker)).toThrow(
      "does not satisfy",
    );
  });
});
