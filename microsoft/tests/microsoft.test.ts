import { describe, expect, test } from "bun:test";
import { evaluateOAuthProviderConformance } from "@absolutejs/agent-exchange-provider-conformance";
import { createMicrosoftGraphOAuthProvider } from "../src";

describe("Microsoft Graph OAuth adapter", () => {
  test("pins one tenant and declares unsupported or unverified features", () => {
    const provider = createMicrosoftGraphOAuthProvider(
      "123e4567-e89b-42d3-a456-426614174000",
    );
    expect(provider.issuer).toContain("123e4567-e89b-42d3-a456-426614174000");
    expect(evaluateOAuthProviderConformance(provider)).toMatchObject({
      eligibleForPhishingResistantProfile: false,
      failures: [
        "issuerIdentification",
        "par",
        "rar",
        "resourceIndicators",
        "senderConstrainedAccessTokens",
      ],
    });
  });

  test("rejects ambiguous multi-tenant authorities", () => {
    for (const tenant of ["common", "organizations", "consumers"]) {
      expect(() => createMicrosoftGraphOAuthProvider(tenant)).toThrow(
        "exact tenant UUID",
      );
    }
  });
});
