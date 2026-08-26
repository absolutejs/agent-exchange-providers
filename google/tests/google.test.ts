import { expect, test } from "bun:test";
import { evaluateOAuthProviderConformance } from "@absolutejs/agent-exchange-provider-conformance";
import { GOOGLE_GMAIL_OAUTH_PROVIDER } from "../src";

test("Google adapter honestly declares its upstream bearer boundary", () => {
  expect(evaluateOAuthProviderConformance(GOOGLE_GMAIL_OAUTH_PROVIDER)).toEqual(
    {
      eligibleForPhishingResistantProfile: false,
      failures: [
        "par",
        "rar",
        "resourceIndicators",
        "senderConstrainedAccessTokens",
      ],
      provider: "google-gmail",
    },
  );
});
