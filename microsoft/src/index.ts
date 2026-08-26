import type { OAuthProviderDescriptor } from "@absolutejs/agent-exchange-provider-conformance";

export const MICROSOFT_GRAPH_MAIL_READ_SCOPE =
  "https://graph.microsoft.com/Mail.Read";

export const createMicrosoftGraphOAuthProvider = (
  tenantId: string,
): OAuthProviderDescriptor => {
  const normalized = tenantId.toLowerCase();
  if (
    !/^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/u.test(
      normalized,
    )
  )
    throw new Error("Microsoft Graph OAuth requires one exact tenant UUID");
  const authority = `https://login.microsoftonline.com/${normalized}`;
  return Object.freeze({
    authorizationEndpoint: `${authority}/oauth2/v2.0/authorize`,
    capabilities: {
      authorizationCode: "supported",
      issuerIdentification: "unknown",
      par: "unsupported",
      pkceS256: "supported",
      rar: "unsupported",
      resourceIndicators: "unsupported",
      senderConstrainedAccessTokens: "unknown",
    },
    documentationUrl:
      "https://learn.microsoft.com/en-us/entra/identity-platform/v2-oauth2-auth-code-flow",
    issuer: `${authority}/v2.0`,
    notes: [
      "The adapter is tenant-specific and rejects multi-tenant authority aliases.",
      "The generally available Graph authorization-code documentation does not establish the complete AbsoluteJS hardened profile.",
    ],
    provider: "microsoft-graph",
    recommendedScopes: [MICROSOFT_GRAPH_MAIL_READ_SCOPE],
    resource: "https://graph.microsoft.com/",
    tokenEndpoint: `${authority}/oauth2/v2.0/token`,
  } as const satisfies OAuthProviderDescriptor);
};
