import type { OAuthProviderDescriptor } from "@absolutejs/agent-exchange-provider-conformance";

export const GOOGLE_GMAIL_READONLY_SCOPE =
  "https://www.googleapis.com/auth/gmail.readonly";

export const GOOGLE_GMAIL_OAUTH_PROVIDER = Object.freeze({
  authorizationEndpoint: "https://accounts.google.com/o/oauth2/v2/auth",
  capabilities: {
    authorizationCode: "supported",
    issuerIdentification: "supported",
    par: "unsupported",
    pkceS256: "supported",
    rar: "unsupported",
    resourceIndicators: "unsupported",
    senderConstrainedAccessTokens: "unsupported",
  },
  documentationUrl:
    "https://developers.google.com/identity/protocols/oauth2/resources/dpop-adoption",
  issuer: "https://accounts.google.com",
  notes: [
    "Google's documented DPoP mode binds refresh tokens, while access tokens remain Bearer.",
    "gmail.readonly is a restricted scope and may require Google verification and a security assessment.",
  ],
  provider: "google-gmail",
  recommendedScopes: [GOOGLE_GMAIL_READONLY_SCOPE],
  resource: "https://gmail.googleapis.com/",
  tokenEndpoint: "https://oauth2.googleapis.com/token",
} as const satisfies OAuthProviderDescriptor);
