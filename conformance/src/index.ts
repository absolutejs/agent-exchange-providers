const encoder = new TextEncoder();
const decoder = new TextDecoder("utf-8", { fatal: true });

const asArrayBuffer = (value: Uint8Array): ArrayBuffer =>
  Uint8Array.from(value).buffer;

export type OAuthFeatureStatus = "supported" | "unknown" | "unsupported";

export type OAuthProviderCapabilities = {
  readonly authorizationCode: OAuthFeatureStatus;
  readonly issuerIdentification: OAuthFeatureStatus;
  readonly par: OAuthFeatureStatus;
  readonly pkceS256: OAuthFeatureStatus;
  readonly rar: OAuthFeatureStatus;
  readonly resourceIndicators: OAuthFeatureStatus;
  readonly senderConstrainedAccessTokens:
    "dpop" | "mtls" | "unknown" | "unsupported";
};

export type OAuthProviderDescriptor = {
  readonly authorizationEndpoint: string;
  readonly capabilities: OAuthProviderCapabilities;
  readonly documentationUrl: string;
  readonly issuer: string;
  readonly notes?: readonly string[];
  readonly provider: string;
  readonly recommendedScopes: readonly string[];
  readonly resource: string;
  readonly tokenEndpoint: string;
};

export type OAuthConformanceReport = {
  readonly eligibleForPhishingResistantProfile: boolean;
  readonly failures: readonly string[];
  readonly provider: string;
};

const httpsUrl = (value: string, name: string): URL => {
  const url = new URL(value);
  if (url.protocol !== "https:" || url.username !== "" || url.password !== "")
    throw new Error(`${name} must be an HTTPS URL without credentials`);
  return url;
};

export const evaluateOAuthProviderConformance = (
  descriptor: OAuthProviderDescriptor,
): OAuthConformanceReport => {
  if (descriptor.provider.length === 0 || descriptor.provider.length > 128)
    throw new Error("provider must be a bounded identifier");
  httpsUrl(descriptor.issuer, "issuer");
  httpsUrl(descriptor.authorizationEndpoint, "authorizationEndpoint");
  httpsUrl(descriptor.tokenEndpoint, "tokenEndpoint");
  httpsUrl(descriptor.resource, "resource");
  httpsUrl(descriptor.documentationUrl, "documentationUrl");
  if (
    descriptor.recommendedScopes.length === 0 ||
    descriptor.recommendedScopes.some(
      (scope) => scope.length === 0 || scope.length > 512 || /\s/u.test(scope),
    )
  )
    throw new Error(
      "recommendedScopes must contain bounded OAuth scope values",
    );

  const failures: string[] = [];
  const requireFeature = (
    name: keyof Omit<
      OAuthProviderCapabilities,
      "senderConstrainedAccessTokens"
    >,
  ) => {
    if (descriptor.capabilities[name] !== "supported") failures.push(name);
  };
  requireFeature("authorizationCode");
  requireFeature("issuerIdentification");
  requireFeature("par");
  requireFeature("pkceS256");
  requireFeature("rar");
  requireFeature("resourceIndicators");
  if (
    descriptor.capabilities.senderConstrainedAccessTokens !== "dpop" &&
    descriptor.capabilities.senderConstrainedAccessTokens !== "mtls"
  )
    failures.push("senderConstrainedAccessTokens");

  return Object.freeze({
    eligibleForPhishingResistantProfile: failures.length === 0,
    failures: Object.freeze(failures),
    provider: descriptor.provider,
  });
};

export const assertPhishingResistantOAuthProvider = (
  descriptor: OAuthProviderDescriptor,
): void => {
  const report = evaluateOAuthProviderConformance(descriptor);
  if (!report.eligibleForPhishingResistantProfile)
    throw new Error(
      `OAuth provider ${report.provider} does not satisfy the phishing-resistant profile: ${report.failures.join(", ")}`,
    );
};

const fromBase64Url = (value: string): Uint8Array => {
  if (!/^[A-Za-z0-9_-]+$/u.test(value)) throw new Error("invalid base64url");
  const padded = value
    .replaceAll("-", "+")
    .replaceAll("_", "/")
    .padEnd(Math.ceil(value.length / 4) * 4, "=");
  const binary = atob(padded);
  return Uint8Array.from(binary, (character) => character.charCodeAt(0));
};

const toBase64Url = (value: Uint8Array): string => {
  let binary = "";
  for (const byte of value) binary += String.fromCharCode(byte);
  return btoa(binary)
    .replaceAll("+", "-")
    .replaceAll("/", "_")
    .replace(/=+$/u, "");
};

const parseJsonPart = (value: string): Record<string, unknown> => {
  const bytes = fromBase64Url(value);
  if (bytes.byteLength === 0 || bytes.byteLength > 8 * 1024)
    throw new Error("invalid DPoP JWT part");
  const parsed: unknown = JSON.parse(decoder.decode(bytes));
  if (typeof parsed !== "object" || parsed === null || Array.isArray(parsed))
    throw new Error("invalid DPoP JWT part");
  return parsed as Record<string, unknown>;
};

export const normalizeDpopHtu = (value: string): string => {
  const url = httpsUrl(value, "htu");
  url.hash = "";
  url.search = "";
  return url.toString();
};

const tokenHash = async (token: string): Promise<string> =>
  toBase64Url(
    new Uint8Array(
      await crypto.subtle.digest("SHA-256", encoder.encode(token)),
    ),
  );

export const verifyDpopProof = async (input: {
  readonly accessToken?: string;
  readonly htm: string;
  readonly htu: string;
  readonly maxAgeSeconds?: number;
  readonly nonce?: string;
  readonly now?: () => number;
  readonly proof: string;
}): Promise<JsonWebKey> => {
  if (input.proof.length === 0 || input.proof.length > 16 * 1024)
    throw new Error("invalid DPoP proof");
  const parts = input.proof.split(".");
  if (parts.length !== 3 || parts.some((part) => part.length === 0))
    throw new Error("invalid DPoP proof");
  const [headerPart, payloadPart, signaturePart] = parts as [
    string,
    string,
    string,
  ];
  const header = parseJsonPart(headerPart);
  const payload = parseJsonPart(payloadPart);
  if (header.typ !== "dpop+jwt" || header.alg !== "ES256")
    throw new Error("invalid DPoP header");
  if (typeof header.jwk !== "object" || header.jwk === null)
    throw new Error("invalid DPoP public key");
  const jwk = header.jwk as JsonWebKey & { readonly d?: unknown };
  if (
    jwk.kty !== "EC" ||
    jwk.crv !== "P-256" ||
    typeof jwk.x !== "string" ||
    typeof jwk.y !== "string" ||
    jwk.d !== undefined
  )
    throw new Error("invalid DPoP public key");
  if (
    payload.htm !== input.htm ||
    payload.htu !== normalizeDpopHtu(input.htu) ||
    typeof payload.jti !== "string" ||
    encoder.encode(payload.jti).byteLength < 12 ||
    typeof payload.iat !== "number" ||
    !Number.isSafeInteger(payload.iat)
  )
    throw new Error("invalid DPoP claims");
  const now = Math.floor((input.now ?? Date.now)() / 1000);
  const maxAge = input.maxAgeSeconds ?? 60;
  if (
    maxAge < 1 ||
    maxAge > 300 ||
    payload.iat > now + 5 ||
    payload.iat < now - maxAge
  )
    throw new Error("expired DPoP proof");
  if (payload.nonce !== input.nonce) throw new Error("invalid DPoP nonce");
  const expectedAth =
    input.accessToken === undefined
      ? undefined
      : await tokenHash(input.accessToken);
  if (payload.ath !== expectedAth)
    throw new Error("invalid DPoP access-token hash");

  const publicKey = await crypto.subtle.importKey(
    "jwk",
    jwk,
    { name: "ECDSA", namedCurve: "P-256" },
    false,
    ["verify"],
  );
  const verified = await crypto.subtle.verify(
    { hash: "SHA-256", name: "ECDSA" },
    publicKey,
    asArrayBuffer(fromBase64Url(signaturePart)),
    encoder.encode(`${headerPart}.${payloadPart}`),
  );
  if (!verified) throw new Error("invalid DPoP signature");
  return Object.freeze({ ...jwk });
};

export * from "./a2a";
