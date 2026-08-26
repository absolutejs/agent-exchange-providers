import type { AgentExchangeRequest } from "@absolutejs/agent-exchange";

const encoder = new TextEncoder();
const decoder = new TextDecoder("utf-8", { fatal: true });
const MAX_RESPONSE_BYTES = 64 * 1024;

export type OAuthAuthorizationDetails = {
  readonly actions: readonly string[];
  readonly identifier?: string;
  readonly locations: readonly string[];
  readonly type: string;
};

export type HardenedOAuthProfile = {
  readonly authorizationDetails: OAuthAuthorizationDetails;
  readonly authorizationEndpoint: string;
  readonly clientId: string;
  readonly issuer: string;
  readonly pushedAuthorizationRequestEndpoint: string;
  readonly redirectUri: string;
  readonly resource: string;
  readonly scopes: readonly string[];
  readonly tokenEndpoint: string;
};

export type OAuthAuthorizationSession = {
  readonly codeVerifier: string;
  readonly exchangeId: string;
  readonly expiresAt: number;
  readonly issuer: string;
  readonly state: string;
};

export type OAuthAuthorizationSessionStore = {
  readonly consume: (
    state: string,
  ) => Promise<OAuthAuthorizationSession | undefined>;
  readonly save: (session: OAuthAuthorizationSession) => Promise<boolean>;
};

export type OAuthGrant = {
  readonly code: string;
  readonly codeVerifier: string;
  readonly exchangeId: string;
  readonly expiresAt: number;
  readonly issuer: string;
};

export type DpopProofSigner = {
  readonly createProof: (input: {
    readonly accessToken?: string;
    readonly htm: "POST";
    readonly htu: string;
    readonly nonce?: string;
  }) => Promise<string> | string;
};

export type OAuthFetch = (
  input: string,
  init: RequestInit,
) => Promise<Response>;

const fail = (message: string): never => {
  throw new Error(`OAuth exchange failed: ${message}`);
};

const exactHttpsUrl = (value: string, name: string): URL => {
  const url = new URL(value);
  if (url.protocol !== "https:" || url.username !== "" || url.password !== "") {
    return fail(`${name} must be an HTTPS URL without credentials`);
  }
  return url;
};

const validateProfile = (profile: HardenedOAuthProfile): void => {
  const issuer = exactHttpsUrl(profile.issuer, "issuer");
  if (issuer.search !== "" || issuer.hash !== "")
    fail("issuer must not contain query or fragment");
  exactHttpsUrl(profile.authorizationEndpoint, "authorizationEndpoint");
  exactHttpsUrl(
    profile.pushedAuthorizationRequestEndpoint,
    "pushedAuthorizationRequestEndpoint",
  );
  exactHttpsUrl(profile.tokenEndpoint, "tokenEndpoint");
  exactHttpsUrl(profile.redirectUri, "redirectUri");
  exactHttpsUrl(profile.resource, "resource");
  if (profile.clientId.length === 0 || profile.clientId.length > 512)
    fail("invalid clientId");
  if (
    profile.scopes.length === 0 ||
    profile.scopes.some((scope) => scope === "" || /\s/.test(scope))
  )
    fail("invalid scopes");
  const details = profile.authorizationDetails;
  if (
    details.type === "" ||
    details.type.length > 256 ||
    details.actions.length === 0 ||
    details.actions.some(
      (action) => action.length === 0 || action.length > 256,
    ) ||
    details.locations.length === 0 ||
    details.locations.some(
      (location) =>
        exactHttpsUrl(location, "authorization location").origin === "",
    )
  )
    fail("invalid authorization_details");
};

const assertPhishingResistantRequest = (
  request: AgentExchangeRequest,
  profile: HardenedOAuthProfile,
): void => {
  if (
    request.assurance.approval !== "webauthn-verifier-bound" ||
    request.assurance.credential !== "sender-constrained" ||
    request.assurance.execution !== "purpose-bound"
  )
    fail("request does not use the phishing-resistant assurance profile");
  if (request.resource.origin !== new URL(profile.resource).origin)
    fail("resource origin mismatch");
};

const randomBase64Url = (bytes: number): string => {
  const value = crypto.getRandomValues(new Uint8Array(bytes));
  let binary = "";
  for (const byte of value) binary += String.fromCharCode(byte);
  return btoa(binary)
    .replaceAll("+", "-")
    .replaceAll("/", "_")
    .replace(/=+$/u, "");
};

const sha256Base64Url = async (value: string): Promise<string> => {
  const digest = new Uint8Array(
    await crypto.subtle.digest("SHA-256", encoder.encode(value)),
  );
  let binary = "";
  for (const byte of digest) binary += String.fromCharCode(byte);
  return btoa(binary)
    .replaceAll("+", "-")
    .replaceAll("/", "_")
    .replace(/=+$/u, "");
};

const readJson = async (
  response: Response,
): Promise<Record<string, unknown>> => {
  const declared = Number(response.headers.get("content-length") ?? "0");
  if (Number.isFinite(declared) && declared > MAX_RESPONSE_BYTES)
    fail("response too large");
  const text = await response.text();
  if (encoder.encode(text).byteLength > MAX_RESPONSE_BYTES)
    fail("response too large");
  try {
    const value: unknown = JSON.parse(text);
    if (typeof value !== "object" || value === null || Array.isArray(value))
      return fail("invalid JSON response");
    return value as Record<string, unknown>;
  } catch {
    return fail("invalid JSON response");
  }
};

export const createHardenedOAuthAuthorizationClient = (options: {
  readonly fetch?: OAuthFetch;
  readonly now?: () => number;
  readonly profile: HardenedOAuthProfile;
  readonly sessionStore: OAuthAuthorizationSessionStore;
}) => {
  validateProfile(options.profile);
  const requestFetch = options.fetch ?? fetch;
  const now = options.now ?? Date.now;

  return {
    begin: async (request: AgentExchangeRequest) => {
      assertPhishingResistantRequest(request, options.profile);
      const state = randomBase64Url(32);
      const codeVerifier = randomBase64Url(32);
      const body = new URLSearchParams({
        authorization_details: JSON.stringify(
          options.profile.authorizationDetails,
        ),
        client_id: options.profile.clientId,
        code_challenge: await sha256Base64Url(codeVerifier),
        code_challenge_method: "S256",
        redirect_uri: options.profile.redirectUri,
        resource: options.profile.resource,
        response_type: "code",
        scope: options.profile.scopes.join(" "),
        state,
      });
      const response = await requestFetch(
        options.profile.pushedAuthorizationRequestEndpoint,
        {
          body,
          headers: { "content-type": "application/x-www-form-urlencoded" },
          method: "POST",
          redirect: "error",
        },
      );
      if (response.status !== 201) fail("PAR was not accepted");
      const parsed = await readJson(response);
      if (
        typeof parsed.request_uri !== "string" ||
        !parsed.request_uri.startsWith("urn:") ||
        parsed.request_uri.length > 2048 ||
        typeof parsed.expires_in !== "number" ||
        !Number.isSafeInteger(parsed.expires_in) ||
        parsed.expires_in < 1 ||
        parsed.expires_in > 600
      )
        fail("invalid PAR response");
      const requestUri = parsed.request_uri as string;
      const expiresIn = parsed.expires_in as number;
      const expiresAt = Math.min(request.expiresAt, now() + expiresIn * 1000);
      if (
        !(await options.sessionStore.save({
          codeVerifier,
          exchangeId: request.exchangeId,
          expiresAt,
          issuer: options.profile.issuer,
          state,
        }))
      ) {
        fail("authorization state collision");
      }
      const url = new URL(options.profile.authorizationEndpoint);
      url.searchParams.set("client_id", options.profile.clientId);
      url.searchParams.set("request_uri", requestUri);
      return { expiresAt, url: url.toString() };
    },

    complete: async (input: {
      readonly code: string;
      readonly iss: string;
      readonly state: string;
    }) => {
      const session = await options.sessionStore.consume(input.state);
      if (session === undefined)
        throw new Error(
          "OAuth exchange failed: invalid authorization response",
        );
      if (
        session.expiresAt <= now() ||
        session.state !== input.state ||
        input.iss !== options.profile.issuer ||
        session.issuer !== options.profile.issuer ||
        input.code.length === 0 ||
        input.code.length > 4096
      )
        fail("invalid authorization response");
      return {
        code: input.code,
        codeVerifier: session.codeVerifier,
        exchangeId: session.exchangeId,
        expiresAt: session.expiresAt,
        issuer: session.issuer,
      } satisfies OAuthGrant;
    },
  };
};

export const encodeOAuthGrant = (grant: OAuthGrant): Uint8Array =>
  encoder.encode(JSON.stringify(grant));

export const decodeOAuthGrant = (bytes: Uint8Array): OAuthGrant => {
  if (bytes.byteLength === 0 || bytes.byteLength > 16 * 1024)
    return fail("invalid grant bundle");
  try {
    const value: unknown = JSON.parse(decoder.decode(bytes));
    if (typeof value !== "object" || value === null)
      return fail("invalid grant bundle");
    const grant = value as Partial<OAuthGrant>;
    if (
      typeof grant.code !== "string" ||
      grant.code.length === 0 ||
      grant.code.length > 4096 ||
      typeof grant.codeVerifier !== "string" ||
      !/^[A-Za-z0-9._~-]{43,128}$/u.test(grant.codeVerifier) ||
      typeof grant.exchangeId !== "string" ||
      typeof grant.expiresAt !== "number" ||
      typeof grant.issuer !== "string"
    )
      return fail("invalid grant bundle");
    return grant as OAuthGrant;
  } catch {
    return fail("invalid grant bundle");
  }
};

export const redeemOAuthGrant = async <Result>(options: {
  readonly dpop: DpopProofSigner;
  readonly execute: (input: {
    readonly accessToken: string;
    readonly createDpopProof: DpopProofSigner["createProof"];
  }) => Promise<Result>;
  readonly fetch?: OAuthFetch;
  readonly grant: OAuthGrant;
  readonly now?: () => number;
  readonly profile: HardenedOAuthProfile;
  readonly request: AgentExchangeRequest;
}): Promise<Result> => {
  validateProfile(options.profile);
  assertPhishingResistantRequest(options.request, options.profile);
  const now = options.now ?? Date.now;
  if (
    options.grant.exchangeId !== options.request.exchangeId ||
    options.grant.issuer !== options.profile.issuer ||
    options.grant.expiresAt <= now()
  )
    fail("grant binding mismatch");
  const requestFetch = options.fetch ?? fetch;
  const body = new URLSearchParams({
    client_id: options.profile.clientId,
    code: options.grant.code,
    code_verifier: options.grant.codeVerifier,
    grant_type: "authorization_code",
    redirect_uri: options.profile.redirectUri,
    resource: options.profile.resource,
  });
  const exchange = async (nonce?: string) =>
    requestFetch(options.profile.tokenEndpoint, {
      body,
      headers: {
        "content-type": "application/x-www-form-urlencoded",
        dpop: await options.dpop.createProof({
          htm: "POST",
          htu: options.profile.tokenEndpoint,
          ...(nonce === undefined ? {} : { nonce }),
        }),
      },
      method: "POST",
      redirect: "error",
    });
  let response = await exchange();
  const nonce = response.headers.get("dpop-nonce");
  if (!response.ok && nonce !== null && nonce.length <= 1024)
    response = await exchange(nonce);
  if (!response.ok) fail("token redemption failed");
  const parsed = await readJson(response);
  if (
    typeof parsed.token_type !== "string" ||
    parsed.token_type.toLowerCase() !== "dpop" ||
    typeof parsed.access_token !== "string" ||
    parsed.access_token.length === 0 ||
    parsed.access_token.length > 16 * 1024 ||
    typeof parsed.expires_in !== "number" ||
    parsed.expires_in <= 0 ||
    parsed.expires_in > 3600
  )
    fail("token is not acceptably sender-constrained");
  const accessToken = parsed.access_token;
  if (typeof accessToken !== "string")
    throw new Error(
      "OAuth exchange failed: token is not acceptably sender-constrained",
    );
  return options.execute({
    accessToken,
    createDpopProof: options.dpop.createProof,
  });
};
