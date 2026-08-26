import type {
  AgentExchangeApprovalProvider,
  AgentExchangeRequest,
  AgentExchangeStandingMandateDraft,
} from "@absolutejs/agent-exchange";
import { agentExchangeMandateApprovalChallenge } from "@absolutejs/agent-exchange";
import type {
  WebAuthnAdapter,
  WebAuthnCredentialStore,
} from "@absolutejs/auth";

const MAX_CREDENTIALS = 20;
const MAX_CREDENTIAL_ID_LENGTH = 2048;

export type WebAuthnAgentExchangeApprovalProviderOptions = {
  readonly allowInsecureLocalhost?: boolean;
  readonly adapter: WebAuthnAdapter;
  readonly credentialStore: WebAuthnCredentialStore;
  readonly now?: () => number;
  readonly origin: string;
  readonly resolveUserId: (input: {
    readonly request: AgentExchangeRequest;
    readonly subject: string;
  }) => Promise<string> | string;
  readonly rpId: string;
};

export type AgentExchangeMandateApprovalProvider = {
  readonly begin: (input: {
    readonly challenge: string;
    readonly draft: AgentExchangeStandingMandateDraft;
    readonly subject: string;
    readonly verifierOrigin: string;
  }) => Promise<{ readonly challenge: string; readonly options: unknown }>;
  readonly verify: (input: {
    readonly challenge: string;
    readonly draft: AgentExchangeStandingMandateDraft;
    readonly response: unknown;
    readonly subject: string;
    readonly verifierOrigin: string;
  }) => Promise<{
    readonly credentialId: string;
    readonly rpId: string;
    readonly subject: string;
    readonly userVerified: true;
    readonly verifierOrigin: string;
  }>;
};

export type WebAuthnAgentExchangeMandateApprovalProviderOptions = {
  readonly allowInsecureLocalhost?: boolean;
  readonly adapter: WebAuthnAdapter;
  readonly credentialStore: WebAuthnCredentialStore;
  readonly now?: () => number;
  readonly origin: string;
  readonly resolveUserId: (input: {
    readonly draft: AgentExchangeStandingMandateDraft;
    readonly subject: string;
  }) => Promise<string> | string;
  readonly rpId: string;
};

const fail = (): never => {
  throw new Error("WebAuthn approval failed");
};

const validatedOrigin = (
  value: string,
  allowInsecureLocalhost: boolean,
): URL => {
  const url = new URL(value);
  const isLocalhost =
    url.hostname === "localhost" ||
    url.hostname === "127.0.0.1" ||
    url.hostname === "[::1]";
  if (
    (url.protocol !== "https:" &&
      !(allowInsecureLocalhost && url.protocol === "http:" && isLocalhost)) ||
    url.username !== "" ||
    url.password !== "" ||
    url.pathname !== "/" ||
    url.search !== "" ||
    url.hash !== ""
  ) {
    throw new Error(
      "origin must be an HTTPS origin without credentials or a path",
    );
  }
  return url;
};

const assertRpId = (
  origin: URL,
  rpId: string,
  allowInsecureLocalhost: boolean,
): void => {
  const normalized = rpId.toLowerCase();
  const isAllowedLocalhost =
    allowInsecureLocalhost &&
    (normalized === "localhost" || normalized === "127.0.0.1") &&
    origin.hostname === normalized;
  if (
    normalized === "" ||
    normalized.includes(":") ||
    (!isAllowedLocalhost &&
      (!normalized.includes(".") ||
        (origin.hostname !== normalized &&
          !origin.hostname.endsWith(`.${normalized}`))))
  ) {
    throw new Error("rpId must equal or be a registrable suffix of origin");
  }
};

const responseCredentialId = (response: unknown): string => {
  if (
    typeof response !== "object" ||
    response === null ||
    !("id" in response) ||
    typeof response.id !== "string" ||
    response.id.length === 0 ||
    response.id.length > MAX_CREDENTIAL_ID_LENGTH
  ) {
    return fail();
  }
  return response.id;
};

export const createWebAuthnAgentExchangeApprovalProvider = (
  options: WebAuthnAgentExchangeApprovalProviderOptions,
): AgentExchangeApprovalProvider => {
  const allowInsecureLocalhost = options.allowInsecureLocalhost === true;
  const origin = validatedOrigin(options.origin, allowInsecureLocalhost);
  const expectedOrigin = origin.origin;
  const rpId = options.rpId.toLowerCase();
  assertRpId(origin, rpId, allowInsecureLocalhost);
  const now = options.now ?? Date.now;

  const resolveOwnedCredentials = async (
    request: AgentExchangeRequest,
    subject: string,
  ) => {
    const userId = await options.resolveUserId({ request, subject });
    if (typeof userId !== "string" || userId.length === 0) return fail();
    const credentials =
      await options.credentialStore.listCredentialsByUser(userId);
    if (credentials.length === 0 || credentials.length > MAX_CREDENTIALS)
      return fail();
    return { credentials, userId };
  };

  return {
    begin: async ({ challenge, request, subject, verifierOrigin }) => {
      if (
        verifierOrigin !== expectedOrigin ||
        request.requester.authority !== expectedOrigin ||
        subject !== request.requester.subject
      )
        return fail();
      const { credentials } = await resolveOwnedCredentials(request, subject);
      const generated = await options.adapter.createAuthenticationOptions({
        allowCredentials: credentials.map(({ credentialId, transports }) => ({
          id: credentialId,
          ...(transports === undefined ? {} : { transports }),
        })),
        challenge,
        rpId,
        userVerification: "required",
      });
      if (generated.challenge !== challenge) return fail();
      return { challenge, options: generated.options };
    },

    verify: async ({
      challenge,
      request,
      response,
      subject,
      verifierOrigin,
    }) => {
      if (
        verifierOrigin !== expectedOrigin ||
        request.requester.authority !== expectedOrigin ||
        subject !== request.requester.subject
      )
        return fail();
      const { credentials, userId } = await resolveOwnedCredentials(
        request,
        subject,
      );
      const credentialId = responseCredentialId(response);
      const credential = credentials.find(
        (value) => value.credentialId === credentialId,
      );
      if (credential === undefined || credential.userId !== userId)
        return fail();

      const result = await options.adapter.verifyAuthentication({
        credential: {
          counter: credential.counter,
          credentialId: credential.credentialId,
          publicKey: credential.publicKey,
          ...(credential.transports === undefined
            ? {}
            : { transports: credential.transports }),
        },
        expectedChallenge: challenge,
        expectedOrigin,
        expectedRPID: rpId,
        requireUserVerification: true,
        response,
      });
      if (
        !result.verified ||
        result.newCounter === undefined ||
        !Number.isSafeInteger(result.newCounter) ||
        result.newCounter < credential.counter
      ) {
        return fail();
      }

      await options.credentialStore.saveCredential({
        ...credential,
        counter: result.newCounter,
        lastUsedAt: now(),
      });
      return {
        credentialId,
        rpId,
        subject,
        userVerified: true,
        verifierOrigin: expectedOrigin,
      };
    },
  };
};

export const createWebAuthnAgentExchangeMandateApprovalProvider = (
  options: WebAuthnAgentExchangeMandateApprovalProviderOptions,
): AgentExchangeMandateApprovalProvider => {
  const allowInsecureLocalhost = options.allowInsecureLocalhost === true;
  const origin = validatedOrigin(options.origin, allowInsecureLocalhost);
  const expectedOrigin = origin.origin;
  const rpId = options.rpId.toLowerCase();
  assertRpId(origin, rpId, allowInsecureLocalhost);
  const now = options.now ?? Date.now;

  const resolveOwnedCredentials = async (
    draft: AgentExchangeStandingMandateDraft,
    subject: string,
  ) => {
    const userId = await options.resolveUserId({ draft, subject });
    if (typeof userId !== "string" || userId.length === 0) return fail();
    const credentials =
      await options.credentialStore.listCredentialsByUser(userId);
    if (credentials.length === 0 || credentials.length > MAX_CREDENTIALS)
      return fail();
    return { credentials, userId };
  };

  const assertBound = async (input: {
    readonly challenge: string;
    readonly draft: AgentExchangeStandingMandateDraft;
    readonly subject: string;
    readonly verifierOrigin: string;
  }) => {
    if (
      input.verifierOrigin !== expectedOrigin ||
      input.draft.issuer.authority !== expectedOrigin ||
      input.draft.issuer.subject !== input.subject ||
      input.challenge !==
        (await agentExchangeMandateApprovalChallenge(input.draft))
    )
      return fail();
  };

  return {
    begin: async (input) => {
      await assertBound(input);
      const { credentials } = await resolveOwnedCredentials(
        input.draft,
        input.subject,
      );
      const generated = await options.adapter.createAuthenticationOptions({
        allowCredentials: credentials.map(({ credentialId, transports }) => ({
          id: credentialId,
          ...(transports === undefined ? {} : { transports }),
        })),
        challenge: input.challenge,
        rpId,
        userVerification: "required",
      });
      if (generated.challenge !== input.challenge) return fail();
      return { challenge: input.challenge, options: generated.options };
    },
    verify: async (input) => {
      await assertBound(input);
      const { credentials, userId } = await resolveOwnedCredentials(
        input.draft,
        input.subject,
      );
      const credentialId = responseCredentialId(input.response);
      const credential = credentials.find(
        (value) => value.credentialId === credentialId,
      );
      if (credential === undefined || credential.userId !== userId)
        return fail();
      const result = await options.adapter.verifyAuthentication({
        credential: {
          counter: credential.counter,
          credentialId: credential.credentialId,
          publicKey: credential.publicKey,
          ...(credential.transports === undefined
            ? {}
            : { transports: credential.transports }),
        },
        expectedChallenge: input.challenge,
        expectedOrigin,
        expectedRPID: rpId,
        requireUserVerification: true,
        response: input.response,
      });
      if (
        !result.verified ||
        result.newCounter === undefined ||
        !Number.isSafeInteger(result.newCounter) ||
        result.newCounter < credential.counter
      )
        return fail();
      await options.credentialStore.saveCredential({
        ...credential,
        counter: result.newCounter,
        lastUsedAt: now(),
      });
      return {
        credentialId,
        rpId,
        subject: input.subject,
        userVerified: true,
        verifierOrigin: expectedOrigin,
      };
    },
  };
};
