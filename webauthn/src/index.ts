import type {
  AgentExchangeApprovalProvider,
  AgentExchangeRequest,
} from "@absolutejs/agent-exchange";
import type {
  WebAuthnAdapter,
  WebAuthnCredentialStore,
} from "@absolutejs/auth";

const MAX_CREDENTIALS = 20;
const MAX_CREDENTIAL_ID_LENGTH = 2048;

export type WebAuthnAgentExchangeApprovalProviderOptions = {
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

const fail = (): never => {
  throw new Error("WebAuthn approval failed");
};

const validatedOrigin = (value: string): URL => {
  const url = new URL(value);
  if (
    url.protocol !== "https:" ||
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

const assertRpId = (origin: URL, rpId: string): void => {
  const normalized = rpId.toLowerCase();
  if (
    normalized === "" ||
    !normalized.includes(".") ||
    normalized.includes(":") ||
    (origin.hostname !== normalized &&
      !origin.hostname.endsWith(`.${normalized}`))
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
  const origin = validatedOrigin(options.origin);
  const expectedOrigin = origin.origin;
  const rpId = options.rpId.toLowerCase();
  assertRpId(origin, rpId);
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
