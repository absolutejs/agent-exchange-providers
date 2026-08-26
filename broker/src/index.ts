import {
  containsSensitiveValue,
  type AgentExchangeRequest,
  type SensitiveValueSinkResult,
} from "@absolutejs/agent-exchange";

const MAX_IDENTIFIER_BYTES = 512;

export type TokenConfinedBrokerClaim = {
  readonly exchangeId: string;
  readonly expiresAt: number;
  readonly provider: string;
  readonly tenantId: string;
};

export type TokenConfinedBrokerClaimResult =
  "claimed" | "completed" | "conflict" | "revoked";

export type TokenConfinedBrokerStore = {
  readonly claim: (
    claim: TokenConfinedBrokerClaim,
  ) => Promise<TokenConfinedBrokerClaimResult>;
  readonly complete: (input: {
    readonly exchangeId: string;
    readonly reference?: string;
    readonly tenantId: string;
  }) => Promise<boolean>;
  readonly fail: (input: {
    readonly exchangeId: string;
    readonly tenantId: string;
  }) => Promise<void>;
  readonly revoke: (input: {
    readonly exchangeId: string;
    readonly tenantId: string;
  }) => Promise<boolean>;
};

export type TokenConfinedCredential = {
  readonly accessToken: string;
  readonly expiresAt?: number;
};

export type TokenConfinedCredentialResolver = {
  readonly resolve: (input: {
    readonly accountRef: string;
    readonly exchangeId: string;
    readonly provider: string;
    readonly subject: string;
    readonly tenantId: string;
  }) => Promise<TokenConfinedCredential>;
};

export type TokenConfinedProviderExecutor = {
  readonly execute: (input: {
    readonly accessToken: string;
    readonly request: AgentExchangeRequest;
    readonly tenantId: string;
  }) => Promise<SensitiveValueSinkResult>;
};

export type TokenConfinedBrokerReceipt = {
  readonly assurance: AgentExchangeRequest["assurance"];
  readonly brokerMode: "token-confined-broker";
  readonly completedAt: number;
  readonly exchangeId: string;
  readonly maximumUses: 1;
  readonly modelObservedSecret: false;
  readonly processingMode: "tool-confined";
  readonly provider: string;
  readonly reference?: string;
  readonly status: "submitted";
  readonly tenantId: string;
};

const validIdentifier = (value: string): boolean =>
  value.trim().length > 0 &&
  new TextEncoder().encode(value).byteLength <= MAX_IDENTIFIER_BYTES;

const assertRequest = (
  request: AgentExchangeRequest,
  tenantId: string,
  now: number,
): void => {
  if (
    !validIdentifier(tenantId) ||
    request.assurance.approval !== "webauthn-verifier-bound" ||
    request.assurance.credential !== "token-confined-broker" ||
    request.assurance.execution !== "purpose-bound" ||
    request.processingMode !== "tool-confined" ||
    request.maximumUses !== 1 ||
    request.expiresAt <= now ||
    !validIdentifier(request.exchangeId) ||
    !validIdentifier(request.requester.subject) ||
    !validIdentifier(request.resource.accountRef) ||
    !validIdentifier(request.resource.operation) ||
    !validIdentifier(request.resource.provider)
  )
    throw new Error("Token-confined broker rejected the request");
};

export const createTokenConfinedBroker = (options: {
  readonly credentials: TokenConfinedCredentialResolver;
  readonly now?: () => number;
  readonly providers: Readonly<Record<string, TokenConfinedProviderExecutor>>;
  readonly store: TokenConfinedBrokerStore;
}) => {
  const now = options.now ?? Date.now;

  return Object.freeze({
    execute: async (input: {
      readonly request: AgentExchangeRequest;
      readonly tenantId: string;
    }): Promise<TokenConfinedBrokerReceipt> => {
      const startedAt = now();
      assertRequest(input.request, input.tenantId, startedAt);
      const provider = options.providers[input.request.resource.provider];
      if (provider === undefined)
        throw new Error("Token-confined broker rejected the request");
      const claimed = await options.store.claim({
        exchangeId: input.request.exchangeId,
        expiresAt: input.request.expiresAt,
        provider: input.request.resource.provider,
        tenantId: input.tenantId,
      });
      if (claimed !== "claimed")
        throw new Error("Token-confined broker rejected the request");

      let token = "";
      try {
        const credential = await options.credentials.resolve({
          accountRef: input.request.resource.accountRef,
          exchangeId: input.request.exchangeId,
          provider: input.request.resource.provider,
          subject: input.request.requester.subject,
          tenantId: input.tenantId,
        });
        token = credential.accessToken;
        if (
          token.length === 0 ||
          (credential.expiresAt !== undefined && credential.expiresAt <= now())
        )
          throw new Error("credential unavailable");
        const submitted = await provider.execute({
          accessToken: token,
          request: input.request,
          tenantId: input.tenantId,
        });
        if (
          submitted.status !== "submitted" ||
          containsSensitiveValue(submitted, new TextEncoder().encode(token))
        )
          throw new Error("unsafe provider result");
        const completedAt = now();
        if (completedAt >= input.request.expiresAt)
          throw new Error("request expired");
        const receipt: TokenConfinedBrokerReceipt = Object.freeze({
          assurance: input.request.assurance,
          brokerMode: "token-confined-broker",
          completedAt,
          exchangeId: input.request.exchangeId,
          maximumUses: 1,
          modelObservedSecret: false,
          processingMode: "tool-confined",
          provider: input.request.resource.provider,
          ...(submitted.reference === undefined
            ? {}
            : { reference: submitted.reference }),
          status: "submitted",
          tenantId: input.tenantId,
        });
        if (
          !(await options.store.complete({
            exchangeId: input.request.exchangeId,
            ...(receipt.reference === undefined
              ? {}
              : { reference: receipt.reference }),
            tenantId: input.tenantId,
          }))
        )
          throw new Error("completion conflict");
        return receipt;
      } catch {
        await options.store.fail({
          exchangeId: input.request.exchangeId,
          tenantId: input.tenantId,
        });
        throw new Error("Token-confined broker operation failed");
      } finally {
        token = "";
      }
    },
  });
};

export const createMemoryTokenConfinedBrokerStore =
  (): TokenConfinedBrokerStore => {
    const records = new Map<
      string,
      TokenConfinedBrokerClaim & {
        reference?: string;
        status: "claimed" | "completed" | "failed" | "revoked";
      }
    >();
    const key = (tenantId: string, exchangeId: string) =>
      `${tenantId.length}:${tenantId}:${exchangeId}`;

    return Object.freeze({
      claim: async (claim) => {
        const recordKey = key(claim.tenantId, claim.exchangeId);
        const existing = records.get(recordKey);
        if (existing !== undefined)
          return existing.status === "completed"
            ? "completed"
            : existing.status === "revoked"
              ? "revoked"
              : "conflict";
        records.set(recordKey, { ...claim, status: "claimed" });
        return "claimed";
      },
      complete: async ({ exchangeId, reference, tenantId }) => {
        const recordKey = key(tenantId, exchangeId);
        const current = records.get(recordKey);
        if (current?.status !== "claimed") return false;
        records.set(recordKey, {
          ...current,
          ...(reference === undefined ? {} : { reference }),
          status: "completed",
        });
        return true;
      },
      fail: async ({ exchangeId, tenantId }) => {
        const recordKey = key(tenantId, exchangeId);
        const current = records.get(recordKey);
        if (current?.status === "claimed")
          records.set(recordKey, { ...current, status: "failed" });
      },
      revoke: async ({ exchangeId, tenantId }) => {
        const recordKey = key(tenantId, exchangeId);
        const current = records.get(recordKey);
        if (current === undefined || current.status === "completed")
          return false;
        records.set(recordKey, { ...current, status: "revoked" });
        return true;
      },
    });
  };
