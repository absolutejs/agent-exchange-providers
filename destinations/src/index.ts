import {
  containsSensitiveValue,
  type AgentExchangeRequest,
  type SensitiveValueSinkResult,
} from "@absolutejs/agent-exchange";

const MAX_IDENTIFIER_BYTES = 512;
const encoder = new TextEncoder();

export type AgentExchangeDestinationDescriptor = {
  readonly id: string;
  readonly operations: readonly string[];
  readonly origin: string;
  readonly secretKinds: readonly string[];
};

export type AgentExchangeDestinationInput = {
  readonly plaintext: Uint8Array;
  readonly request: AgentExchangeRequest;
  readonly tenantId: string;
};

export type AgentExchangeDestinationAdapter = {
  readonly descriptor: AgentExchangeDestinationDescriptor;
  readonly submit: (
    input: AgentExchangeDestinationInput,
  ) => Promise<SensitiveValueSinkResult> | SensitiveValueSinkResult;
};

export type AgentExchangeDestinationRegistry = {
  readonly submit: (
    input: AgentExchangeDestinationInput,
  ) => Promise<SensitiveValueSinkResult>;
};

const boundedIdentifier = (value: string): boolean =>
  value.trim() === value &&
  value.length > 0 &&
  encoder.encode(value).byteLength <= MAX_IDENTIFIER_BYTES &&
  !/[\u0000-\u001f\u007f]/u.test(value);

const exactHttpsOrigin = (value: string): boolean => {
  try {
    const parsed = new URL(value);
    return (
      parsed.protocol === "https:" &&
      parsed.username === "" &&
      parsed.password === "" &&
      parsed.origin === value &&
      parsed.pathname === "/" &&
      parsed.search === "" &&
      parsed.hash === ""
    );
  } catch {
    return false;
  }
};

const routeKey = (origin: string, operation: string, secretKind: string) =>
  `${origin.length}:${origin}${operation.length}:${operation}${secretKind.length}:${secretKind}`;

const assertDescriptor = (
  descriptor: AgentExchangeDestinationDescriptor,
): void => {
  if (
    !boundedIdentifier(descriptor.id) ||
    !exactHttpsOrigin(descriptor.origin) ||
    descriptor.operations.length === 0 ||
    descriptor.secretKinds.length === 0 ||
    descriptor.operations.some((value) => !boundedIdentifier(value)) ||
    descriptor.secretKinds.some((value) => !boundedIdentifier(value)) ||
    new Set(descriptor.operations).size !== descriptor.operations.length ||
    new Set(descriptor.secretKinds).size !== descriptor.secretKinds.length
  )
    throw new Error("Invalid Agent Exchange destination descriptor");
};

const assertRequest = (input: AgentExchangeDestinationInput): void => {
  const request = input.request;
  if (
    !boundedIdentifier(input.tenantId) ||
    input.plaintext.byteLength === 0 ||
    request.processingMode !== "tool-confined" ||
    request.maximumUses !== 1 ||
    request.assurance.approval !== "webauthn-verifier-bound" ||
    request.assurance.credential !== "token-confined-broker" ||
    request.assurance.execution !== "purpose-bound" ||
    !exactHttpsOrigin(request.resource.origin) ||
    !boundedIdentifier(request.resource.operation) ||
    !boundedIdentifier(request.secretKind)
  )
    throw new Error("Agent Exchange destination rejected the request");
};

export const createAgentExchangeDestinationRegistry = (
  adapters: readonly AgentExchangeDestinationAdapter[],
): AgentExchangeDestinationRegistry => {
  if (adapters.length === 0)
    throw new Error("At least one destination adapter is required");
  const routes = new Map<string, AgentExchangeDestinationAdapter>();
  const ids = new Set<string>();
  for (const adapter of adapters) {
    assertDescriptor(adapter.descriptor);
    if (ids.has(adapter.descriptor.id))
      throw new Error("Destination adapter IDs must be unique");
    ids.add(adapter.descriptor.id);
    for (const operation of adapter.descriptor.operations) {
      for (const secretKind of adapter.descriptor.secretKinds) {
        const key = routeKey(adapter.descriptor.origin, operation, secretKind);
        if (routes.has(key))
          throw new Error("Destination adapter routes must be unambiguous");
        routes.set(key, adapter);
      }
    }
  }

  return Object.freeze({
    submit: async (
      input: AgentExchangeDestinationInput,
    ): Promise<SensitiveValueSinkResult> => {
      assertRequest(input);
      const adapter = routes.get(
        routeKey(
          input.request.resource.origin,
          input.request.resource.operation,
          input.request.secretKind,
        ),
      );
      if (adapter === undefined)
        throw new Error("Agent Exchange destination is unavailable");

      const isolatedPlaintext = Uint8Array.from(input.plaintext);
      try {
        const result = await adapter.submit({
          plaintext: isolatedPlaintext,
          request: input.request,
          tenantId: input.tenantId,
        });
        if (
          result.status !== "submitted" ||
          (result.reference !== undefined &&
            !boundedIdentifier(result.reference)) ||
          containsSensitiveValue(result, isolatedPlaintext)
        )
          throw new Error("Destination adapter returned an unsafe result");
        return Object.freeze(
          result.reference === undefined
            ? { status: "submitted" as const }
            : { reference: result.reference, status: "submitted" as const },
        );
      } catch {
        throw new Error("Agent Exchange destination submission failed");
      } finally {
        isolatedPlaintext.fill(0);
      }
    },
  });
};
