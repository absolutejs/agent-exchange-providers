import type {
  AgentExchangeDestinationAdapter,
  AgentExchangeDestinationInput,
} from "@absolutejs/agent-exchange-destinations";

const DEFAULT_TIMEOUT_MS = 10_000;
const MAX_AUTHORIZATION_BYTES = 8 * 1024;
const MAX_FIELD_BYTES = 128;
const MAX_TIMEOUT_MS = 30_000;
const encoder = new TextEncoder();

export type AgentExchangeHttpAuthorizationResolver = (
  input: Readonly<{
    exchangeId: string;
    tenantId: string;
  }>,
) => Promise<string> | string;

export type AgentExchangeHttpFetch = (
  input: RequestInfo | URL,
  init?: RequestInit,
) => Promise<Response>;

export type AgentExchangeHttpDestinationOptions = {
  readonly authorization?: AgentExchangeHttpAuthorizationResolver;
  readonly challengeField?: string;
  readonly endpoint: string;
  readonly fetcher?: AgentExchangeHttpFetch;
  readonly id: string;
  readonly operations: readonly string[];
  readonly reference?: string;
  readonly secretField?: string;
  readonly timeoutMs?: number;
};

const validField = (value: string): boolean =>
  value.length > 0 &&
  encoder.encode(value).byteLength <= MAX_FIELD_BYTES &&
  /^[A-Za-z][A-Za-z0-9_.-]*$/u.test(value);

const encodePart = (value: string): Uint8Array =>
  encoder.encode(encodeURIComponent(value).replaceAll("%20", "+"));

const concat = (parts: readonly Uint8Array[]): Uint8Array => {
  const output = new Uint8Array(
    parts.reduce((length, part) => length + part.byteLength, 0),
  );
  let offset = 0;
  for (const part of parts) {
    output.set(part, offset);
    offset += part.byteLength;
  }
  return output;
};

const formBody = (
  input: AgentExchangeDestinationInput,
  secretField: string,
  challengeField: string | undefined,
): Uint8Array => {
  if (
    input.plaintext.byteLength !== 6 ||
    input.plaintext.some((byte) => byte < 48 || byte > 57)
  )
    throw new Error("Verification code must be exactly six ASCII digits");
  const parts = [encodePart(secretField), encoder.encode("="), input.plaintext];
  if (challengeField !== undefined) {
    const challengeId = input.request.resource.challengeId;
    if (challengeId === undefined)
      throw new Error("Destination requires a challenge ID");
    parts.push(
      encoder.encode("&"),
      encodePart(challengeField),
      encoder.encode("="),
      encodePart(challengeId),
    );
  }
  return concat(parts);
};

const configuredEndpoint = (value: string): URL => {
  const endpoint = new URL(value);
  if (
    endpoint.protocol !== "https:" ||
    endpoint.username !== "" ||
    endpoint.password !== "" ||
    endpoint.hash !== "" ||
    endpoint.search !== ""
  )
    throw new Error(
      "Destination endpoint must be HTTPS without credentials, query, or fragment",
    );
  return endpoint;
};

export const createAgentExchangeHttpDestination = (
  options: AgentExchangeHttpDestinationOptions,
): AgentExchangeDestinationAdapter => {
  const endpoint = configuredEndpoint(options.endpoint);
  const secretField = options.secretField ?? "code";
  if (
    !validField(secretField) ||
    (options.challengeField !== undefined &&
      !validField(options.challengeField)) ||
    (options.reference !== undefined &&
      (options.reference.length === 0 || options.reference.length > 512))
  )
    throw new Error("Invalid fixed HTTP destination configuration");
  const timeoutMs = options.timeoutMs ?? DEFAULT_TIMEOUT_MS;
  if (
    !Number.isSafeInteger(timeoutMs) ||
    timeoutMs < 1 ||
    timeoutMs > MAX_TIMEOUT_MS
  )
    throw new Error("Invalid destination timeout");
  const fetcher = options.fetcher ?? fetch;

  return Object.freeze({
    descriptor: Object.freeze({
      id: options.id,
      operations: Object.freeze([...options.operations]),
      origin: endpoint.origin,
      secretKinds: Object.freeze(["email-one-time-code"]),
    }),
    submit: async (input) => {
      if (input.request.resource.origin !== endpoint.origin)
        throw new Error("Destination origin mismatch");
      const body = formBody(input, secretField, options.challengeField);
      const controller = new AbortController();
      const timer = setTimeout(() => controller.abort(), timeoutMs);
      let authorization = "";
      try {
        const headers = new Headers({
          accept: "application/json",
          "cache-control": "no-store",
          "content-type": "application/x-www-form-urlencoded",
          "x-agent-exchange-id": input.request.exchangeId,
          "x-idempotency-key":
            input.request.idempotencyKey ?? input.request.exchangeId,
        });
        if (options.authorization !== undefined) {
          authorization = await options.authorization({
            exchangeId: input.request.exchangeId,
            tenantId: input.tenantId,
          });
          if (
            authorization.length === 0 ||
            encoder.encode(authorization).byteLength >
              MAX_AUTHORIZATION_BYTES ||
            /[\r\n]/u.test(authorization)
          )
            throw new Error("Invalid destination authorization");
          headers.set("authorization", authorization);
        }
        const response = await fetcher(endpoint, {
          body: body as unknown as BodyInit,
          cache: "no-store",
          credentials: "omit",
          headers,
          method: "POST",
          redirect: "error",
          referrerPolicy: "no-referrer",
          signal: controller.signal,
        });
        if (!response.ok)
          throw new Error("Destination rejected the verification code");
        await response.body?.cancel();
        return Object.freeze({
          reference:
            options.reference ?? `${options.id}:${input.request.exchangeId}`,
          status: "submitted" as const,
        });
      } catch {
        throw new Error("Fixed HTTP destination submission failed");
      } finally {
        clearTimeout(timer);
        authorization = "";
        body.fill(0);
      }
    },
  });
};
