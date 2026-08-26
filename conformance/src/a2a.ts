import type { AgentExchangeRequest } from "@absolutejs/agent-exchange";
import {
  ABSOLUTE_AGENT_EXCHANGE_EXTENSION,
  AGENT_EXCHANGE_REQUEST_MEDIA_TYPE,
  parseA2aAgentExchangeReference,
  toA2aAgentExchangeMessage,
  toA2aAgentExchangeReference,
  type A2aAgentExchangeReference,
} from "@absolutejs/agent-exchange/a2a";

export const AGENT_EXCHANGE_A2A_SKILL_ID = "absolute-agent-exchange" as const;
export const AGENT_EXCHANGE_PREPARATION_MEDIA_TYPE =
  "application/vnd.absolutejs.agent-exchange-preparation+json" as const;
export const AGENT_EXCHANGE_RECEIPT_MEDIA_TYPE =
  "application/vnd.absolutejs.agent-exchange-receipt+json" as const;

const MAXIMUM_BODY_BYTES = 65_536;
const DEFAULT_TIMEOUT_MS = 10_000;

export type AgentExchangeA2aConformanceCheck =
  | "authentication-before-parsing"
  | "credential-separation"
  | "discovery"
  | "negotiation"
  | "prepared-execution"
  | "profile"
  | "replay-convergence"
  | "task-redaction";

export type AgentExchangeA2aConformanceFinding = {
  readonly check: AgentExchangeA2aConformanceCheck;
  readonly detail?: string;
  readonly passed: boolean;
};

export type AgentExchangeA2aConformanceReport = {
  readonly conformant: boolean;
  readonly findings: readonly AgentExchangeA2aConformanceFinding[];
};

export type AgentExchangeA2aConformanceRequestPurpose =
  "credential-separation" | "negotiation" | "prepared-execution";

export type AgentExchangeA2aConformanceTarget = {
  readonly acknowledgeExecution: "sandbox-only";
  readonly additionalSensitiveMarkers?: readonly string[];
  readonly a2aHeaders: (input: {
    readonly method: "POST";
    readonly purpose: "a2a";
    readonly url: string;
  }) => HeadersInit | Promise<HeadersInit>;
  readonly createRequest: (
    purpose: AgentExchangeA2aConformanceRequestPurpose,
  ) => AgentExchangeRequest | Promise<AgentExchangeRequest>;
  readonly fetch?: (
    input: RequestInfo | URL,
    init?: RequestInit,
  ) => Promise<Response>;
  readonly maxResponseBytes?: number;
  readonly origin: string;
  readonly preparationHeaders: (input: {
    readonly method: "POST";
    readonly purpose: "preparation";
    readonly url: string;
  }) => HeadersInit | Promise<HeadersInit>;
  readonly timeoutMs?: number;
};

type Discovery = {
  readonly a2aEndpoint: string;
  readonly card: Record<string, unknown>;
  readonly preparationEndpoint: string;
};

type PreparedExecution = {
  readonly a2aEndpoint: string;
  readonly message: Record<string, unknown>;
  readonly request: AgentExchangeRequest;
  readonly response: Record<string, unknown>;
  readonly task: Record<string, unknown>;
};

const isRecord = (value: unknown): value is Record<string, unknown> =>
  value !== null && typeof value === "object" && !Array.isArray(value);

const secureUrl = (value: unknown): value is string => {
  if (typeof value !== "string") return false;
  try {
    const url = new URL(value);
    const local =
      url.protocol === "http:" &&
      (url.hostname === "localhost" || url.hostname === "127.0.0.1");
    return (
      (url.href === value || url.origin === value) &&
      url.username === "" &&
      url.password === "" &&
      url.hash === "" &&
      url.search === "" &&
      (url.protocol === "https:" || local)
    );
  } catch {
    return false;
  }
};

const requestHeaders = async (
  value: HeadersInit | Promise<HeadersInit>,
  fixed: Record<string, string>,
) => {
  const headers = new Headers(await value);
  for (const [name, content] of Object.entries(fixed))
    headers.set(name, content);
  return headers;
};

const boundedBody = async (response: Response, maximumBytes: number) => {
  const body = await response.arrayBuffer();
  if (body.byteLength === 0 || body.byteLength > maximumBytes)
    throw new Error("response body was not bounded");
  try {
    return JSON.parse(
      new TextDecoder("utf-8", { fatal: true }).decode(body),
    ) as unknown;
  } catch {
    throw new Error("response body was not valid JSON");
  }
};

const fetchRequest = async (
  target: AgentExchangeA2aConformanceTarget,
  request: Request,
) =>
  (target.fetch ?? globalThis.fetch)(
    new Request(request, {
      credentials: "omit",
      redirect: "error",
      referrerPolicy: "no-referrer",
      signal: AbortSignal.timeout(target.timeoutMs ?? DEFAULT_TIMEOUT_MS),
    }),
  );

const sameReference = (
  left: A2aAgentExchangeReference,
  right: A2aAgentExchangeReference,
) =>
  left.actionId === right.actionId &&
  left.assurance.approval === right.assurance.approval &&
  left.assurance.credential === right.assurance.credential &&
  left.assurance.execution === right.assurance.execution &&
  left.exchangeId === right.exchangeId &&
  left.expiresAt === right.expiresAt &&
  left.mandateId === right.mandateId &&
  left.operation === right.operation &&
  left.origin === right.origin &&
  left.processingMode === right.processingMode &&
  left.provider === right.provider &&
  left.purpose === right.purpose &&
  left.recipientAgentId === right.recipientAgentId;

const parseReference = (value: unknown, expectedExchangeId: string) =>
  parseA2aAgentExchangeReference({
    contextId: expectedExchangeId,
    extensions: [ABSOLUTE_AGENT_EXCHANGE_EXTENSION],
    messageId: "conformance-reference-validation",
    metadata: {
      [ABSOLUTE_AGENT_EXCHANGE_EXTENSION]: {
        exchangeId: expectedExchangeId,
      },
    },
    parts: [{ data: value, mediaType: AGENT_EXCHANGE_REQUEST_MEDIA_TYPE }],
    role: "ROLE_USER",
  });

const discover = async (
  target: AgentExchangeA2aConformanceTarget,
): Promise<Discovery> => {
  const origin = new URL(target.origin);
  if (origin.origin !== target.origin || !secureUrl(target.origin))
    throw new Error("target origin was not an exact secure origin");
  const response = await fetchRequest(
    target,
    new Request(`${target.origin}/.well-known/agent-card.json`),
  );
  if (!response.ok) throw new Error("Agent Card discovery failed");
  if (
    response.headers.get("content-type")?.split(";", 1)[0]?.trim() !==
    "application/json"
  )
    throw new Error("Agent Card media type was invalid");
  const value = await boundedBody(
    response,
    target.maxResponseBytes ?? MAXIMUM_BODY_BYTES,
  );
  if (!isRecord(value)) throw new Error("Agent Card was not an object");
  const capabilities = isRecord(value.capabilities)
    ? value.capabilities
    : undefined;
  const extensions = Array.isArray(capabilities?.extensions)
    ? capabilities.extensions
    : [];
  const extension = extensions.find(
    (candidate) =>
      isRecord(candidate) &&
      candidate.uri === ABSOLUTE_AGENT_EXCHANGE_EXTENSION,
  );
  if (!isRecord(extension))
    throw new Error("Agent Exchange extension was not advertised");
  if (
    extensions.filter(
      (candidate) =>
        isRecord(candidate) &&
        candidate.uri === ABSOLUTE_AGENT_EXCHANGE_EXTENSION,
    ).length !== 1
  )
    throw new Error("Agent Exchange extension was advertised ambiguously");
  const params = isRecord(extension.params) ? extension.params : undefined;
  const preparation = isRecord(params?.preparation)
    ? params.preparation
    : undefined;
  if (
    !isRecord(preparation) ||
    Object.keys(preparation).some(
      (key) => !["endpoint", "mediaType", "method"].includes(key),
    ) ||
    preparation.method !== "POST" ||
    preparation.mediaType !== AGENT_EXCHANGE_PREPARATION_MEDIA_TYPE ||
    !secureUrl(preparation.endpoint)
  )
    throw new Error("protected preparation was not advertised");
  const interfaces = Array.isArray(value.supportedInterfaces)
    ? value.supportedInterfaces
    : [];
  const selected = interfaces.find(
    (candidate) =>
      isRecord(candidate) &&
      candidate.protocolBinding === "JSONRPC" &&
      candidate.protocolVersion === "1.0" &&
      secureUrl(candidate.url),
  );
  if (!isRecord(selected) || typeof selected.url !== "string")
    throw new Error("A2A 1.0 JSON-RPC interface was not advertised");
  if (
    new URL(selected.url).origin !== target.origin ||
    new URL(preparation.endpoint).origin !== target.origin
  )
    throw new Error("advertised endpoints were not same-origin");
  return {
    a2aEndpoint: selected.url,
    card: value,
    preparationEndpoint: preparation.endpoint,
  };
};

const assertProfile = (discovery: Discovery) => {
  const skills = Array.isArray(discovery.card.skills)
    ? discovery.card.skills
    : [];
  const skill = skills.find(
    (candidate) =>
      isRecord(candidate) && candidate.id === AGENT_EXCHANGE_A2A_SKILL_ID,
  );
  if (!isRecord(skill))
    throw new Error("Agent Exchange skill was not advertised");
  const inputModes = Array.isArray(skill.inputModes) ? skill.inputModes : [];
  const outputModes = Array.isArray(skill.outputModes) ? skill.outputModes : [];
  if (
    !inputModes.includes(AGENT_EXCHANGE_REQUEST_MEDIA_TYPE) ||
    !outputModes.includes(AGENT_EXCHANGE_RECEIPT_MEDIA_TYPE)
  )
    throw new Error("Agent Exchange skill media types were incomplete");
  if (
    !isRecord(discovery.card.securitySchemes) ||
    !Array.isArray(discovery.card.securityRequirements) ||
    discovery.card.securityRequirements.length === 0
  )
    throw new Error("Agent Exchange authentication was not advertised");
};

const prepare = async (
  target: AgentExchangeA2aConformanceTarget,
  discovery: Discovery,
  request: AgentExchangeRequest,
  headers: HeadersInit | Promise<HeadersInit>,
) => {
  const response = await fetchRequest(
    target,
    new Request(discovery.preparationEndpoint, {
      body: JSON.stringify({ request }),
      headers: await requestHeaders(headers, {
        accept: AGENT_EXCHANGE_PREPARATION_MEDIA_TYPE,
        "content-type": AGENT_EXCHANGE_PREPARATION_MEDIA_TYPE,
      }),
      method: "POST",
    }),
  );
  if (!response.ok) throw new Error("protected preparation failed");
  if (
    response.headers.get("content-type")?.split(";", 1)[0]?.trim() !==
      AGENT_EXCHANGE_PREPARATION_MEDIA_TYPE ||
    !response.headers
      .get("cache-control")
      ?.split(",")
      .some((value) => value.trim().toLowerCase() === "no-store")
  )
    throw new Error("preparation response protections were incomplete");
  const value = await boundedBody(
    response,
    target.maxResponseBytes ?? MAXIMUM_BODY_BYTES,
  );
  if (!isRecord(value) || Object.keys(value).some((key) => key !== "reference"))
    throw new Error("preparation response shape was rejected");
  const expected = toA2aAgentExchangeReference(request);
  const actual = parseReference(value.reference, request.exchangeId);
  if (!sameReference(actual, expected))
    throw new Error("prepared reference did not exactly match the request");
  return actual;
};

const a2aCall = async (
  target: AgentExchangeA2aConformanceTarget,
  endpoint: string,
  method: "GetTask" | "SendMessage",
  params: unknown,
  headers: HeadersInit | Promise<HeadersInit>,
  activateExtension = true,
) => {
  const response = await fetchRequest(
    target,
    new Request(endpoint, {
      body: JSON.stringify({
        id: `conformance-${crypto.randomUUID()}`,
        jsonrpc: "2.0",
        method,
        params,
      }),
      headers: await requestHeaders(headers, {
        ...(activateExtension
          ? { "a2a-extensions": ABSOLUTE_AGENT_EXCHANGE_EXTENSION }
          : {}),
        "a2a-version": "1.0",
        "content-type": "application/json",
      }),
      method: "POST",
    }),
  );
  const value = await boundedBody(
    response,
    target.maxResponseBytes ?? MAXIMUM_BODY_BYTES,
  ).catch(() => undefined);
  return { response, value };
};

const assertRejected = (response: Response, value: unknown) => {
  if (!response.ok) return;
  if (isRecord(value) && isRecord(value.error)) return;
  throw new Error("request was not rejected");
};

const markers = (
  request: AgentExchangeRequest,
  additional: readonly string[] = [],
) =>
  [
    request.idempotencyKey,
    request.nonce,
    request.resource.accountRef,
    request.resource.challengeId,
    ...additional,
  ].filter(
    (value): value is string => typeof value === "string" && value !== "",
  );

const markerRepresentations = (marker: string) => {
  const bytes = new TextEncoder().encode(marker);
  let binary = "";
  let hexadecimal = "";
  for (const byte of bytes) {
    binary += String.fromCharCode(byte);
    hexadecimal += byte.toString(16).padStart(2, "0");
  }
  const base64 = btoa(binary);
  return [
    marker,
    hexadecimal,
    hexadecimal.toUpperCase(),
    base64,
    base64.replaceAll("+", "-").replaceAll("/", "_").replace(/=+$/u, ""),
  ];
};

const assertRedacted = (
  value: unknown,
  protectedMarkers: readonly string[],
) => {
  const serialized = JSON.stringify(value);
  if (
    protectedMarkers
      .flatMap(markerRepresentations)
      .some((marker) => serialized.includes(marker))
  )
    throw new Error("protected request data crossed the A2A boundary");
};

const executePrepared = async (
  target: AgentExchangeA2aConformanceTarget,
  discovery: Discovery,
): Promise<PreparedExecution> => {
  const request = await target.createRequest("prepared-execution");
  await prepare(
    target,
    discovery,
    request,
    target.preparationHeaders({
      method: "POST",
      purpose: "preparation",
      url: discovery.preparationEndpoint,
    }),
  );
  const message = toA2aAgentExchangeMessage(request) as Record<string, unknown>;
  assertRedacted(message, markers(request, target.additionalSensitiveMarkers));
  const { response, value } = await a2aCall(
    target,
    discovery.a2aEndpoint,
    "SendMessage",
    { message },
    target.a2aHeaders({
      method: "POST",
      purpose: "a2a",
      url: discovery.a2aEndpoint,
    }),
  );
  if (!response.ok || !isRecord(value) || !isRecord(value.result))
    throw new Error("prepared A2A execution failed");
  if (
    response.headers.get("content-type")?.split(";", 1)[0]?.trim() !==
    "application/json"
  )
    throw new Error("prepared A2A response media type was invalid");
  const task = isRecord(value.result.task) ? value.result.task : undefined;
  if (!task || task.contextId !== request.exchangeId)
    throw new Error("prepared A2A task was invalid");
  const status = isRecord(task.status) ? task.status : undefined;
  if (status?.state !== "TASK_STATE_COMPLETED")
    throw new Error("prepared A2A task did not complete");
  assertRedacted(value, markers(request, target.additionalSensitiveMarkers));
  return {
    a2aEndpoint: discovery.a2aEndpoint,
    message,
    request,
    response: value,
    task,
  };
};

const finding = async (
  check: AgentExchangeA2aConformanceCheck,
  evaluate: () => Promise<void> | void,
): Promise<AgentExchangeA2aConformanceFinding> => {
  try {
    await evaluate();
    return Object.freeze({ check, passed: true });
  } catch (error) {
    return Object.freeze({
      check,
      detail:
        error instanceof Error ? error.message : "conformance check failed",
      passed: false,
    });
  }
};

export const evaluateAgentExchangeA2aConformance = async (
  target: AgentExchangeA2aConformanceTarget,
): Promise<AgentExchangeA2aConformanceReport> => {
  if (target.acknowledgeExecution !== "sandbox-only")
    throw new Error("A2A conformance may run only against a sandbox target");
  let discovery: Discovery | undefined;
  let execution: PreparedExecution | undefined;
  const findings: AgentExchangeA2aConformanceFinding[] = [];

  findings.push(
    await finding("discovery", async () => {
      discovery = await discover(target);
    }),
  );
  findings.push(
    await finding("profile", () => {
      if (!discovery) throw new Error("discovery prerequisite failed");
      assertProfile(discovery);
    }),
  );
  findings.push(
    await finding("authentication-before-parsing", async () => {
      if (!discovery) throw new Error("discovery prerequisite failed");
      const response = await fetchRequest(
        target,
        new Request(discovery.a2aEndpoint, {
          body: "{",
          headers: {
            "a2a-version": "1.0",
            "content-type": "application/json",
          },
          method: "POST",
        }),
      );
      if (response.status !== 401 && response.status !== 403)
        throw new Error("A2A parsed an unauthenticated request");
      const preparation = await fetchRequest(
        target,
        new Request(discovery.preparationEndpoint, {
          body: "{",
          headers: {
            "content-type": AGENT_EXCHANGE_PREPARATION_MEDIA_TYPE,
          },
          method: "POST",
        }),
      );
      if (preparation.status !== 401 && preparation.status !== 403)
        throw new Error("preparation parsed an unauthenticated request");
    }),
  );
  findings.push(
    await finding("credential-separation", async () => {
      if (!discovery) throw new Error("discovery prerequisite failed");
      const request = await target.createRequest("credential-separation");
      const wrongPreparation = await fetchRequest(
        target,
        new Request(discovery.preparationEndpoint, {
          body: JSON.stringify({ request }),
          headers: await requestHeaders(
            target.a2aHeaders({
              method: "POST",
              purpose: "a2a",
              url: discovery.a2aEndpoint,
            }),
            { "content-type": AGENT_EXCHANGE_PREPARATION_MEDIA_TYPE },
          ),
          method: "POST",
        }),
      );
      if (wrongPreparation.status !== 401 && wrongPreparation.status !== 403)
        throw new Error("preparation accepted the A2A credential");
      const wrongA2a = await fetchRequest(
        target,
        new Request(discovery.a2aEndpoint, {
          body: "{",
          headers: await requestHeaders(
            target.preparationHeaders({
              method: "POST",
              purpose: "preparation",
              url: discovery.preparationEndpoint,
            }),
            { "a2a-version": "1.0", "content-type": "application/json" },
          ),
          method: "POST",
        }),
      );
      if (wrongA2a.status !== 401 && wrongA2a.status !== 403)
        throw new Error("A2A accepted the preparation credential");
    }),
  );
  findings.push(
    await finding("negotiation", async () => {
      if (!discovery) throw new Error("discovery prerequisite failed");
      const request = await target.createRequest("negotiation");
      await prepare(
        target,
        discovery,
        request,
        target.preparationHeaders({
          method: "POST",
          purpose: "preparation",
          url: discovery.preparationEndpoint,
        }),
      );
      const result = await a2aCall(
        target,
        discovery.a2aEndpoint,
        "SendMessage",
        { message: toA2aAgentExchangeMessage(request) },
        target.a2aHeaders({
          method: "POST",
          purpose: "a2a",
          url: discovery.a2aEndpoint,
        }),
        false,
      );
      assertRejected(result.response, result.value);
    }),
  );
  findings.push(
    await finding("prepared-execution", async () => {
      if (!discovery) throw new Error("discovery prerequisite failed");
      execution = await executePrepared(target, discovery);
    }),
  );
  findings.push(
    await finding("task-redaction", async () => {
      if (!execution) throw new Error("execution prerequisite failed");
      const protectedMarkers = markers(
        execution.request,
        target.additionalSensitiveMarkers,
      );
      const taskId = execution.task.id;
      if (typeof taskId !== "string" || taskId.length === 0)
        throw new Error("completed task did not have an identifier");
      const result = await a2aCall(
        target,
        execution.a2aEndpoint,
        "GetTask",
        { id: taskId },
        target.a2aHeaders({
          method: "POST",
          purpose: "a2a",
          url: execution.a2aEndpoint,
        }),
      );
      if (!result.response.ok || !isRecord(result.value))
        throw new Error("completed task could not be retrieved");
      assertRedacted(result.value, protectedMarkers);
    }),
  );
  findings.push(
    await finding("replay-convergence", async () => {
      if (!execution) throw new Error("execution prerequisite failed");
      const result = await a2aCall(
        target,
        execution.a2aEndpoint,
        "SendMessage",
        { message: execution.message },
        target.a2aHeaders({
          method: "POST",
          purpose: "a2a",
          url: execution.a2aEndpoint,
        }),
      );
      if (!result.response.ok || !isRecord(result.value)) return;
      if (isRecord(result.value.error)) return;
      const task = isRecord(result.value.result)
        ? result.value.result.task
        : undefined;
      if (!isRecord(task) || task.id !== execution.task.id)
        throw new Error("replayed task created a different successful result");
      assertRedacted(
        result.value,
        markers(execution.request, target.additionalSensitiveMarkers),
      );
    }),
  );

  return Object.freeze({
    conformant: findings.every((candidate) => candidate.passed),
    findings: Object.freeze(findings),
  });
};

export const assertAgentExchangeA2aConformance = async (
  target: AgentExchangeA2aConformanceTarget,
) => {
  const report = await evaluateAgentExchangeA2aConformance(target);
  if (!report.conformant)
    throw new Error(
      `Agent Exchange A2A conformance failed: ${report.findings
        .filter((candidate) => !candidate.passed)
        .map((candidate) => candidate.check)
        .join(", ")}`,
    );
  return report;
};
