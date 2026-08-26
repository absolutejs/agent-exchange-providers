import {
  createA2aClient,
  createA2aHandler,
  discoverA2aAgent,
  type A2aAgentCard,
  type A2aAuthResult,
  type A2aFetch,
  type A2aRequestContext,
  type A2aTask,
  type A2aTaskStore,
} from "@absolutejs/a2a";
import {
  AGENT_EXCHANGE_REQUEST_MEDIA_TYPE,
  ABSOLUTE_AGENT_EXCHANGE_EXTENSION,
  type A2aAgentExchangeReference,
  parseA2aAgentExchangeReference,
  toA2aAgentExchangeMessage,
  toA2aAgentExchangeReference,
  withAgentExchangeExtension,
} from "@absolutejs/agent-exchange/a2a";
import type { AgentExchangeRequest } from "@absolutejs/agent-exchange";

export const AGENT_EXCHANGE_RECEIPT_MEDIA_TYPE =
  "application/vnd.absolutejs.agent-exchange-receipt+json" as const;
export const AGENT_EXCHANGE_A2A_SKILL_ID = "absolute-agent-exchange" as const;
export const AGENT_EXCHANGE_PREPARATION_MEDIA_TYPE =
  "application/vnd.absolutejs.agent-exchange-preparation+json" as const;

const MAX_IDENTIFIER_BYTES = 512;
const MAX_REFERENCE_BYTES = 2_048;
const encoder = new TextEncoder();

export type AgentExchangeA2aReceipt = {
  readonly completedAt: number;
  readonly exchangeId: string;
  readonly mandateId?: string;
  readonly modelObservedSecret: false;
  readonly processingMode: "tool-confined";
  readonly reference?: string;
  readonly status: "submitted";
  readonly usesRemaining?: number;
};

export type AgentExchangeA2aExecutionContext<Caller> = {
  readonly caller: Caller;
  readonly reference: A2aAgentExchangeReference;
  readonly request: Request;
};

export type AgentExchangeA2aServerOptions<Caller> = {
  readonly agentCard: A2aAgentCard;
  readonly authorize: (
    request: Request,
  ) => Promise<A2aAuthResult<Caller>> | A2aAuthResult<Caller>;
  readonly execute: (
    context: AgentExchangeA2aExecutionContext<Caller>,
  ) => Promise<AgentExchangeA2aReceipt> | AgentExchangeA2aReceipt;
  readonly maxRequestBytes?: number;
  readonly path?: string;
  readonly preparationEndpoint?: string;
  readonly taskStore: A2aTaskStore;
};

export type AgentExchangeA2aClient = {
  readonly agentCard: A2aAgentCard;
  readonly send: (
    request: AgentExchangeRequest,
  ) => Promise<AgentExchangeA2aReceipt>;
};

export type AgentExchangeA2aPreparationContext = {
  readonly agentCard: A2aAgentCard;
  readonly reference: A2aAgentExchangeReference;
};

export type AgentExchangeA2aPrepare = (
  request: AgentExchangeRequest,
  context: AgentExchangeA2aPreparationContext,
) => Promise<unknown> | unknown;

export type AgentExchangeA2aProfileOptions = {
  readonly preparationEndpoint?: string;
};

const isRecord = (value: unknown): value is Record<string, unknown> =>
  value !== null && typeof value === "object" && !Array.isArray(value);

const bounded = (value: unknown, maximumBytes: number): value is string =>
  typeof value === "string" &&
  value.trim().length > 0 &&
  encoder.encode(value).byteLength <= maximumBytes;

const secureUrl = (value: unknown): value is string => {
  if (typeof value !== "string") return false;
  try {
    const url = new URL(value);
    const local =
      url.protocol === "http:" &&
      (url.hostname === "localhost" || url.hostname === "127.0.0.1");
    return (
      url.href === value &&
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

const parseReceipt = (value: unknown): AgentExchangeA2aReceipt => {
  const allowed = new Set([
    "completedAt",
    "exchangeId",
    "mandateId",
    "modelObservedSecret",
    "processingMode",
    "reference",
    "status",
    "usesRemaining",
  ]);
  if (
    !isRecord(value) ||
    Object.keys(value).some((key) => !allowed.has(key)) ||
    !Number.isSafeInteger(value.completedAt) ||
    (value.completedAt as number) <= 0 ||
    !bounded(value.exchangeId, MAX_IDENTIFIER_BYTES) ||
    (value.mandateId !== undefined &&
      !bounded(value.mandateId, MAX_IDENTIFIER_BYTES)) ||
    value.modelObservedSecret !== false ||
    value.processingMode !== "tool-confined" ||
    (value.reference !== undefined &&
      !bounded(value.reference, MAX_REFERENCE_BYTES)) ||
    value.status !== "submitted" ||
    (value.usesRemaining !== undefined &&
      (typeof value.usesRemaining !== "number" ||
        !Number.isSafeInteger(value.usesRemaining) ||
        value.usesRemaining < 0))
  )
    throw new Error("Agent Exchange A2A receipt was rejected");
  return value as AgentExchangeA2aReceipt;
};

const receiptFromTask = (
  task: A2aTask,
  request: AgentExchangeRequest,
): AgentExchangeA2aReceipt => {
  const part = task.artifacts
    ?.flatMap((artifact) => artifact.parts)
    .find(
      (candidate) =>
        "data" in candidate &&
        candidate.mediaType === AGENT_EXCHANGE_RECEIPT_MEDIA_TYPE,
    );
  const receipt = parseReceipt(
    part !== undefined && "data" in part ? part.data : undefined,
  );
  if (
    task.status.state !== "TASK_STATE_COMPLETED" ||
    task.contextId !== request.exchangeId ||
    receipt.exchangeId !== request.exchangeId ||
    receipt.mandateId !== request.mandateId
  )
    throw new Error("Agent Exchange A2A task was rejected");
  return receipt;
};

const assertCard = (card: A2aAgentCard): A2aAgentCard => {
  const extension = card.capabilities.extensions?.find(
    (candidate) => candidate.uri === ABSOLUTE_AGENT_EXCHANGE_EXTENSION,
  );
  if (extension === undefined)
    throw new Error(
      "Agent does not advertise the Agent Exchange A2A extension",
    );
  return card;
};

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

const parsePreparedReference = (
  value: unknown,
  expected: A2aAgentExchangeReference,
) => {
  const parsed = parseA2aAgentExchangeReference({
    contextId: expected.exchangeId,
    extensions: [ABSOLUTE_AGENT_EXCHANGE_EXTENSION],
    messageId: "preparation-validation",
    metadata: {
      [ABSOLUTE_AGENT_EXCHANGE_EXTENSION]: {
        exchangeId: expected.exchangeId,
      },
    },
    parts: [
      {
        data: value,
        mediaType: AGENT_EXCHANGE_REQUEST_MEDIA_TYPE,
      },
    ],
    role: "ROLE_USER",
  });
  if (!sameReference(parsed, expected))
    throw new Error("Agent Exchange A2A preparation was rejected");
  return parsed;
};

const preparationEndpoint = (card: A2aAgentCard) => {
  const extension = card.capabilities.extensions?.find(
    (candidate) => candidate.uri === ABSOLUTE_AGENT_EXCHANGE_EXTENSION,
  );
  const params = isRecord(extension?.params) ? extension.params : undefined;
  const preparation = isRecord(params?.preparation)
    ? params.preparation
    : undefined;
  if (preparation === undefined) return undefined;
  const endpoint = preparation.endpoint;
  if (
    Object.keys(preparation).some(
      (key) => !["endpoint", "mediaType", "method"].includes(key),
    ) ||
    !secureUrl(endpoint) ||
    preparation.mediaType !== AGENT_EXCHANGE_PREPARATION_MEDIA_TYPE ||
    preparation.method !== "POST" ||
    !card.supportedInterfaces.some(
      (entry) => new URL(entry.url).origin === new URL(endpoint).origin,
    )
  )
    throw new Error("Agent Exchange A2A preparation profile was rejected");
  return endpoint;
};

const responseBody = async (response: Response, maximumBytes: number) => {
  const body = await response.arrayBuffer();
  if (body.byteLength > maximumBytes)
    throw new Error("Agent Exchange A2A preparation response was rejected");
  try {
    return JSON.parse(new TextDecoder().decode(body)) as unknown;
  } catch {
    throw new Error("Agent Exchange A2A preparation response was rejected");
  }
};

const headersFrom = async (
  value: HeadersInit | (() => HeadersInit | Promise<HeadersInit>) | undefined,
) => new Headers(typeof value === "function" ? await value() : value);

export const toAgentExchangeA2aTask = (input: {
  readonly message: Parameters<typeof parseA2aAgentExchangeReference>[0];
  readonly receipt: AgentExchangeA2aReceipt;
  readonly reference: A2aAgentExchangeReference;
}): A2aTask => {
  const receipt = parseReceipt(input.receipt);
  if (
    receipt.exchangeId !== input.reference.exchangeId ||
    receipt.mandateId !== input.reference.mandateId
  )
    throw new Error("Agent Exchange A2A execution was rejected");
  return {
    artifacts: [
      {
        artifactId: `receipt_${input.reference.exchangeId}`,
        name: "Redacted Agent Exchange receipt",
        parts: [
          { data: receipt, mediaType: AGENT_EXCHANGE_RECEIPT_MEDIA_TYPE },
        ],
      },
    ],
    contextId: input.reference.exchangeId,
    history: [input.message],
    id: input.reference.exchangeId,
    metadata: {
      [ABSOLUTE_AGENT_EXCHANGE_EXTENSION]: {
        exchangeId: input.reference.exchangeId,
      },
    },
    status: {
      state: "TASK_STATE_COMPLETED",
      timestamp: new Date(receipt.completedAt).toISOString(),
    },
  };
};

export const withAgentExchangeA2aProfile = (
  card: A2aAgentCard,
  options: AgentExchangeA2aProfileOptions = {},
): A2aAgentCard => {
  const extended = withAgentExchangeExtension(card);
  const endpoint = options.preparationEndpoint;
  const extensions = extended.capabilities.extensions?.map((extension) =>
    extension.uri === ABSOLUTE_AGENT_EXCHANGE_EXTENSION &&
    endpoint !== undefined
      ? {
          ...extension,
          params: {
            preparation: {
              endpoint,
              mediaType: AGENT_EXCHANGE_PREPARATION_MEDIA_TYPE,
              method: "POST",
            },
          },
        }
      : extension,
  );
  if (
    endpoint !== undefined &&
    (!secureUrl(endpoint) ||
      !card.supportedInterfaces.some(
        (entry) => new URL(entry.url).origin === new URL(endpoint).origin,
      ))
  )
    throw new Error("Agent Exchange A2A preparation endpoint was rejected");
  return {
    ...extended,
    capabilities: { ...extended.capabilities, extensions, streaming: false },
    defaultInputModes: [
      ...new Set([
        ...extended.defaultInputModes,
        "application/vnd.absolutejs.agent-exchange-reference+json",
      ]),
    ],
    defaultOutputModes: [
      ...new Set([
        ...extended.defaultOutputModes,
        AGENT_EXCHANGE_RECEIPT_MEDIA_TYPE,
      ]),
    ],
    skills: [
      ...extended.skills.filter(
        (skill) => skill.id !== AGENT_EXCHANGE_A2A_SKILL_ID,
      ),
      {
        description:
          "Execute an opaque, purpose-bound Agent Exchange reference without exposing protected values to either model.",
        id: AGENT_EXCHANGE_A2A_SKILL_ID,
        inputModes: [
          "application/vnd.absolutejs.agent-exchange-reference+json",
        ],
        name: "Agent Exchange",
        outputModes: [AGENT_EXCHANGE_RECEIPT_MEDIA_TYPE],
        tags: ["agent-exchange", "security", "tool-confined"],
      },
    ],
  };
};

export const createAgentExchangeA2aHandler = <Caller>(
  options: AgentExchangeA2aServerOptions<Caller>,
) => {
  const card = withAgentExchangeA2aProfile(options.agentCard, {
    preparationEndpoint: options.preparationEndpoint,
  });
  return createA2aHandler({
    agentCard: card,
    authorize: options.authorize,
    maxRequestBytes: options.maxRequestBytes,
    path: options.path,
    sendMessage: async ({ message }, context: A2aRequestContext<Caller>) => {
      const reference = parseA2aAgentExchangeReference(message);
      const receipt = parseReceipt(
        await options.execute({
          caller: context.caller,
          reference,
          request: context.request,
        }),
      );
      return { task: toAgentExchangeA2aTask({ message, receipt, reference }) };
    },
    taskStore: options.taskStore,
  });
};

export const createAgentExchangeA2aClient = (options: {
  readonly agentCard: A2aAgentCard;
  readonly fetch?: A2aFetch;
  readonly headers?: HeadersInit | (() => HeadersInit | Promise<HeadersInit>);
  readonly maxResponseBytes?: number;
  readonly preparationHeaders?:
    HeadersInit | (() => HeadersInit | Promise<HeadersInit>);
  readonly prepare?: AgentExchangeA2aPrepare;
  readonly timeoutMs?: number;
}): AgentExchangeA2aClient => {
  const agentCard = assertCard(options.agentCard);
  const client = createA2aClient({
    agentCard,
    extensions: [ABSOLUTE_AGENT_EXCHANGE_EXTENSION],
    fetch: options.fetch,
    headers: options.headers,
    maxResponseBytes: options.maxResponseBytes,
    timeoutMs: options.timeoutMs,
  });
  return Object.freeze({
    agentCard,
    send: async (request: AgentExchangeRequest) => {
      const expectedReference = toA2aAgentExchangeReference(request);
      const endpoint = preparationEndpoint(agentCard);
      if (options.prepare) {
        parsePreparedReference(
          await options.prepare(request, {
            agentCard,
            reference: expectedReference,
          }),
          expectedReference,
        );
      } else if (endpoint) {
        const headers = await headersFrom(options.preparationHeaders);
        headers.set("accept", AGENT_EXCHANGE_PREPARATION_MEDIA_TYPE);
        headers.set("content-type", AGENT_EXCHANGE_PREPARATION_MEDIA_TYPE);
        const response = await (options.fetch ?? globalThis.fetch)(
          new Request(endpoint, {
            body: JSON.stringify({ request }),
            credentials: "omit",
            headers,
            method: "POST",
            redirect: "error",
            referrerPolicy: "no-referrer",
            signal: AbortSignal.timeout(options.timeoutMs ?? 10_000),
          }),
        );
        if (!response.ok)
          throw new Error("Agent Exchange A2A preparation failed");
        if (
          response.headers.get("content-type")?.split(";", 1)[0]?.trim() !==
          AGENT_EXCHANGE_PREPARATION_MEDIA_TYPE
        )
          throw new Error("Agent Exchange A2A preparation was rejected");
        const prepared = await responseBody(
          response,
          options.maxResponseBytes ?? 65_536,
        );
        if (
          !isRecord(prepared) ||
          Object.keys(prepared).some((key) => key !== "reference")
        )
          throw new Error("Agent Exchange A2A preparation was rejected");
        parsePreparedReference(prepared.reference, expectedReference);
      }
      const response = await client.sendMessage({
        configuration: {
          acceptedOutputModes: [AGENT_EXCHANGE_RECEIPT_MEDIA_TYPE],
          historyLength: 0,
          returnImmediately: false,
        },
        message: toA2aAgentExchangeMessage(request),
      });
      if (!response.task)
        throw new Error("Agent Exchange A2A server did not return a task");
      return receiptFromTask(response.task, request);
    },
  });
};

export const connectAgentExchangeA2a = async (options: {
  readonly discoveryHeaders?: HeadersInit;
  readonly fetch?: A2aFetch;
  readonly headers?: HeadersInit | (() => HeadersInit | Promise<HeadersInit>);
  readonly maxResponseBytes?: number;
  readonly origin: string;
  readonly preparationHeaders?:
    HeadersInit | (() => HeadersInit | Promise<HeadersInit>);
  readonly prepare?: AgentExchangeA2aPrepare;
  readonly timeoutMs?: number;
}): Promise<AgentExchangeA2aClient> => {
  const agentCard = await discoverA2aAgent(options.origin, {
    fetch: options.fetch,
    headers: options.discoveryHeaders,
    maxResponseBytes: options.maxResponseBytes,
    timeoutMs: options.timeoutMs,
  });
  return createAgentExchangeA2aClient({ ...options, agentCard });
};
