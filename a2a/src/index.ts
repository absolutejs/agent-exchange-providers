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
  ABSOLUTE_AGENT_EXCHANGE_EXTENSION,
  type A2aAgentExchangeReference,
  parseA2aAgentExchangeReference,
  toA2aAgentExchangeMessage,
  withAgentExchangeExtension,
} from "@absolutejs/agent-exchange/a2a";
import type { AgentExchangeRequest } from "@absolutejs/agent-exchange";

export const AGENT_EXCHANGE_RECEIPT_MEDIA_TYPE =
  "application/vnd.absolutejs.agent-exchange-receipt+json" as const;
export const AGENT_EXCHANGE_A2A_SKILL_ID = "absolute-agent-exchange" as const;

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
  readonly taskStore: A2aTaskStore;
};

export type AgentExchangeA2aClient = {
  readonly agentCard: A2aAgentCard;
  readonly send: (
    request: AgentExchangeRequest,
  ) => Promise<AgentExchangeA2aReceipt>;
};

const isRecord = (value: unknown): value is Record<string, unknown> =>
  value !== null && typeof value === "object" && !Array.isArray(value);

const bounded = (value: unknown, maximumBytes: number): value is string =>
  typeof value === "string" &&
  value.trim().length > 0 &&
  encoder.encode(value).byteLength <= maximumBytes;

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
): A2aAgentCard => {
  const extended = withAgentExchangeExtension(card);
  return {
    ...extended,
    capabilities: { ...extended.capabilities, streaming: false },
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
  const card = withAgentExchangeA2aProfile(options.agentCard);
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
