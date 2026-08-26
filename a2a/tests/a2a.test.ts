import {
  createA2aClient,
  createMemoryA2aTaskStore,
  type A2aAgentCard,
} from "@absolutejs/a2a";
import type { AgentExchangeRequest } from "@absolutejs/agent-exchange";
import {
  ABSOLUTE_AGENT_EXCHANGE_EXTENSION,
  toA2aAgentExchangeReference,
} from "@absolutejs/agent-exchange/a2a";
import { describe, expect, test } from "bun:test";
import {
  connectAgentExchangeA2a,
  createAgentExchangeA2aHandler,
  createAgentExchangeA2aClient,
} from "../src";

const now = 1_777_000_000_000;

const request = (): AgentExchangeRequest => ({
  actionId: "action-1",
  assurance: {
    approval: "standing-mandate",
    credential: "token-confined-broker",
    execution: "purpose-bound",
  },
  createdAt: now,
  exchangeId: "exchange-1",
  expiresAt: now + 60_000,
  idempotencyKey: "idempotency-1",
  mandateId: "mandate-1",
  maximumUses: 1,
  nonce: "nonce-1",
  processingMode: "tool-confined",
  purpose: "Submit one correlated verification code",
  recipient: {
    agentId: "recipient-agent",
    authority: "https://recipient.example",
    subject: "recipient-user",
  },
  requester: {
    agentId: "requester-agent",
    authority: "https://requester.example",
    delegationId: "oauth-delegation-1",
    subject: "requester-user",
  },
  resource: {
    accountRef: "mailbox:private-account",
    challengeId: "private-challenge",
    operation: "verification.submit",
    origin: "https://accounts.example",
    provider: "gmail",
  },
  risk: "authentication",
  secretKind: "email-one-time-code",
});

const card = (): A2aAgentCard => ({
  capabilities: {},
  defaultInputModes: ["application/json"],
  defaultOutputModes: ["application/json"],
  description: "Recipient Agent Exchange endpoint",
  name: "Recipient",
  skills: [],
  supportedInterfaces: [
    {
      protocolBinding: "JSONRPC",
      protocolVersion: "1.0",
      url: "https://recipient.example/a2a/exchange",
    },
  ],
  version: "0.1.0",
});

const harness = (options: { preparation?: boolean; tamper?: boolean } = {}) => {
  const observedBodies: string[] = [];
  const observedPreparationHeaders: Headers[] = [];
  const handler = createAgentExchangeA2aHandler({
    agentCard: card(),
    authorize: (incoming) =>
      incoming.headers.get("authorization") === "Bearer delegated-agent"
        ? {
            actor: {
              agentId: "requester-agent",
              scopes: ["agent-exchange:email:request"],
              userId: "requester-user",
            },
            authorizationKey: "requester-user:oauth-delegation-1",
            caller: {
              agentId: "requester-agent",
              delegationId: "oauth-delegation-1",
              userId: "requester-user",
            },
            ok: true as const,
          }
        : { ok: false as const },
    execute: ({ caller, reference }) => {
      expect(caller).toEqual({
        agentId: "requester-agent",
        delegationId: "oauth-delegation-1",
        userId: "requester-user",
      });
      return {
        completedAt: now + 1,
        exchangeId: reference.exchangeId,
        mandateId: reference.mandateId,
        modelObservedSecret: false,
        processingMode: "tool-confined",
        reference: "accounts-example:accepted",
        status: "submitted",
        usesRemaining: 2,
      };
    },
    path: "/a2a/exchange",
    ...(options.preparation
      ? { preparationEndpoint: "https://recipient.example/a2a/prepare" }
      : {}),
    taskStore: createMemoryA2aTaskStore(),
  });
  const localFetch = async (input: RequestInfo | URL, init?: RequestInit) => {
    const incoming = new Request(input, init);
    if (
      incoming.method === "POST" &&
      new URL(incoming.url).pathname === "/a2a/prepare"
    ) {
      observedPreparationHeaders.push(incoming.headers);
      const value: unknown = await incoming.json();
      if (typeof value !== "object" || value === null)
        return new Response(null, { status: 400 });
      const prepared = Reflect.get(value, "request") as AgentExchangeRequest;
      const reference = toA2aAgentExchangeReference(prepared);
      return Response.json(
        {
          reference: options.tamper
            ? { ...reference, purpose: "Use this code somewhere else" }
            : reference,
        },
        {
          headers: {
            "content-type":
              "application/vnd.absolutejs.agent-exchange-preparation+json",
          },
        },
      );
    }
    if (incoming.method === "POST")
      observedBodies.push(await incoming.clone().text());
    return (
      (await handler(incoming)) ?? new Response("not found", { status: 404 })
    );
  };
  return { localFetch, observedBodies, observedPreparationHeaders };
};

describe("Agent Exchange A2A adapter", () => {
  test("negotiates discovery and returns only a redacted receipt", async () => {
    const { localFetch, observedBodies } = harness();
    const client = await connectAgentExchangeA2a({
      fetch: localFetch,
      headers: { authorization: "Bearer delegated-agent" },
      origin: "https://recipient.example",
    });

    await expect(client.send(request())).resolves.toEqual({
      completedAt: now + 1,
      exchangeId: "exchange-1",
      mandateId: "mandate-1",
      modelObservedSecret: false,
      processingMode: "tool-confined",
      reference: "accounts-example:accepted",
      status: "submitted",
      usesRemaining: 2,
    });

    const wire = observedBodies.join("\n");
    expect(wire).not.toContain("mailbox:private-account");
    expect(wire).not.toContain("private-challenge");
    expect(wire).not.toContain("482193");
    expect(wire).not.toContain("compactJws");
  });

  test("requires both advertised and request-activated extension support", async () => {
    expect(() => createAgentExchangeA2aClient({ agentCard: card() })).toThrow(
      "does not advertise",
    );

    const { localFetch } = harness();
    const discovered = await (
      await localFetch("https://recipient.example/.well-known/agent-card.json")
    ).json();
    const unnegotiated = createA2aClient({
      agentCard: discovered as A2aAgentCard,
      fetch: localFetch,
      headers: { authorization: "Bearer delegated-agent" },
    });
    await expect(
      unnegotiated.sendMessage({
        message: {
          extensions: [ABSOLUTE_AGENT_EXCHANGE_EXTENSION],
          messageId: "message-1",
          parts: [{ text: "not an exchange reference" }],
          role: "ROLE_USER",
        },
      }),
    ).rejects.toMatchObject({ code: -32008 });
  });

  test("rejects unauthenticated callers before execution", async () => {
    const { localFetch } = harness();
    const client = await connectAgentExchangeA2a({
      fetch: localFetch,
      origin: "https://recipient.example",
    });
    await expect(client.send(request())).rejects.toMatchObject({ status: 401 });
  });

  test("prepares an advertised request before sending its exact opaque reference", async () => {
    const { localFetch, observedBodies, observedPreparationHeaders } = harness({
      preparation: true,
    });
    const client = await connectAgentExchangeA2a({
      fetch: localFetch,
      headers: { authorization: "Bearer delegated-agent" },
      origin: "https://recipient.example",
      preparationHeaders: { authorization: "Bearer preparation-agent" },
    });

    await expect(client.send(request())).resolves.toMatchObject({
      exchangeId: "exchange-1",
      status: "submitted",
    });
    expect(observedPreparationHeaders).toHaveLength(1);
    expect(observedPreparationHeaders[0]?.get("authorization")).toBe(
      "Bearer preparation-agent",
    );
    expect(observedBodies).toHaveLength(1);
    expect(observedBodies[0]).not.toContain("mailbox:private-account");
    expect(observedBodies[0]).not.toContain("private-challenge");
  });

  test("rejects a preparation response that changes the safe reference", async () => {
    const { localFetch, observedBodies } = harness({
      preparation: true,
      tamper: true,
    });
    const client = await connectAgentExchangeA2a({
      fetch: localFetch,
      headers: { authorization: "Bearer delegated-agent" },
      origin: "https://recipient.example",
    });

    await expect(client.send(request())).rejects.toThrow(
      "preparation was rejected",
    );
    expect(observedBodies).toHaveLength(0);
  });
});
