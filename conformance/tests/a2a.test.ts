import { createMemoryA2aTaskStore } from "@absolutejs/a2a";
import type { AgentExchangeRequest } from "@absolutejs/agent-exchange";
import { toA2aAgentExchangeReference } from "@absolutejs/agent-exchange/a2a";
import {
  AGENT_EXCHANGE_PREPARATION_MEDIA_TYPE,
  createAgentExchangeA2aHandler,
} from "@absolutejs/agent-exchange-a2a";
import { describe, expect, test } from "bun:test";
import {
  assertAgentExchangeA2aConformance,
  evaluateAgentExchangeA2aConformance,
  type AgentExchangeA2aConformanceRequestPurpose,
  type AgentExchangeA2aConformanceTarget,
} from "../src";

const ORIGIN = "https://recipient.example";
const A2A_ENDPOINT = `${ORIGIN}/a2a`;
const PREPARATION_ENDPOINT = `${ORIGIN}/agent-exchange/requests`;
const A2A_TOKEN = "Bearer sandbox-a2a-token";
const PREPARATION_TOKEN = "Bearer sandbox-preparation-token";

const createRequest = (
  purpose: AgentExchangeA2aConformanceRequestPurpose,
): AgentExchangeRequest => {
  const now = Date.now();
  return {
    actionId: `action-${purpose}`,
    assurance: {
      approval: "standing-mandate",
      credential: "token-confined-broker",
      execution: "purpose-bound",
    },
    createdAt: now,
    exchangeId: `exchange-${purpose}`,
    expiresAt: now + 60_000,
    idempotencyKey: `private-idempotency-${purpose}`,
    mandateId: "mandate-sandbox",
    maximumUses: 1,
    nonce: `private-nonce-${purpose}`,
    processingMode: "tool-confined",
    purpose: "Submit one sandbox verification code",
    recipient: {
      agentId: "recipient-agent",
      authority: ORIGIN,
      subject: "recipient-user",
    },
    requester: {
      agentId: "requester-agent",
      authority: "https://requester.example",
      delegationId: "delegation-sandbox",
      subject: "requester-user",
    },
    resource: {
      accountRef: `private-account-${purpose}`,
      challengeId: `private-challenge-${purpose}`,
      operation: "verification.submit",
      origin: "https://accounts.example",
      provider: "gmail",
    },
    risk: "authentication",
    secretKind: "email-one-time-code",
  };
};

const fixture = (
  options: {
    encodedLeak?: boolean;
    leak?: boolean;
    sharedCredential?: boolean;
  } = {},
) => {
  const prepared = new Map<string, AgentExchangeRequest>();
  const handler = createAgentExchangeA2aHandler({
    agentCard: {
      capabilities: {},
      defaultInputModes: ["application/json"],
      defaultOutputModes: ["application/json"],
      description: "Conformance sandbox recipient",
      name: "Conformance sandbox",
      securityRequirements: [
        { schemes: { a2aOAuth: { list: ["agent-exchange:request"] } } },
      ],
      securitySchemes: {
        a2aOAuth: { scheme: "bearer", type: "http" },
      },
      skills: [],
      supportedInterfaces: [
        {
          protocolBinding: "JSONRPC",
          protocolVersion: "1.0",
          url: A2A_ENDPOINT,
        },
      ],
      version: "0.1.0",
    },
    authorize: (request) =>
      request.headers.get("authorization") === A2A_TOKEN
        ? {
            actor: {
              agentId: "requester-agent",
              scopes: ["agent-exchange:request"],
              userId: "requester-user",
            },
            authorizationKey: "requester-user:delegation-sandbox",
            caller: { requester: "requester-user" },
            ok: true as const,
          }
        : { ok: false as const, status: 401 },
    execute: ({ reference }) => {
      const request = prepared.get(reference.exchangeId);
      if (!request) throw new Error("prepared request unavailable");
      prepared.delete(reference.exchangeId);
      expect(reference).toEqual(toA2aAgentExchangeReference(request));
      return {
        completedAt: Date.now(),
        exchangeId: reference.exchangeId,
        ...(reference.mandateId === undefined
          ? {}
          : { mandateId: reference.mandateId }),
        modelObservedSecret: false,
        processingMode: "tool-confined",
        ...(options.leak || options.encodedLeak
          ? {
              reference: options.encodedLeak
                ? Buffer.from(request.resource.accountRef).toString("base64url")
                : request.resource.accountRef,
            }
          : { reference: "sandbox:accepted" }),
        status: "submitted" as const,
      };
    },
    path: "/a2a",
    preparationEndpoint: PREPARATION_ENDPOINT,
    taskStore: createMemoryA2aTaskStore(),
  });
  const localFetch = async (input: RequestInfo | URL, init?: RequestInit) => {
    const incoming = new Request(input, init);
    if (new URL(incoming.url).pathname === "/agent-exchange/requests") {
      if (
        incoming.headers.get("authorization") !==
        (options.sharedCredential ? A2A_TOKEN : PREPARATION_TOKEN)
      )
        return new Response(null, { status: 401 });
      let value: unknown;
      try {
        value = await incoming.json();
      } catch {
        return new Response(null, { status: 400 });
      }
      const request =
        typeof value === "object" && value !== null
          ? (Reflect.get(value, "request") as AgentExchangeRequest)
          : undefined;
      if (!request) return new Response(null, { status: 400 });
      prepared.set(request.exchangeId, request);
      return Response.json(
        { reference: toA2aAgentExchangeReference(request) },
        {
          headers: {
            "cache-control": "no-store",
            "content-type": AGENT_EXCHANGE_PREPARATION_MEDIA_TYPE,
          },
        },
      );
    }
    return (await handler(incoming)) ?? new Response(null, { status: 404 });
  };
  const target: AgentExchangeA2aConformanceTarget = {
    acknowledgeExecution: "sandbox-only",
    a2aHeaders: () => ({ authorization: A2A_TOKEN }),
    createRequest,
    fetch: localFetch,
    origin: ORIGIN,
    preparationHeaders: () => ({
      authorization: options.sharedCredential ? A2A_TOKEN : PREPARATION_TOKEN,
    }),
  };
  return target;
};

describe("Agent Exchange A2A conformance", () => {
  test("accepts a sandbox that enforces the complete prepared profile", async () => {
    const report = await assertAgentExchangeA2aConformance(fixture());

    expect(report.conformant).toBe(true);
    expect(report.findings).toHaveLength(8);
    expect(report.findings.every((finding) => finding.passed)).toBe(true);
  });

  test("reports a receipt that reflects protected request data", async () => {
    const report = await evaluateAgentExchangeA2aConformance(
      fixture({ leak: true }),
    );

    expect(report.conformant).toBe(false);
    expect(report.findings).toContainEqual({
      check: "prepared-execution",
      detail: "protected request data crossed the A2A boundary",
      passed: false,
    });
  });

  test("detects encoded protected request data in a receipt", async () => {
    const report = await evaluateAgentExchangeA2aConformance(
      fixture({ encodedLeak: true }),
    );

    expect(report.findings).toContainEqual({
      check: "prepared-execution",
      detail: "protected request data crossed the A2A boundary",
      passed: false,
    });
  });

  test("rejects one credential shared across preparation and A2A", async () => {
    const report = await evaluateAgentExchangeA2aConformance(
      fixture({ sharedCredential: true }),
    );

    expect(report.findings).toContainEqual({
      check: "credential-separation",
      detail: "preparation accepted the A2A credential",
      passed: false,
    });
  });

  test("requires explicit acknowledgement that execution is sandboxed", async () => {
    await expect(
      evaluateAgentExchangeA2aConformance({
        ...fixture(),
        acknowledgeExecution: "production" as "sandbox-only",
      }),
    ).rejects.toThrow("sandbox target");
  });
});
