import { expect, test } from "bun:test";
import {
  discoverVerificationService,
  discoverySenderQuery,
  messagesForService,
} from "../src/index";
import {
  resolveEmailVerificationCode,
  type NormalizedEmailMessage,
} from "@absolutejs/email";

const now = Date.now();
const mailbox = "owner@example.org";
const origin = "https://claude.ai";
const message: NormalizedEmailMessage = {
  provider: "gmail",
  direction: "inbound",
  accountEmail: mailbox,
  id: "fixture",
  occurredAt: new Date(now),
  from: { address: "no-reply-claude@mail.anthropic.com" },
  to: [{ address: mailbox }],
  subject: "Your Claude sign-in code",
  bodyText: "Your verification code: 123456",
  authenticationResults: [
    "mx.google.com; dmarc=pass header.from=mail.anthropic.com",
  ],
};
const discover = (
  overrides: Partial<NormalizedEmailMessage> = {},
  service = origin,
) =>
  discoverVerificationService({
    origin: service,
    accountEmail: mailbox,
    now,
    messages: [{ ...message, ...overrides }],
  });

test("Claude searches both sender domains and delivers a code through the original Claude profile", async () => {
  expect(discoverySenderQuery(origin)).toBe(
    "{from:claude.ai from:mail.anthropic.com}",
  );
  expect(discoverySenderQuery("https://app.example.org")).toBe(
    "from:(example.org)",
  );
  const profile = await discover();
  expect(profile.permission.grant.origin).toBe(origin);
  expect(profile.email.senderAddresses).toEqual([message.from!.address!]);
  expect(JSON.stringify(profile)).not.toContain("123456");
  const value = resolveEmailVerificationCode([message], {
    profile: profile.email,
    expectedOrigin: origin,
    accountEmail: mailbox,
    notBefore: new Date(now - 60000),
    notAfter: new Date(now + 1000),
  });
  try {
    expect(new TextDecoder().decode(value.bytes)).toBe("123456");
  } finally {
    value.bytes.fill(0);
  }
});

test("Claude rejects the wrong service, other recipients, unauthenticated mail and non-login messages", async () => {
  for (const overrides of [
    { authenticationResults: [] },
    { to: [{ address: "another@example.org" }] },
    { subject: "Claude Console login code" },
    { subject: "Claude password reset code" },
    { from: { address: "sender@mail.anthropic.com.example.org" } },
    { from: { address: "marketing@mail.anthropic.com" } },
    { bodyText: "Open your secure login link" },
  ]) {
    await expect(discover(overrides)).rejects.toThrow();
  }
  await expect(discover({}, "https://unrelated.example.org")).rejects.toThrow();
});

test("delivery rechecks the exact discovered subject and recipient on a later lookup", async () => {
  const { email } = await discover();
  const later = [
    { ...message, subject: "Re: " + message.subject },
    { ...message, to: [{ address: "another@example.org" }] },
    { ...message, bodyText: "Your verification code: 234567" },
  ];
  expect(
    messagesForService(origin, mailbox, later, email.subjectIncludesAny),
  ).toEqual([later[2]!]);
});
