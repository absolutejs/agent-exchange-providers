import { test, expect } from "bun:test";
import { discoverVerificationService, verificationServiceOrigin } from "../src";
const now = Date.now();
const mail = (patch = {}) => ({
  accountEmail: "owner@example.com",
  provider: "gmail",
  direction: "inbound" as const,
  id: "private-message",
  occurredAt: new Date(now),
  from: { address: "security@mail.novel-service.com" },
  to: [{ address: "owner@example.com" }],
  subject: "Sign in verification",
  bodyText: "Please sign in.\nYour verification code:\n\n724981\n",
  authenticationResults: [
    "mx.google.com; dmarc=pass header.from=mail.novel-service.com",
  ],
  ...patch,
});
const discover = (
  messages = [mail()],
  origin = "https://app.novel-service.com",
) =>
  discoverVerificationService({
    origin,
    accountEmail: "owner@example.com",
    messages,
    now,
  });
test("unknown provider is inferred with no secret in output and stable revision", async () => {
  const a = await discover(),
    b = await discover([
      mail({
        bodyText: "Please sign in.\nYour verification code:\n\n135790\n",
      }),
    ]);
  expect(a).toEqual(b);
  expect(a.permission.allowAlways).toBe(true);
  expect(JSON.stringify(a)).not.toContain("724981");
  expect(JSON.stringify(a)).not.toContain("private-message");
  expect(a.email.senderAddresses).toEqual(["security@mail.novel-service.com"]);
});
test("no model or email may expand trust across domains, mailbox or authentication", async () => {
  for (const patch of [
    { from: { address: "attacker@evil.com" } },
    { authenticationResults: [] },
    { accountEmail: "other@example.com" },
    { occurredAt: new Date(now - 16 * 60000) },
    { bodyText: "Your verification code:\n724981\n135790" },
    { subject: "Reset password verification" },
    { bodyText: "Change your email. Verification code: 724981" },
  ])
    await expect(discover([mail(patch)])).rejects.toThrow();
});
test("ambiguous templates fail instead of picking the first", async () => {
  await expect(
    discover([mail(), mail({ subject: "Login code" })]),
  ).rejects.toThrow("Ambiguous");
});
test("PSL private tenant boundaries and malformed origins are rejected", async () => {
  for (const origin of [
    "http://service.com",
    "https://localhost",
    "https://127.0.0.1",
    "https://user:secret@service.com",
  ])
    expect(() => verificationServiceOrigin(origin)).toThrow();
  await expect(
    discover(
      [mail({ from: { address: "security@evil.github.io" } })],
      "https://good.github.io",
    ),
  ).rejects.toThrow();
});
test("inline OTP and changed templates produce distinct revisions", async () => {
  const inline = await discover([
    mail({ bodyText: "Your verification code: 724981" }),
  ]);
  expect(inline.email.codeLayout).toBe("after-marker");
  expect(inline.permission.revision).not.toBe(
    (await discover()).permission.revision,
  );
});
