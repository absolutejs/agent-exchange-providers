import { getDomain } from "tldts";
import {
  resolveEmailVerificationCode,
  type EmailVerificationProfile,
  type NormalizedEmailMessage,
} from "@absolutejs/email";
import type { ServiceProfile } from "@absolutejs/agent-exchange-permissions";

export type DiscoveredVerificationService = {
  permission: ServiceProfile;
  email: EmailVerificationProfile & {
    correlation: { mode: "temporal-only" };
    operations: readonly string[];
  };
};
const forbidden =
  /password\s*(?:reset|change)|reset\s*(?:your\s*)?password|account\s*recovery|disable\s*(?:2fa|mfa)|(?:change|remove|add)\s*(?:your\s*)?(?:email|phone|authenticator)|(?:payment|transfer|withdrawal)/i;
/** No URL is fetched. PSL private-domain boundaries prevent trusting sibling tenants. */
export function verificationServiceOrigin(value: string) {
  const url = new URL(value);
  if (
    url.protocol !== "https:" ||
    url.username ||
    url.password ||
    url.port ||
    !getDomain(url.hostname, { allowPrivateDomains: true }) ||
    /^(localhost|\d|\[)/.test(url.hostname)
  )
    throw Error("A public HTTPS service origin is required");
  return url.origin;
}
export function verificationSearchDomain(origin: string) {
  return getDomain(new URL(verificationServiceOrigin(origin)).hostname, {
    allowPrivateDomains: true,
  })!;
}
const digest = async (value: unknown) =>
  Array.from(
    new Uint8Array(
      await crypto.subtle.digest(
        "SHA-256",
        new TextEncoder().encode(JSON.stringify(value)),
      ),
    ),
  )
    .map((x) => x.toString(16).padStart(2, "0"))
    .join("");
/** Discovery is not authorization. Call only after the mailbox owner permits this bounded inspection.
 * Input bodies stay inside the trusted process. Output never includes a code, body, snippet or message ID.
 * The owner must review the inferred sender/destination association before signing a permission.
 */
export async function discoverVerificationService(input: {
  origin: string;
  accountEmail: string;
  messages: readonly NormalizedEmailMessage[];
  now?: number;
}): Promise<DiscoveredVerificationService> {
  const origin = verificationServiceOrigin(input.origin),
    domain = verificationSearchDomain(origin),
    now = input.now ?? Date.now();
  if (input.messages.length > 10) throw Error("Too many candidates");
  const candidates = new Map<
    string,
    { email: DiscoveredVerificationService["email"] }
  >();
  for (const message of input.messages) {
    const sender = message.from?.address.toLowerCase() ?? "",
      senderDomain = sender.split("@")[1] ?? "";
    const subject = (message.subject ?? "").trim(),
      body = message.bodyText ?? "";
    if (
      getDomain(senderDomain, { allowPrivateDomains: true }) !== domain ||
      !/^[a-z0-9.!#$%&'*+/=?^_`{|}~-]+@[a-z0-9.-]+$/.test(sender) ||
      subject.length > 160 ||
      /\d|https?:|[\r\n<>]/i.test(subject) ||
      !/(?:verif|sign.?in|log.?in|code|otp)/i.test(subject) ||
      forbidden.test(subject + "\n" + body) ||
      body.length > 32768
    )
      continue;
    // No service-specific marker. Infer a short alphabetic code label immediately before the only six-digit token.
    const codes = [...body.matchAll(/(?<!\d)\d{6}(?!\d)/g)];
    if (codes.length !== 1) continue;
    const position = codes[0]!.index!;
    const prefix = body.slice(Math.max(0, position - 200), position);
    const line =
      prefix
        .split(/\r?\n/)
        .map((s) => s.trim())
        .filter(Boolean)
        .at(-1) ?? "";
    const marker = line
      .replace(
        /^.*?\b(?=(?:verification|security|one.time|sign.in|log.in|digit|code|otp)\b)/i,
        "",
      )
      .replace(/\d+/g, "")
      .trim();
    if (
      !marker ||
      marker.length > 120 ||
      !/(?:code|otp)/i.test(marker) ||
      !/^[a-zA-Z\s:.,'’()-]+$/.test(marker) ||
      !body.slice(0, position).includes(marker)
    )
      continue;
    const inline = !/\n/.test(
      prefix.slice(prefix.lastIndexOf(marker) + marker.length),
    );
    const email: DiscoveredVerificationService["email"] = {
      id: "discovery-candidate",
      origins: [origin],
      providers: ["gmail"],
      operations: ["browser.login.verify"],
      correlation: { mode: "temporal-only" },
      bodyMarkers: [marker],
      codeLayout: inline ? "after-marker" : "standalone-after-marker",
      maxMarkerGap: 64,
      senderAddresses: [sender],
      subjectIncludesAny: [subject],
      senderAuthentication: {
        allowedHeaderFromDomains: [senderDomain],
        trustedAuthservIds: ["mx.google.com"],
      },
    };
    try {
      const result = resolveEmailVerificationCode([message], {
        profile: email,
        accountEmail: input.accountEmail,
        expectedOrigin: origin,
        notBefore: new Date(now - 9 * 60000),
        notAfter: new Date(now + 30000),
      });
      result.bytes.fill(0);
    } catch {
      continue;
    }
    candidates.set(JSON.stringify(email), { email });
  }
  if (candidates.size !== 1)
    throw Error(
      candidates.size
        ? "Ambiguous verification template"
        : "No authenticated verification template",
    );
  const email = [...candidates.values()][0]!.email;
  const revision = await digest(email),
    id = "discovered-" + (await digest(origin)).slice(0, 32);
  return {
    permission: {
      id,
      revision,
      adapterRevision: revision,
      label: new URL(origin).hostname + " sign-in",
      allowAlways: true,
      grant: {
        origin,
        operation: "browser.login.verify",
        provider: "gmail",
        purpose: "Complete an owner-approved sign-in in the bound browser",
        risk: "authentication",
        secretKind: "email-one-time-code",
      },
    },
    email: { ...email, id: "discovered-email-" + revision },
  };
}
