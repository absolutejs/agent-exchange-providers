import {
  agentExchangeApprovalChallenge,
  type AgentExchangeRequest,
} from "@absolutejs/agent-exchange";

/** A Playwright-compatible page. The host must disable tracing/video/network-body logs. */
export type VerificationPage = {
  evaluate<R, A>(
    callback: (argument: A) => R | Promise<R>,
    argument: A,
  ): Promise<R>;
  mainFrame(): unknown;
  on(event: "framenavigated", listener: (frame: unknown) => void): unknown;
  off(event: "framenavigated", listener: (frame: unknown) => void): unknown;
};
export type BrowserVerificationProfile = {
  readonly id: string;
  readonly origin: string;
  readonly operation: string;
  readonly submission?: "native-post" | "spa";
  readonly pathnames: readonly string[];
  readonly formActionPathnames: readonly string[];
  readonly formSelector: string;
  readonly codeSelector: string;
  readonly submitSelector: string;
};
// The same function inspects and submits, checking the form again after input
// handlers execute. It never returns the code or a provider response body.
function inPage(input: {
  profile: BrowserVerificationProfile;
  marker: string;
  snapshot?: string;
  code?: string;
}) {
  const p = input.profile;
  const marker = Symbol.for(input.marker);
  const documentState = document as unknown as Record<symbol, unknown>;
  if (input.snapshot === undefined)
    Object.defineProperty(document, marker, {
      value: crypto.randomUUID(),
      configurable: true,
    });
  if (typeof documentState[marker] !== "string")
    throw Error("Document changed");
  function elements() {
    if (
      location.origin !== p.origin ||
      !p.pathnames.includes(location.pathname) ||
      window.top !== window
    )
      throw Error("Unavailable");
    const forms = document.querySelectorAll(p.formSelector),
      fields = document.querySelectorAll(p.codeSelector),
      buttons = document.querySelectorAll(p.submitSelector);
    if (forms.length !== 1 || fields.length !== 1 || buttons.length !== 1)
      throw Error("Ambiguous");
    const form = forms[0],
      field = fields[0],
      button = buttons[0];
    if (
      !(form instanceof HTMLFormElement) ||
      !(field instanceof HTMLInputElement) ||
      !(button instanceof HTMLElement) ||
      field.form !== form ||
      !form.contains(button) ||
      field.disabled ||
      field.readOnly ||
      field.type === "password" ||
      field.type === "hidden" ||
      form.querySelectorAll('input[type="password"]').length > 0 ||
      field.getClientRects().length === 0 ||
      button.getClientRects().length === 0
    )
      throw Error("Unavailable");
    const action = new URL(form.action, location.href);
    if (
      action.origin !== p.origin ||
      !p.formActionPathnames.includes(action.pathname) ||
      (p.submission !== "spa" && form.method.toLowerCase() !== "post") ||
      (form.target && form.target !== "_self")
    )
      throw Error("Destination changed");
    const snapshot = JSON.stringify([
      location.href,
      action.href,
      form.method,
      field.name,
      field.type,
      documentState[marker],
      Array.from(form.querySelectorAll('input[type="hidden"]')).map((e) => [
        (e as HTMLInputElement).name,
        (e as HTMLInputElement).value,
      ]),
    ]);
    return { form, field, button, snapshot };
  }
  const before = elements();
  if (input.snapshot !== undefined && before.snapshot !== input.snapshot)
    throw Error("Session changed");
  if (input.code === undefined) return before.snapshot;
  if (!/^[0-9]{6}$/.test(input.code) || before.field.value !== "")
    throw Error("Invalid input");
  try {
    const setter = Object.getOwnPropertyDescriptor(
      HTMLInputElement.prototype,
      "value",
    )!.set!;
    setter.call(before.field, input.code);
    before.field.dispatchEvent(new Event("input", { bubbles: true }));
    before.field.dispatchEvent(new Event("change", { bubbles: true }));
    const after = elements();
    if (
      after.snapshot !== before.snapshot ||
      after.form !== before.form ||
      after.field !== before.field ||
      after.button !== before.button
    )
      throw Error("Session changed");
    // React/Vue forms often omit method. Never allow a native GET fallback.
    if (p.submission === "spa")
      after.form.addEventListener("submit", (e) => e.preventDefault(), {
        capture: true,
        once: true,
      });
    after.button.click();
    return "submitted";
  } catch {
    before.field.value = "";
    throw Error("Submission failed");
  }
}

/** Call only after checking the authenticated requester, mandate and browser account. */
export async function createBrowserVerificationDestination(options: {
  page: VerificationPage;
  profile: BrowserVerificationProfile;
  request: AgentExchangeRequest;
  tenantId: string;
  /** Must check authenticated success for the expected account, not just navigation. */
  verifySuccess: () => Promise<boolean>;
  /** Re-check revocation/application access immediately before submission. */
  assertAuthorized: () => Promise<void>;
  now?: () => number;
}) {
  const p = structuredClone(options.profile),
    request = structuredClone(options.request),
    now = options.now ?? Date.now;
  const origin = new URL(p.origin);
  if (
    origin.protocol !== "https:" ||
    origin.origin !== p.origin ||
    !options.tenantId ||
    request.resource.origin !== p.origin ||
    request.resource.operation !== p.operation ||
    !request.resource.challengeId ||
    request.secretKind !== "email-one-time-code" ||
    request.processingMode !== "tool-confined" ||
    request.maximumUses !== 1 ||
    !["standing-mandate", "webauthn-verifier-bound"].includes(
      request.assurance.approval,
    ) ||
    request.assurance.credential !== "token-confined-broker" ||
    request.assurance.execution !== "purpose-bound" ||
    request.expiresAt <= now() ||
    request.expiresAt - now() > 120000 ||
    p.pathnames.length === 0 ||
    p.formActionPathnames.length === 0 ||
    [...p.pathnames, ...p.formActionPathnames].some(
      (path) =>
        !path.startsWith("/") ||
        path.includes("*") ||
        path.includes("?") ||
        path.includes("#"),
    )
  )
    throw Error("Browser verification unavailable");
  const binding = await agentExchangeApprovalChallenge(request);
  let navigated = false,
    claimed = false;
  const navigation = (frame: unknown) => {
    if (frame === options.page.mainFrame()) navigated = true;
  };
  options.page.on("framenavigated", navigation);
  const marker = "absolute-verification:" + crypto.randomUUID();
  const close = () => {
    claimed = true;
    options.page.off("framenavigated", navigation);
  };
  let snapshot: string;
  try {
    snapshot = await options.page.evaluate(inPage, { profile: p, marker });
    if (navigated) throw Error();
  } catch {
    close();
    throw Error("Browser verification unavailable");
  }
  return {
    descriptor: {
      id: p.id,
      operations: [p.operation],
      origin: p.origin,
      secretKinds: ["email-one-time-code"],
    },
    close,
    async submit(input: {
      plaintext: Uint8Array;
      request: AgentExchangeRequest;
      tenantId: string;
    }) {
      // Claim synchronously before any await. Failed or ambiguous submissions cannot retry.
      if (claimed) throw Error("Browser verification already attempted");
      claimed = true;
      const bytes = Uint8Array.from(input.plaintext);
      try {
        if (
          navigated ||
          now() >= request.expiresAt ||
          input.tenantId !== options.tenantId ||
          input.request.createdAt !== request.createdAt ||
          input.request.mandateId !== request.mandateId ||
          (await agentExchangeApprovalChallenge(input.request)) !== binding ||
          bytes.length !== 6 ||
          bytes.some((b) => b < 48 || b > 57)
        )
          throw Error();
        await options.assertAuthorized();
        if (navigated || now() >= request.expiresAt) throw Error();
        await options.page.evaluate(inPage, {
          profile: p,
          marker,
          snapshot,
          code: new TextDecoder().decode(bytes),
        });
        if (!(await options.verifySuccess())) throw Error();
        return { status: "submitted" as const };
      } catch {
        throw Error("Browser verification failed");
      } finally {
        bytes.fill(0);
        close();
      }
    },
  };
}
