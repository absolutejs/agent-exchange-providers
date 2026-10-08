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

/** Discovers a single conventional OTP form without exposing page text or field values.
 * The supplied origin must come from the owner-approved service, never from the page.
 * Does not authorize or submit anything. Unsupported/multi-input forms fail closed.
 */
export async function discoverBrowserVerificationProfile(input: {
  page: VerificationPage;
  origin: string;
  operation: string;
  id: string;
}): Promise<BrowserVerificationProfile> {
  const url = new URL(input.origin);
  if (url.protocol !== "https:" || url.origin !== input.origin)
    throw Error("Exact HTTPS origin required");
  const marker = crypto.randomUUID();
  const shape = await input.page.evaluate(
    ({ origin, marker }) => {
      if (location.origin !== origin || window.top !== window)
        throw Error("Origin changed");
      const fields = Array.from(document.querySelectorAll("input")).filter(
        (field) =>
          field.getClientRects().length > 0 &&
          !field.disabled &&
          !field.readOnly &&
          ["text", "tel", "number"].includes(field.type) &&
          field.value === "" &&
          (field.autocomplete === "one-time-code" ||
            /\b(?:code|otp)\b/i.test(
              [
                field.name,
                field.id,
                field.placeholder,
                field.getAttribute("aria-label"),
                ...Array.from(field.labels ?? []).map((x) => x.textContent),
              ].join(" "),
            )),
      );
      if (fields.length !== 1) throw Error("Ambiguous code field");
      const field = fields[0]!,
        form = field.form;
      if (!form || form.querySelector('input[type="password"]'))
        throw Error("Unsupported form");
      const buttons = Array.from(
        form.querySelectorAll('button,input[type="submit"]'),
      ).filter(
        (button) =>
          button.getClientRects().length > 0 &&
          (button as HTMLButtonElement).type === "submit" &&
          !(button as HTMLButtonElement).disabled,
      );
      if (buttons.length !== 1) throw Error("Ambiguous submit control");
      const action = new URL(form.action, location.href);
      if (
        action.origin !== origin ||
        (form.target && form.target !== "_self") ||
        /reset|recover|settings|security|payment|transfer/i.test(
          location.pathname + " " + action.pathname,
        )
      )
        throw Error("Unsupported destination");
      for (const checkbox of Array.from(
        form.querySelectorAll<HTMLInputElement>(
          'input[type="checkbox"]:checked',
        ),
      )) {
        const label = Array.from(checkbox.labels ?? [])
          .map((x) => x.textContent ?? "")
          .join(" ");
        if (/trust.*device|remember.*device|remember me/i.test(label))
          checkbox.click();
      }
      form.setAttribute("data-absolute-verification-form", marker);
      field.setAttribute("data-absolute-verification-code", marker);
      buttons[0]!.setAttribute("data-absolute-verification-submit", marker);
      return {
        pathname: location.pathname,
        action: action.pathname,
        method: form.method,
      };
    },
    { origin: input.origin, marker },
  );
  return {
    id: input.id,
    origin: input.origin,
    operation: input.operation,
    submission: shape.method.toLowerCase() === "post" ? "native-post" : "spa",
    pathnames: [shape.pathname],
    formActionPathnames: [shape.action],
    formSelector: `[data-absolute-verification-form="${marker}"]`,
    codeSelector: `[data-absolute-verification-code="${marker}"]`,
    submitSelector: `[data-absolute-verification-submit="${marker}"]`,
  };
}

/** Conservative generic success check: expected account text AND a sign-out control.
 * May follow one unambiguous same-origin profile link supplied by the service.
 * A redirect alone is never success; unsupported account UIs return false.
 */
export async function verifyBrowserAccountSession(input: {
  page: VerificationPage & { goto(url: string): Promise<unknown> };
  origin: string;
  accountEmail: string;
}) {
  let menuOpened = false;
  async function inspect(openMenu = false) {
    return input.page.evaluate(
      ({ origin, email, openMenu }) => {
        if (location.origin !== origin)
          return { verified: false, links: [] as string[] };
        if (
          openMenu &&
          !Array.from(document.querySelectorAll<HTMLElement>("body *")).some(
            (e) =>
              e.children.length === 0 &&
              e.getClientRects().length > 0 &&
              /^(sign out|log out|logout|my account|profile|account settings)$/i.test(
                e.textContent?.trim() ?? "",
              ),
          )
        ) {
          const menus = Array.from(
            document.querySelectorAll<HTMLButtonElement>("button"),
          ).filter(
            (e) =>
              e.getClientRects().length > 0 &&
              !e.disabled &&
              /^(user|account|profile)( menu)?$/i.test(
                e.getAttribute("aria-label") ?? e.textContent?.trim() ?? "",
              ),
          );
          if (menus.length === 1) menus[0]!.click();
        }
        const identity = Array.from(
          document.querySelectorAll("span,p,div,a,li,dd,h1,h2,h3"),
        ).some((e) => e.textContent?.trim() === email);
        const signout = Array.from(
          document.querySelectorAll("a,button,[role=menuitem],div,span"),
        ).some((e) =>
          /^(sign out|log out|logout)$/i.test(e.textContent?.trim() ?? ""),
        );
        const codeVisible = Array.from(
          document.querySelectorAll("[data-absolute-verification-code]"),
        ).some((e) => e.getClientRects().length > 0);
        const links = Array.from(
          document.querySelectorAll<HTMLAnchorElement>("a[href]"),
        )
          .filter((a) => {
            const u = new URL(a.href);
            return (
              u.origin === origin &&
              /profile|my account|account settings/i.test(
                (a.textContent ?? "") + " " + u.pathname,
              ) &&
              !/billing|security|delete|password|logout|signout/i.test(
                u.pathname,
              )
            );
          })
          .map((a) => a.href);
        return {
          verified: identity && signout && !codeVisible,
          links: [...new Set(links)],
        };
      },
      { origin: input.origin, email: input.accountEmail, openMenu },
    );
  }
  for (let attempt = 0; attempt < 20; attempt++) {
    try {
      const openMenu = attempt >= 4 && !menuOpened;
      if (openMenu) menuOpened = true;
      if ((await inspect(openMenu)).verified) return true;
    } catch {
      /* navigation in progress */
    }
    await new Promise((resolve) => setTimeout(resolve, 500));
  }
  const snapshot = await inspect();
  if (snapshot.links.length === 1) await input.page.goto(snapshot.links[0]!);
  else {
    const opened = await input.page.evaluate(
      ({ origin }) => {
        if (location.origin !== origin) return false;
        const controls = Array.from(
          document.querySelectorAll<HTMLElement>(
            "a,button,[role=menuitem],div,span",
          ),
        ).filter(
          (e) =>
            e.children.length === 0 &&
            e.getClientRects().length > 0 &&
            /^(my account|profile|account settings)$/i.test(
              e.textContent?.trim() ?? "",
            ),
        );
        if (controls.length !== 1) return false;
        controls[0]!.click();
        return true;
      },
      { origin: input.origin },
    );
    if (!opened) return false;
  }
  for (let attempt = 0; attempt < 20; attempt++) {
    if ((await inspect()).verified) return true;
    await new Promise((resolve) => setTimeout(resolve, 500));
  }
  return false;
}

export {
  createExtensionVerificationPage,
  type ExtensionVerificationApi,
} from "./extension";
