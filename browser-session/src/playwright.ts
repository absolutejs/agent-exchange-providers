import { lookup } from "node:dns/promises";
import { chromium, type Page, type ElementHandle } from "playwright-core";
import {
  isPublicNetworkAddress,
  pinnedPublicRequest,
} from "@absolutejs/egress/transport";
import type { BrowserSessionResource, BrowserSessionScope } from "./index";
/** Chromium factory for an isolated runner. Requires OS/container network limits
 * as defense in depth. All HTTP requests use ABS's pinned public-IP transport;
 * WebSockets, service workers and non-HTTPS requests are disabled. Never enable
 * tracing, videos, request-body logging or browser debugging outside loopback.
 */
export function createManagedChromiumLauncher(
  options: { executablePath?: string; maximumResponseBytes?: number } = {},
) {
  const maximumResponseBytes = options.maximumResponseBytes ?? 8 * 1024 * 1024;
  if (
    !Number.isSafeInteger(maximumResponseBytes) ||
    maximumResponseBytes < 1024 ||
    maximumResponseBytes > 32 * 1024 * 1024
  )
    throw Error("Invalid browser response limit");
  return async (input: {
    id: string;
    scope: BrowserSessionScope;
    signal: AbortSignal;
  }): Promise<BrowserSessionResource<Page>> => {
    input.signal.throwIfAborted();
    const origin = new URL(input.scope.serviceOrigin);
    if (
      origin.protocol !== "https:" ||
      origin.origin !== input.scope.serviceOrigin ||
      origin.port
    )
      throw Error("Exact HTTPS origin required");
    // A separate browser process per session, with the Chromium sandbox enabled.
    const server = await chromium.launchServer({
      headless: true,
      chromiumSandbox: true,
      host: "127.0.0.1",
      timeout: 30000,
      executablePath: options.executablePath,
      args: [
        "--disable-quic",
        "--disable-background-networking",
        "--force-webrtc-ip-handling-policy=disable_non_proxied_udp",
      ],
    });
    let closing: Promise<void> | undefined;
    const close = (): Promise<void> => {
      if (closing) return closing;
      closing = (async () => {
        input.signal.removeEventListener("abort", aborted);
        let timer: ReturnType<typeof setTimeout> | undefined;
        try {
          await Promise.race([
            server.close().catch(() => server.kill()),
            new Promise<void>((resolve, reject) => {
              timer = setTimeout(() => {
                server.kill().then(resolve, reject);
              }, 3000);
            }),
          ]);
        } finally {
          clearTimeout(timer);
        }
      })();
      return closing;
    };
    const aborted = () => {
      void close().catch(() => {});
    };
    input.signal.addEventListener("abort", aborted, { once: true });
    try {
      input.signal.throwIfAborted();
      const browser = await chromium.connect(server.wsEndpoint());
      const context = await browser.newContext({
        acceptDownloads: false,
        serviceWorkers: "block",
        viewport: { width: 1280, height: 800 },
      });
      await context.routeWebSocket("**/*", (socket) => socket.close());
      await context.route("**/*", async (route) => {
        try {
          input.signal.throwIfAborted();
          const request = route.request(),
            url = new URL(request.url());
          if (
            url.protocol !== "https:" ||
            url.username ||
            url.password ||
            (url.port && url.port !== "443")
          )
            throw Error();
          if (
            request.isNavigationRequest() &&
            request.frame() === request.frame().page().mainFrame() &&
            url.origin !== input.scope.serviceOrigin
          )
            throw Error();
          const addresses = await lookup(url.hostname, { all: true });
          if (
            !addresses.length ||
            addresses.some(({ address }) => !isPublicNetworkAddress(address))
          )
            throw Error();
          const body = request.postDataBuffer();
          if (body && body.length > 1024 * 1024) throw Error();
          const method = request.method();
          const response = await pinnedPublicRequest(
            new Request(url, {
              method,
              headers: await request.allHeaders(),
              body:
                ["GET", "HEAD"].includes(method) || !body
                  ? undefined
                  : Uint8Array.from(body),
              signal: AbortSignal.any([
                input.signal,
                AbortSignal.timeout(20000),
              ]),
            }),
            {
              hostname: url.hostname,
              address: addresses[0]!.address,
              maxResponseBytes: maximumResponseBytes,
            },
          );
          const headers = Object.fromEntries(response.headers);
          const cookies = response.headers.getSetCookie();
          if (cookies.length) headers["set-cookie"] = cookies.join("\n");
          // Node's raw transport does not decompress the body; preserve encoding.
          await route.fulfill({
            status: response.status,
            headers,
            body: Buffer.from(await response.arrayBuffer()),
          });
        } catch {
          await route.abort("blockedbyclient").catch(() => {});
        }
      });
      const page = await context.newPage();
      context.on("page", (popup) => {
        if (popup !== page) void popup.close().catch(() => {});
      });
      page.setDefaultTimeout(15000);
      await page.goto(input.scope.serviceOrigin, {
        waitUntil: "domcontentloaded",
        timeout: 30000,
      });
      input.signal.throwIfAborted();
      return { page, close };
    } catch {
      await close();
      throw Error("Managed browser could not start");
    }
  };
}
/** Human-only preview; OTP and password controls remain masked. No screenshot
 * is persisted or provided to the assistant model by this package. */
export async function maskedBrowserPreview(page: Page) {
  return page.screenshot({
    type: "jpeg",
    quality: 65,
    timeout: 5000,
    mask: [
      page.locator(
        'input[type="password"],input[autocomplete="one-time-code"],[data-absolute-verification-code]',
      ),
    ],
    maskColor: "#667085",
  });
}

export type BrowserFocus = {
  id: string | null;
  kind: "password" | "email" | "verification" | "text" | "none";
  editable: boolean;
  bounds: { x: number; y: number; width: number; height: number } | null;
};
const focusedFields = new WeakMap<
  Page,
  { id: string; element: ElementHandle<SVGElement | HTMLElement> }
>();
/** Fixed field categories and geometry only. Never returns field values, page
 * labels, surrounding text, or password length. IDs bind text to the exact DOM
 * element observed by the human, and expire on focus/document changes. */
export async function getBrowserFocus(page: Page): Promise<BrowserFocus> {
  const element = await page.$(":focus");
  const previous = focusedFields.get(page);
  const metadata =
    element &&
    (await element.evaluate((node) => {
      const input = node instanceof HTMLInputElement;
      const textarea = node instanceof HTMLTextAreaElement;
      if (!input && !textarea) return null;
      const type = input ? node.type : "text";
      if (
        ![
          "text",
          "password",
          "email",
          "search",
          "tel",
          "url",
          "number",
        ].includes(type)
      )
        return null;
      const rect = node.getBoundingClientRect();
      return {
        kind:
          type === "password"
            ? ("password" as const)
            : node.autocomplete === "one-time-code"
              ? ("verification" as const)
              : type === "email" || node.autocomplete === "username"
                ? ("email" as const)
                : ("text" as const),
        editable:
          !node.disabled && !node.readOnly && rect.width > 0 && rect.height > 0,
        bounds: {
          x: rect.x,
          y: rect.y,
          width: rect.width,
          height: rect.height,
        },
      };
    }));
  if (!element || !metadata?.editable) {
    await element?.dispose();
    await previous?.element.dispose();
    focusedFields.delete(page);
    return {
      id: null,
      kind: metadata?.kind ?? "none",
      editable: false,
      bounds: metadata?.bounds ?? null,
    };
  }
  const same =
    previous &&
    (await element
      .evaluate((node, prior) => node === prior, previous.element)
      .catch(() => false));
  if (same) {
    await element.dispose();
    return { ...metadata, id: previous.id };
  }
  await previous?.element.dispose();
  const id = crypto.randomUUID();
  focusedFields.set(page, { id, element });
  return { ...metadata, id };
}

export type BrowserHumanInput =
  | { type: "click"; x: number; y: number }
  | { type: "scroll"; deltaY: number }
  | { type: "text"; text: string; focusId: string }
  | { type: "key"; key: string };
/** Human-only controls. Values must never be persisted, audited, traced or sent
 * to a model. The host supplies the authenticated actor and serializes this with
 * verification using the session pool. No arbitrary JavaScript or navigation. */
export async function applyBrowserHumanInput(
  page: Page,
  input: BrowserHumanInput,
  expectedOrigin: string,
) {
  if (new URL(page.url()).origin !== expectedOrigin)
    throw Error("Browser destination changed");
  switch (input.type) {
    case "click":
      if (
        !Number.isFinite(input.x) ||
        !Number.isFinite(input.y) ||
        input.x < 0 ||
        input.x > 1280 ||
        input.y < 0 ||
        input.y > 800
      )
        throw Error("Invalid pointer position");
      await page.mouse.click(input.x, input.y);
      break;
    case "scroll":
      if (!Number.isFinite(input.deltaY) || Math.abs(input.deltaY) > 2000)
        throw Error("Invalid scroll distance");
      await page.mouse.wheel(0, input.deltaY);
      break;
    case "text":
      if (
        typeof input.text !== "string" ||
        input.text.length < 1 ||
        input.text.length > 4096
      )
        throw Error("Invalid text input");
      // Re-read focus before accepting private input. fill targets the captured
      // element, rather than whichever field gains focus during an async pause.
      const focus = await getBrowserFocus(page);
      const target = focusedFields.get(page);
      if (
        !input.focusId ||
        !focus.editable ||
        focus.id !== input.focusId ||
        !target
      )
        throw Error("Selected field changed; select it again");
      await target.element.fill(input.text);

      break;
    case "key":
      if (
        ![
          "Enter",
          "Tab",
          "Backspace",
          "Escape",
          "ArrowUp",
          "ArrowDown",
          "ArrowLeft",
          "ArrowRight",
          "Home",
          "End",
        ].includes(input.key)
      )
        throw Error("Unsupported key");
      await page.keyboard.press(input.key);
      break;
    default:
      throw Error("Unsupported browser input");
  }
}
