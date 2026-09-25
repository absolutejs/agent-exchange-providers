import type { VerificationPage } from "./index";
/** Minimal MV3 surface; requires activeTab + scripting, never all_urls/history. */
export type ExtensionVerificationApi = {
  scripting: {
    executeScript<R, A>(input: {
      target: { tabId: number; frameIds: [0] };
      world: "MAIN";
      func: (arg: A) => R | Promise<R>;
      args: [A];
    }): Promise<{ frameId: number; result?: R }[]>;
  };
  tabs: {
    get(tabId: number): Promise<{ url?: string }>;
    update(tabId: number, options: { url: string }): Promise<unknown>;
    onUpdated: {
      addListener(
        fn: (id: number, change: { status?: string; url?: string }) => void,
      ): void;
      removeListener(
        fn: (id: number, change: { status?: string; url?: string }) => void,
      ): void;
    };
    onRemoved: {
      addListener(fn: (id: number) => void): void;
      removeListener(fn: (id: number) => void): void;
    };
  };
};
/** Construct only from an extension action click on the destination tab. Keep this
 * adapter in the extension worker: never accept remote JavaScript or expose the
 * general evaluate method to page messages/model tools. The existing destination
 * binds its document nonce and rechecks the owner-approved origin at submission.
 */
export function createExtensionVerificationPage(options: {
  api: ExtensionVerificationApi;
  tabId: number;
  origin: string;
}) {
  const origin = new URL(options.origin);
  if (
    origin.protocol !== "https:" ||
    origin.origin !== options.origin ||
    !Number.isSafeInteger(options.tabId) ||
    options.tabId < 0
  )
    throw Error("Invalid extension destination");
  const mainFrame = {},
    listeners = new Set<(frame: unknown) => void>();
  let closed = false;
  const changed = (id: number, change: { status?: string; url?: string }) => {
    if (
      id === options.tabId &&
      (change.status === "loading" || change.url !== undefined)
    )
      for (const fn of listeners) fn(mainFrame);
  };
  const removed = (id: number) => {
    if (id === options.tabId) {
      for (const fn of listeners) fn(mainFrame);
      close();
    }
  };
  function close() {
    if (closed) return;
    closed = true;
    listeners.clear();
    options.api.tabs.onUpdated.removeListener(changed);
    options.api.tabs.onRemoved.removeListener(removed);
  }
  options.api.tabs.onUpdated.addListener(changed);
  options.api.tabs.onRemoved.addListener(removed);
  async function assertOrigin() {
    if (closed) throw Error("Extension destination unavailable");
    const tab = await options.api.tabs.get(options.tabId);
    if (closed || !tab.url || new URL(tab.url).origin !== options.origin)
      throw Error("Extension destination changed");
  }
  const page: VerificationPage & {
    goto(url: string): Promise<unknown>;
    close(): void;
  } = {
    mainFrame: () => mainFrame,
    on: (_event, listener) => {
      listeners.add(listener);
    },
    off: (_event, listener) => {
      listeners.delete(listener);
    },
    async evaluate<R, A>(func: (arg: A) => R | Promise<R>, arg: A): Promise<R> {
      try {
        await assertOrigin();
        const result = await options.api.scripting.executeScript({
          target: { tabId: options.tabId, frameIds: [0] },
          world: "MAIN",
          func,
          args: [arg],
        });
        if (closed || result.length !== 1 || result[0]?.frameId !== 0)
          throw Error();
        return result[0].result as R;
      } catch {
        throw Error("Extension verification operation failed");
      }
    },
    async goto(url: string) {
      try {
        await assertOrigin();
        if (new URL(url).origin !== options.origin) throw Error();
        return await options.api.tabs.update(options.tabId, { url });
      } catch {
        throw Error("Extension destination navigation failed");
      }
    },
    close,
  };
  return page;
}
