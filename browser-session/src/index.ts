export type BrowserSessionScope = Readonly<{
  ownerId: string;
  serviceOrigin: string;
  accountRef: string;
  resourceRef: string;
}>;
export type BrowserSessionInfo = BrowserSessionScope &
  Readonly<{
    id: string;
    expiresAt: number;
    state: "starting" | "ready" | "verifying" | "closing";
  }>;
export type BrowserSessionResource<Page> = {
  page: Page;
  close(): Promise<void>;
};
export type BrowserSessionAuthorization = {
  actorId: string;
  scope: BrowserSessionScope;
  sessionId?: string;
  operation: "create" | "inspect" | "interact" | "verify" | "close";
};
/** Ephemeral browser resources, not durable jobs. launch must isolate a browser;
 * close must terminate its process within a bounded time. Authenticate actors in
 * the host and persist business requests separately. Never replay uncertain login.
 */
export function createBrowserSessionPool<Page>(options: {
  authorize(input: BrowserSessionAuthorization): Promise<boolean>;
  launch(input: {
    id: string;
    scope: BrowserSessionScope;
    signal: AbortSignal;
  }): Promise<BrowserSessionResource<Page>>;
  maximumSessions?: number;
  lifetimeMs?: number;
  now?: () => number;
  onClosed?(info: BrowserSessionInfo): Promise<void>;
}) {
  const maximum = options.maximumSessions ?? 1,
    lifetime = options.lifetimeMs ?? 15 * 60_000;
  if (
    !Number.isSafeInteger(maximum) ||
    maximum < 1 ||
    maximum > 20 ||
    !Number.isSafeInteger(lifetime) ||
    lifetime < 1000 ||
    lifetime > 60 * 60_000
  )
    throw Error("Invalid browser session limits");
  const now = options.now ?? Date.now;
  type Entry = {
    info: BrowserSessionInfo;
    controller: AbortController;
    resource?: BrowserSessionResource<Page>;
    opening?: Promise<void>;
    closing?: Promise<void>;
    timer?: ReturnType<typeof setTimeout>;
    busy: boolean;
    settled?: Promise<void>;
    failedClose: boolean;
  };
  const entries = new Map<string, Entry>();
  let stopped = false;
  const snapshot = (entry: Entry): BrowserSessionInfo => ({ ...entry.info });
  async function closeEntry(entry: Entry) {
    if (entry.closing) return entry.closing;
    entry.info = { ...entry.info, state: "closing" };
    entry.controller.abort();
    clearTimeout(entry.timer);
    entry.closing = (async () => {
      await entry.opening?.catch(() => {});
      try {
        await entry.resource?.close();
      } catch {
        entry.failedClose = true;
        throw Error("Browser termination unconfirmed");
      }
      entries.delete(entry.info.id);
      await options.onClosed?.(snapshot(entry));
    })();
    return entry.closing;
  }
  async function access(
    actorId: string,
    id: string,
    operation: BrowserSessionAuthorization["operation"],
  ) {
    const entry = entries.get(id);
    if (
      !entry ||
      actorId !== entry.info.ownerId ||
      entry.info.state === "closing"
    )
      throw Error("Browser session unavailable");
    if (now() >= entry.info.expiresAt) {
      await closeEntry(entry);
      throw Error("Browser session expired");
    }
    if (
      !(await options.authorize({
        actorId,
        scope: entry.info,
        sessionId: id,
        operation,
      }))
    )
      throw Error("Browser session unavailable");
    if (entry.controller.signal.aborted || now() >= entry.info.expiresAt)
      throw Error("Browser session unavailable");
    return entry;
  }
  type Work<Result> = (
    page: Page,
    context: { signal: AbortSignal; assertAuthorized(): Promise<void> },
  ) => Promise<Result>;
  async function use<Result>(
    actorId: string,
    id: string,
    operation: "interact" | "verify",
    work: Work<Result>,
  ) {
    let entry = await access(actorId, id, operation);
    // A human click may arrive while its latest preview is being rendered.
    // Wait for that bounded operation rather than dropping the click. Never
    // queue human input behind a protected verification.
    if (entry.busy && entry.info.state === "ready" && entry.settled) {
      let timer: ReturnType<typeof setTimeout> | undefined;
      try {
        await Promise.race([
          entry.settled,
          new Promise<never>((_, reject) => {
            timer = setTimeout(
              () => reject(Error("Browser session busy")),
              6000,
            );
          }),
        ]);
      } finally {
        clearTimeout(timer);
      }
      entry = await access(actorId, id, operation);
    }
    if (entry.busy || !entry.resource || entry.info.state !== "ready")
      throw Error("Browser session busy");
    entry.busy = true;
    let release!: () => void;
    entry.settled = new Promise<void>((resolve) => {
      release = resolve;
    });
    if (operation === "verify")
      entry.info = { ...entry.info, state: "verifying" };
    try {
      return await work(entry.resource.page, {
        signal: entry.controller.signal,
        assertAuthorized: async () => {
          await access(actorId, id, operation);
        },
      });
    } finally {
      entry.busy = false;
      release();
      entry.settled = undefined;
      if (entry.info.state !== "closing")
        entry.info = { ...entry.info, state: "ready" };
    }
  }
  return {
    async create(actorId: string, scope: BrowserSessionScope) {
      const url = new URL(scope.serviceOrigin);
      if (
        typeof actorId !== "string" ||
        !actorId ||
        actorId.length > 512 ||
        actorId !== scope.ownerId ||
        typeof scope.resourceRef !== "string" ||
        !scope.resourceRef ||
        scope.resourceRef.length > 512 ||
        typeof scope.accountRef !== "string" ||
        !scope.accountRef ||
        scope.accountRef.length > 512 ||
        url.protocol !== "https:" ||
        url.origin !== scope.serviceOrigin ||
        url.username ||
        url.password ||
        url.port
      )
        throw Error("An owner and exact HTTPS service origin are required");
      const frozen = Object.freeze({
        ownerId: scope.ownerId,
        accountRef: scope.accountRef,
        resourceRef: scope.resourceRef,
        serviceOrigin: scope.serviceOrigin,
      });
      if (
        !(await options.authorize({
          actorId,
          scope: frozen,
          operation: "create",
        }))
      )
        throw Error("Browser session unavailable");
      if (stopped || entries.size >= maximum)
        throw Error("Browser capacity unavailable");
      const id = crypto.randomUUID();
      const entry: Entry = {
        info: { ...frozen, id, expiresAt: now() + lifetime, state: "starting" },
        controller: new AbortController(),
        busy: false,
        failedClose: false,
      };
      entries.set(id, entry);
      entry.timer = setTimeout(() => {
        void closeEntry(entry).catch(() => {});
      }, lifetime);
      entry.opening = (async () => {
        entry.resource = await options.launch({
          id,
          scope: frozen,
          signal: entry.controller.signal,
        });
      })();
      try {
        await entry.opening;
        entry.opening = undefined;
        if (
          entry.controller.signal.aborted ||
          stopped ||
          now() >= entry.info.expiresAt
        ) {
          await closeEntry(entry);
          throw Error("Browser session expired during startup");
        }
        entry.info = { ...entry.info, state: "ready" };
        return snapshot(entry);
      } catch {
        entry.opening = undefined;
        await closeEntry(entry);
        throw Error("Browser session could not start");
      }
    },
    async inspect(actorId: string, id: string) {
      return snapshot(await access(actorId, id, "inspect"));
    },
    /** Human input or masked screenshots only: do not expose this to a model. */
    interact: <Result>(actorId: string, id: string, work: Work<Result>) =>
      use(actorId, id, "interact", work),
    /** Bind approved origin/account/document; recheck immediately before submit. */
    verify: <Result>(actorId: string, id: string, work: Work<Result>) =>
      use(actorId, id, "verify", work),
    async close(actorId: string, id: string) {
      await closeEntry(await access(actorId, id, "close"));
    },
    async stop() {
      stopped = true;
      await Promise.all([...entries.values()].map(closeEntry));
    },
    metrics() {
      return {
        capacity: maximum,
        occupied: entries.size,
        stopped,
        terminationFailures: [...entries.values()].filter((e) => e.failedClose)
          .length,
      };
    },
  };
}

/** Safe public failure categories. Never expose provider messages, call logs,
 * field values, request bodies, URLs or credentials in client error responses. */
export function browserSessionFailure(
  error: unknown,
):
  | "session_expired"
  | "session_busy"
  | "session_unavailable"
  | "field_changed"
  | "origin_changed"
  | "invalid_input"
  | "input_timeout"
  | "operation_failed" {
  if (!(error instanceof Error)) return "operation_failed";
  const codes: Record<string, ReturnType<typeof browserSessionFailure>> = {
    "Browser session expired": "session_expired",
    "Browser session expired during startup": "session_expired",
    "Browser session busy": "session_busy",
    "Browser capacity unavailable": "session_busy",
    "Browser session unavailable": "session_unavailable",
    "Selected field changed; select it again": "field_changed",
    "Browser destination changed": "origin_changed",
    "Invalid text input": "invalid_input",
    "Invalid pointer position": "invalid_input",
    "Invalid scroll distance": "invalid_input",
    "Unsupported key": "invalid_input",
    "Unsupported browser input": "invalid_input",
  };
  return Object.hasOwn(codes, error.message)
    ? codes[error.message]!
    : error.name === "TimeoutError"
      ? "input_timeout"
      : "operation_failed";
}
