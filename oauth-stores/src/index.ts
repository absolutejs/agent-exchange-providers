import type {
  OAuthAuthorizationSession,
  OAuthAuthorizationSessionStore,
} from "@absolutejs/agent-exchange-oauth";

const encoder = new TextEncoder();
const decoder = new TextDecoder("utf-8", { fatal: true });
const MAX_SESSION_BYTES = 16 * 1024;
const MAX_TTL_MS = 10 * 60_000;
const SEALING_CONTEXT = encoder.encode(
  "org.absolutejs.agent-exchange.oauth-session.v1",
);

const asArrayBuffer = (value: Uint8Array): ArrayBuffer =>
  Uint8Array.from(value).buffer;

export type OAuthSessionSealer = {
  readonly open: (sealed: Uint8Array) => Promise<Uint8Array>;
  readonly seal: (plaintext: Uint8Array) => Promise<Uint8Array>;
};

export type AtomicRedisSessionClient = {
  readonly putIfAbsent: (input: {
    readonly key: string;
    readonly ttlMs: number;
    readonly value: string;
  }) => Promise<boolean>;
  readonly take: (key: string) => Promise<string | undefined>;
};

export type PostgresSessionClient = {
  readonly query: <Row = Record<string, unknown>>(
    text: string,
    values: readonly unknown[],
  ) => Promise<{ readonly rowCount: number; readonly rows: readonly Row[] }>;
};

export const OAUTH_SESSION_POSTGRES_MIGRATION = `
CREATE TABLE IF NOT EXISTS absolute_agent_exchange_oauth_sessions (
  state_digest TEXT PRIMARY KEY,
  ciphertext TEXT NOT NULL,
  expires_at BIGINT NOT NULL,
  created_at BIGINT NOT NULL
);
CREATE INDEX IF NOT EXISTS absolute_agent_exchange_oauth_sessions_expiry_idx
  ON absolute_agent_exchange_oauth_sessions (expires_at);
`.trim();

const toBase64Url = (value: Uint8Array): string => {
  let binary = "";
  for (const byte of value) binary += String.fromCharCode(byte);
  return btoa(binary)
    .replaceAll("+", "-")
    .replaceAll("/", "_")
    .replace(/=+$/u, "");
};

const fromBase64Url = (value: string): Uint8Array => {
  if (!/^[A-Za-z0-9_-]+$/u.test(value) || value.length > 32 * 1024)
    throw new Error("OAuth session store failed");
  const padded = value
    .replaceAll("-", "+")
    .replaceAll("_", "/")
    .padEnd(Math.ceil(value.length / 4) * 4, "=");
  const binary = atob(padded);
  return Uint8Array.from(binary, (character) => character.charCodeAt(0));
};

const stateDigest = async (state: string): Promise<string> =>
  toBase64Url(
    new Uint8Array(
      await crypto.subtle.digest("SHA-256", encoder.encode(state)),
    ),
  );

const serialize = (session: OAuthAuthorizationSession): Uint8Array => {
  const bytes = encoder.encode(JSON.stringify(session));
  if (bytes.byteLength > MAX_SESSION_BYTES)
    throw new Error("OAuth session store failed");
  return bytes;
};

const deserialize = (
  bytes: Uint8Array,
  expectedState: string,
): OAuthAuthorizationSession => {
  if (bytes.byteLength === 0 || bytes.byteLength > MAX_SESSION_BYTES)
    throw new Error("OAuth session store failed");
  try {
    const value: unknown = JSON.parse(decoder.decode(bytes));
    if (typeof value !== "object" || value === null) throw new Error("invalid");
    const session = value as Partial<OAuthAuthorizationSession>;
    if (
      session.state !== expectedState ||
      typeof session.codeVerifier !== "string" ||
      !/^[A-Za-z0-9._~-]{43,128}$/u.test(session.codeVerifier) ||
      typeof session.exchangeId !== "string" ||
      session.exchangeId.length === 0 ||
      typeof session.expiresAt !== "number" ||
      !Number.isSafeInteger(session.expiresAt) ||
      typeof session.issuer !== "string" ||
      session.issuer.length === 0
    )
      throw new Error("invalid");
    return session as OAuthAuthorizationSession;
  } catch {
    throw new Error("OAuth session store failed");
  }
};

const validTtl = (session: OAuthAuthorizationSession, now: number): number => {
  const ttlMs = session.expiresAt - now;
  if (!Number.isSafeInteger(ttlMs) || ttlMs < 1 || ttlMs > MAX_TTL_MS)
    throw new Error("OAuth session store failed");
  return ttlMs;
};

export const createMemoryOAuthAuthorizationSessionStore =
  (): OAuthAuthorizationSessionStore => {
    const sessions = new Map<string, OAuthAuthorizationSession>();
    return Object.freeze({
      consume: async (state) => {
        const session = sessions.get(state);
        sessions.delete(state);
        return session;
      },
      save: async (session) => {
        if (sessions.has(session.state)) return false;
        sessions.set(session.state, Object.freeze({ ...session }));
        return true;
      },
    });
  };

export const createRedisOAuthAuthorizationSessionStore = (options: {
  readonly client: AtomicRedisSessionClient;
  readonly keyPrefix?: string;
  readonly now?: () => number;
  readonly sealer: OAuthSessionSealer;
}): OAuthAuthorizationSessionStore => {
  const prefix = options.keyPrefix ?? "absolute:agent-exchange:oauth:";
  if (prefix.length === 0 || prefix.length > 256)
    throw new Error("OAuth session store failed");
  const now = options.now ?? Date.now;
  const key = async (state: string) => `${prefix}${await stateDigest(state)}`;
  return Object.freeze({
    consume: async (state) => {
      const stored = await options.client.take(await key(state));
      if (stored === undefined) return undefined;
      return deserialize(
        await options.sealer.open(fromBase64Url(stored)),
        state,
      );
    },
    save: async (session) =>
      options.client.putIfAbsent({
        key: await key(session.state),
        ttlMs: validTtl(session, now()),
        value: toBase64Url(await options.sealer.seal(serialize(session))),
      }),
  });
};

export const createPostgresOAuthAuthorizationSessionStore = (options: {
  readonly client: PostgresSessionClient;
  readonly now?: () => number;
  readonly sealer: OAuthSessionSealer;
}): OAuthAuthorizationSessionStore => {
  const now = options.now ?? Date.now;
  return Object.freeze({
    consume: async (state) => {
      const result = await options.client.query<{
        readonly ciphertext: string;
      }>(
        "DELETE FROM absolute_agent_exchange_oauth_sessions WHERE state_digest = $1 RETURNING ciphertext",
        [await stateDigest(state)],
      );
      const ciphertext = result.rows[0]?.ciphertext;
      if (ciphertext === undefined) return undefined;
      return deserialize(
        await options.sealer.open(fromBase64Url(ciphertext)),
        state,
      );
    },
    save: async (session) => {
      validTtl(session, now());
      const result = await options.client.query(
        "INSERT INTO absolute_agent_exchange_oauth_sessions (state_digest, ciphertext, expires_at, created_at) VALUES ($1, $2, $3, $4) ON CONFLICT (state_digest) DO NOTHING",
        [
          await stateDigest(session.state),
          toBase64Url(await options.sealer.seal(serialize(session))),
          session.expiresAt,
          now(),
        ],
      );
      return result.rowCount === 1;
    },
  });
};

export const createWebCryptoOAuthSessionSealer = (
  key: CryptoKey,
): OAuthSessionSealer => {
  if (
    key.type !== "secret" ||
    key.extractable ||
    key.algorithm.name !== "AES-GCM" ||
    !key.usages.includes("encrypt") ||
    !key.usages.includes("decrypt")
  )
    throw new Error("session sealer requires a non-exportable AES-GCM key");
  return Object.freeze({
    open: async (sealed) => {
      if (
        sealed.byteLength < 12 + 16 ||
        sealed.byteLength > MAX_SESSION_BYTES + 64
      )
        throw new Error("OAuth session store failed");
      try {
        return new Uint8Array(
          await crypto.subtle.decrypt(
            {
              additionalData: SEALING_CONTEXT,
              iv: sealed.slice(0, 12),
              name: "AES-GCM",
              tagLength: 128,
            },
            key,
            asArrayBuffer(sealed.slice(12)),
          ),
        );
      } catch {
        throw new Error("OAuth session store failed");
      }
    },
    seal: async (plaintext) => {
      if (
        plaintext.byteLength === 0 ||
        plaintext.byteLength > MAX_SESSION_BYTES
      )
        throw new Error("OAuth session store failed");
      const iv = crypto.getRandomValues(new Uint8Array(12));
      const ciphertext = new Uint8Array(
        await crypto.subtle.encrypt(
          {
            additionalData: SEALING_CONTEXT,
            iv,
            name: "AES-GCM",
            tagLength: 128,
          },
          key,
          asArrayBuffer(plaintext),
        ),
      );
      const sealed = new Uint8Array(iv.byteLength + ciphertext.byteLength);
      sealed.set(iv);
      sealed.set(ciphertext, iv.byteLength);
      return sealed;
    },
  });
};
