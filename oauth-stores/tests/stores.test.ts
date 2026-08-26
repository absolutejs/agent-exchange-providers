import { describe, expect, test } from "bun:test";
import {
  createMemoryOAuthAuthorizationSessionStore,
  createRedisOAuthAuthorizationSessionStore,
  createWebCryptoOAuthSessionSealer,
} from "../src";

const session = {
  codeVerifier: "a".repeat(43),
  exchangeId: "exchange-1",
  expiresAt: 61_000,
  issuer: "https://issuer.example",
  state: "state-secret",
} as const;

describe("OAuth authorization session stores", () => {
  test("memory sessions are collision-safe and consumed once", async () => {
    const store = createMemoryOAuthAuthorizationSessionStore();
    expect(await store.save(session)).toBe(true);
    expect(await store.save(session)).toBe(false);
    expect(await store.consume(session.state)).toEqual(session);
    expect(await store.consume(session.state)).toBeUndefined();
  });

  test("Redis adapter hashes state, seals values, sets TTL, and atomically takes", async () => {
    const key = await crypto.subtle.generateKey(
      { length: 256, name: "AES-GCM" },
      false,
      ["encrypt", "decrypt"],
    );
    const values = new Map<string, string>();
    let observedKey = "";
    const store = createRedisOAuthAuthorizationSessionStore({
      client: {
        putIfAbsent: async ({ key: storageKey, ttlMs, value }) => {
          expect(ttlMs).toBe(60_000);
          observedKey = storageKey;
          if (values.has(storageKey)) return false;
          values.set(storageKey, value);
          return true;
        },
        take: async (storageKey) => {
          const value = values.get(storageKey);
          values.delete(storageKey);
          return value;
        },
      },
      now: () => 1_000,
      sealer: createWebCryptoOAuthSessionSealer(key),
    });
    expect(await store.save(session)).toBe(true);
    expect(observedKey).not.toContain(session.state);
    expect(JSON.stringify([...values.values()])).not.toContain(
      session.codeVerifier,
    );
    expect(await store.consume(session.state)).toEqual(session);
    expect(await store.consume(session.state)).toBeUndefined();
  });
});
