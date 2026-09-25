import { test, expect } from "bun:test";
import { createBrowserSessionPool } from "../src";
const scope = {
  ownerId: "alice",
  accountRef: "mailbox-a",
  resourceRef: "shared-task-context",
  serviceOrigin: "https://service.example",
};
function fixture(
  options: {
    maximumSessions?: number;
    now?: () => number;
    authorize?: (input: any) => Promise<boolean>;
    launch?: (input: any) => Promise<any>;
  } = {},
) {
  let closed = 0;
  const pool = createBrowserSessionPool({
    authorize: async () => true,
    launch: async () => ({
      page: {},
      close: async () => {
        closed++;
      },
    }),
    ...options,
  });
  return { pool, closed: () => closed };
}
test("owner isolation, current authorization and metadata without page access", async () => {
  let allowed = true;
  const { pool, closed } = fixture({ authorize: async () => allowed });
  const session = await pool.create("alice", scope);
  expect("page" in session).toBe(false);
  await expect(pool.inspect("bob", session.id)).rejects.toThrow();
  allowed = false;
  await expect(
    pool.interact("alice", session.id, async () => {}),
  ).rejects.toThrow();
  await pool.stop();
  expect(closed()).toBe(1);
});
test("concurrent starts reserve capacity before launching", async () => {
  let release!: () => void;
  const gate = new Promise<void>((r) => (release = r));
  const { pool } = fixture({
    launch: async () => {
      await gate;
      return { page: {}, close: async () => {} };
    },
  });
  const starting = pool.create("alice", scope);
  await Promise.resolve();
  await expect(pool.create("alice", scope)).rejects.toThrow("capacity");
  release();
  await starting;
  await pool.stop();
});
test("verification excludes human interaction and can recheck revoked permission", async () => {
  let allowed = true,
    enter!: () => void,
    release!: () => void;
  const entered = new Promise<void>((r) => (enter = r)),
    gate = new Promise<void>((r) => (release = r));
  const { pool } = fixture({ authorize: async () => allowed });
  const session = await pool.create("alice", scope);
  const verification = pool.verify("alice", session.id, async (_page, ctx) => {
    enter();
    await gate;
    await ctx.assertAuthorized();
  });
  await entered;
  await expect(
    pool.interact("alice", session.id, async () => {}),
  ).rejects.toThrow("busy");
  allowed = false;
  release();
  await expect(verification).rejects.toThrow();
  await pool.stop();
});
test("expiration during an authorization wait cannot grant stale access", async () => {
  let now = 0;
  const { pool } = fixture({
    now: () => now,
    authorize: async (input) => {
      if (input.operation === "interact") now = 1_000_000;
      return true;
    },
  });
  const session = await pool.create("alice", scope);
  await expect(
    pool.interact("alice", session.id, async () => {
      throw Error("must not execute");
    }),
  ).rejects.toThrow("unavailable");
  await pool.stop();
});
test("shutdown closes a browser that finishes launching late", async () => {
  let release!: () => void,
    closed = 0;
  const gate = new Promise<void>((r) => (release = r));
  const { pool } = fixture({
    launch: async () => {
      await gate;
      return {
        page: {},
        close: async () => {
          closed++;
        },
      };
    },
  });
  const starting = pool.create("alice", scope);
  await Promise.resolve();
  const stopped = pool.stop();
  release();
  await expect(starting).rejects.toThrow();
  await stopped;
  expect(closed).toBe(1);
  expect(pool.metrics().occupied).toBe(0);
  await expect(pool.create("alice", scope)).rejects.toThrow("capacity");
});
test("unconfirmed termination retains its capacity slot", async () => {
  const { pool } = fixture({
    launch: async () => ({
      page: {},
      close: async () => {
        throw Error("process still alive");
      },
    }),
  });
  const session = await pool.create("alice", scope);
  await expect(pool.close("alice", session.id)).rejects.toThrow("termination");
  expect(pool.metrics().terminationFailures).toBe(1);
  await expect(pool.create("alice", scope)).rejects.toThrow("capacity");
});
test("only exact HTTPS origins can be bound", async () => {
  const { pool } = fixture();
  for (const serviceOrigin of [
    "http://service.example",
    "https://service.example/login",
    "https://name:password@service.example",
    "https://service.example:8443",
  ])
    await expect(
      pool.create("alice", { ...scope, serviceOrigin }),
    ).rejects.toThrow();
  await pool.stop();
});
