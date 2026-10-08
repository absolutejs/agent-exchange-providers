import { test, expect } from "bun:test";
import {
  createExtensionVerificationPage,
  type ExtensionVerificationApi,
} from "../src/extension";
test("extension adapter binds the clicked tab and top frame, rejects cross-origin navigation and removes listeners", async () => {
  let url = "https://service.example/code",
    calls = 0,
    updates = new Set<Function>(),
    removed = new Set<Function>();
  const api: ExtensionVerificationApi = {
    scripting: {
      executeScript: async (input) => {
        calls++;
        expect(input.target).toEqual({ tabId: 42, frameIds: [0] });
        expect(input.world).toBe("MAIN");
        return [{ frameId: 0, result: await input.func(input.args[0]) }];
      },
    },
    tabs: {
      get: async () => ({ url }),
      update: async (_id, input) => {
        url = input.url;
      },
      onUpdated: {
        addListener: (fn) => {
          updates.add(fn);
        },
        removeListener: (fn) => {
          updates.delete(fn);
        },
      },
      onRemoved: {
        addListener: (fn) => {
          removed.add(fn);
        },
        removeListener: (fn) => {
          removed.delete(fn);
        },
      },
    },
  };
  const page = createExtensionVerificationPage({
    api,
    tabId: 42,
    origin: "https://service.example",
  });
  expect(await page.evaluate((n) => n + 1, 1)).toBe(2);
  let navigations = 0;
  page.on("framenavigated", (f) => {
    expect(f).toBe(page.mainFrame());
    navigations++;
  });
  for (const fn of updates) fn(99, { status: "loading" });
  expect(navigations).toBe(0);
  for (const fn of updates) fn(42, { status: "loading" });
  expect(navigations).toBe(1);
  await expect(page.goto("https://other.example")).rejects.toThrow();
  url = "https://other.example";
  await expect(page.evaluate(() => 0, undefined)).rejects.toThrow();
  expect(calls).toBe(1);
  page.close();
  expect(updates.size).toBe(0);
  expect(removed.size).toBe(0);
  await expect(page.evaluate(() => 0, undefined)).rejects.toThrow();
});
