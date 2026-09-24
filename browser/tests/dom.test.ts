import { test, expect } from "bun:test";
import { createBrowserVerificationDestination } from "../src";
import type { AgentExchangeRequest } from "@absolutejs/agent-exchange";
// Optional real-browser conformance; routes are fulfilled locally, no provider traffic.
test.skipIf(!process.env.BROWSER_TEST_CDP || !process.env.PLAYWRIGHT_MODULE)(
  "real DOM: SPA/native submission, action mutation, duplicate fields and reload fail closed",
  async () => {
    const { chromium } = await import(process.env.PLAYWRIGHT_MODULE!);
    const browser = await chromium.connectOverCDP(
      process.env.BROWSER_TEST_CDP!,
    );
    const context = await browser.newContext();
    try {
      for (const scenario of [
        "native",
        "spa",
        "poison",
        "duplicate",
        "reload",
      ]) {
        const page = await context.newPage();
        let submissions = 0;
        await page.route("**/*", async (route: any) => {
          if (route.request().method() === "POST") {
            submissions++;
            await route.fulfill({
              contentType: "text/html",
              body: '<main data-verified="yes">Signed in</main>',
            });
            return;
          }
          await route.fulfill({
            contentType: "text/html",
            body: `<form method="${scenario === "native" ? "post" : "get"}" action="/verify"><input name="code"><button type="submit">Verify</button>${scenario === "duplicate" ? '<input name="code">' : ""}</form><script>const f=document.querySelector('form');${scenario === "spa" ? "f.addEventListener('submit',e=>{e.preventDefault();document.body.dataset.verified='yes';})" : ""}${scenario === "poison" ? "document.querySelector('input').addEventListener('input',()=>{f.action='https://wrong.example/verify';})" : ""}</script>`,
          });
        });
        await page.goto("https://verification-fixture.invalid/verify");
        const request: AgentExchangeRequest = {
          actionId: "action",
          assurance: {
            approval: "standing-mandate",
            credential: "token-confined-broker",
            execution: "purpose-bound",
          },
          createdAt: Date.now(),
          exchangeId: crypto.randomUUID(),
          expiresAt: Date.now() + 60000,
          maximumUses: 1,
          nonce: "nonce",
          processingMode: "tool-confined",
          purpose: "Fixture",
          recipient: {
            agentId: "owner",
            authority: "https://app.example",
            subject: "owner",
          },
          requester: {
            agentId: "requester",
            authority: "https://app.example",
            subject: "requester",
          },
          resource: {
            accountRef: "mailbox",
            challengeId: crypto.randomUUID(),
            operation: "login",
            origin: "https://verification-fixture.invalid",
            provider: "gmail",
          },
          risk: "authentication",
          secretKind: "email-one-time-code",
        };
        const create = () =>
          createBrowserVerificationDestination({
            page,
            request,
            tenantId: "fixture",
            profile: {
              id: "fixture",
              origin: "https://verification-fixture.invalid",
              operation: "login",
              submission: scenario === "native" ? "native-post" : "spa",
              pathnames: ["/verify"],
              formActionPathnames: ["/verify"],
              formSelector: "form",
              codeSelector: "input[name=code]",
              submitSelector: "button[type=submit]",
            },
            assertAuthorized: async () => {},
            verifySuccess: async () => {
              await page
                .locator("[data-verified=yes]")
                .waitFor({ timeout: 3000 });
              return true;
            },
          });
        if (scenario === "duplicate") {
          await expect(create()).rejects.toThrow();
          await page.close();
          continue;
        }
        const d = await create();
        if (scenario === "reload") await page.reload();
        const run = d.submit({
          plaintext: new TextEncoder().encode("482193"),
          request,
          tenantId: "fixture",
        });
        if (["native", "spa"].includes(scenario))
          await expect(run).resolves.toEqual({ status: "submitted" });
        else await expect(run).rejects.toThrow();
        expect(submissions).toBe(scenario === "native" ? 1 : 0);
        await page.close();
      }
    } finally {
      await context.close();
      await browser.close();
    }
  },
  30000,
);
