import { test, expect } from "bun:test";
import { chromium } from "playwright-core";
import { getBrowserFocus, applyBrowserHumanInput } from "../src/playwright";
test.skipIf(!process.env.BROWSER_TEST_EXECUTABLE)(
  "private input binds to the selected element and reports no field contents",
  async () => {
    const browser = await chromium.launch({
      executablePath: process.env.BROWSER_TEST_EXECUTABLE!,
      chromiumSandbox: true,
    });
    try {
      const page = await browser.newPage();
      await page.route("**/*", (route) =>
        route.fulfill({
          contentType: "text/html",
          body: '<input id="email" type="email"><input id="password" type="password"><input id="locked" readonly><button>Continue</button>',
        }),
      );
      await page.goto("https://input.example");
      expect((await getBrowserFocus(page)).editable).toBe(false);
      await page.locator("#email").focus();
      const email = await getBrowserFocus(page);
      expect(email.kind).toBe("email");
      expect((await getBrowserFocus(page)).id).toBe(email.id);
      await page.locator("#password").focus();
      await expect(
        applyBrowserHumanInput(
          page,
          { type: "text", text: "synthetic-private-value", focusId: email.id! },
          "https://input.example",
        ),
      ).rejects.toThrow("Selected field changed");
      expect(await page.locator("#password").inputValue()).toBe("");
      const password = await getBrowserFocus(page);
      expect(password.kind).toBe("password");
      await applyBrowserHumanInput(
        page,
        {
          type: "text",
          text: "synthetic-private-value",
          focusId: password.id!,
        },
        "https://input.example",
      );
      expect(await page.locator("#password").inputValue()).toBe(
        "synthetic-private-value",
      );
      expect(JSON.stringify(await getBrowserFocus(page))).not.toContain(
        "synthetic-private-value",
      );
      await applyBrowserHumanInput(
        page,
        {
          type: "text",
          text: "synthetic-private-value",
          focusId: password.id!,
        },
        "https://input.example",
      );
      expect(await page.locator("#password").inputValue()).toBe(
        "synthetic-private-value",
      );
      await page.reload();
      await page.locator("#password").focus();
      await expect(
        applyBrowserHumanInput(
          page,
          {
            type: "text",
            text: "synthetic-private-value",
            focusId: password.id!,
          },
          "https://input.example",
        ),
      ).rejects.toThrow("Selected field changed");
      await page.locator("#locked").focus();
      expect((await getBrowserFocus(page)).editable).toBe(false);
    } finally {
      await browser.close();
    }
  },
  30000,
);
