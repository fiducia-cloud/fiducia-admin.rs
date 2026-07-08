import assert from "node:assert/strict";
import { test } from "node:test";
import { chromium } from "playwright";
import { chromeExecutablePath, startAdmin } from "./admin-browser-harness.mjs";

test("playwright drives the admin dashboard, API keys, and infra scale flows", async (t) => {
  const server = await startAdmin();
  t.after(() => server.stop());

  const browser = await chromium.launch({
    executablePath: chromeExecutablePath(),
    headless: true,
  });
  t.after(() => browser.close());

  const page = await browser.newPage({ viewport: { height: 900, width: 1440 } });
  const pageErrors = [];
  page.on("pageerror", (error) => pageErrors.push(error.message));

  // Dashboard renders under the dev-admin session (no DB required).
  await page.goto(`${server.url}/`, { waitUntil: "networkidle" });
  await assertVisibleText(page, "Dashboard");
  await assertVisibleText(page, "Welcome");

  // API keys: fill name, pick a scope, Create — htmx swaps the panel in place.
  await page.locator('nav a[href="/keys"]').click();
  await assertVisibleText(page, "Create a key");
  await page.fill("input[name='name']", "Playwright issued admin key");
  await page.selectOption("select[name='scope']", "kv:write");
  await page.getByRole("button", { name: "Create" }).click();
  await assertVisibleText(page, "Playwright issued admin key");

  // Infra: set target_nodes, Apply — htmx swaps the infra panel in place.
  await page.locator('nav a[href="/infra"]').click();
  await assertVisibleText(page, "Cluster & infra");
  await assertVisibleText(page, "Scale");
  await page.fill("input[name='target_nodes']", "7");
  await page.getByRole("button", { name: "Apply" }).click();
  await assertVisibleText(page, "Scale to 7 nodes requested.");

  assert.deepEqual(pageErrors, []);
});

async function assertVisibleText(page, text) {
  await page.getByText(text).first().waitFor({ state: "visible" });
}
