// Playwright browser E2E: boots or reuses a fully configured axum admin server
// and drives the isolated operator account and infra-scale HTMX flows.
import assert from "node:assert/strict";
import { test } from "node:test";
import { chromium } from "playwright";
import {
  chromeExecutablePath,
  startAdmin,
  unavailableReason,
} from "./admin-browser-harness.mjs";

test("playwright drives the isolated admin dashboard and infra scale flow", async (t) => {
  const unavailable = unavailableReason();
  if (unavailable) {
    t.skip(unavailable);
    return;
  }
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

  // Dashboard renders under the debug-only dev-admin session.
  await page.goto(`${server.url}/`, { waitUntil: "networkidle" });
  await assertVisibleText(page, "Dashboard");
  await assertVisibleText(page, "Welcome");

  assert.equal(await page.locator('nav a[href="/keys"]').count(), 0);
  assert.equal(await page.locator('nav a[href="/account"]').count(), 0);

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
