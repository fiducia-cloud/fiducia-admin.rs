// Puppeteer browser E2E: boots or reuses a fully configured axum admin server
// and drives the isolated operator account and infra-scale HTMX flows.
import assert from "node:assert/strict";
import { test } from "node:test";
import puppeteer from "puppeteer";
import {
  chromeExecutablePath,
  startAdmin,
  unavailableReason,
} from "./admin-browser-harness.mjs";

test("puppeteer drives the isolated admin dashboard and infra scale flow", async (t) => {
  const unavailable = unavailableReason();
  if (unavailable) {
    t.skip(unavailable);
    return;
  }
  const server = await startAdmin();
  t.after(() => server.stop());

  const browser = await puppeteer.launch({
    executablePath: chromeExecutablePath(),
    headless: "new",
  });
  t.after(() => browser.close());

  const page = await browser.newPage();
  await page.setViewport({ height: 900, width: 1440 });
  const pageErrors = [];
  page.on("pageerror", (error) => pageErrors.push(error.message));

  // Dashboard renders under the debug-only dev-admin session.
  await page.goto(`${server.url}/`, { waitUntil: "networkidle0" });
  assert.match(await pageText(page), /Dashboard/);
  assert.match(await pageText(page), /Welcome/);

  assert.equal(await page.$$('nav a[href="/keys"]').then((nodes) => nodes.length), 0);
  assert.equal(await page.$$('nav a[href="/account"]').then((nodes) => nodes.length), 0);

  // Infra: set target_nodes, Apply — htmx swaps the infra panel (no reload).
  await Promise.all([
    page.waitForNavigation({ waitUntil: "networkidle0" }),
    page.click('nav a[href="/infra"]'),
  ]);
  await page.$eval("input[name='target_nodes']", (el) => {
    el.value = "5";
  });
  await Promise.all([
    page.click("form[action='/infra/scale'] button[type='submit']"),
    page.waitForFunction(() =>
      document
        .querySelector("[data-scale-status]")
        ?.textContent?.includes("Scale to 5 nodes requested"),
    ),
  ]);
  assert.match(await pageText(page), /Scale to 5 nodes requested/);

  assert.deepEqual(pageErrors, []);
});

async function pageText(page) {
  return page.$eval("body", (body) => body.textContent ?? "");
}
