// Puppeteer browser E2E: boots the real axum admin server (dev session, no DB)
// and drives the dashboard, API-keys create, and infra-scale HTMX swap flows.
import assert from "node:assert/strict";
import { test } from "node:test";
import puppeteer from "puppeteer";
import { chromeExecutablePath, startAdmin } from "./admin-browser-harness.mjs";

test("puppeteer drives the admin dashboard, API keys, and infra scale flows", async (t) => {
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

  // Dashboard renders under the dev-admin session (no DB required).
  await page.goto(`${server.url}/`, { waitUntil: "networkidle0" });
  assert.match(await pageText(page), /Dashboard/);
  assert.match(await pageText(page), /Welcome/);

  // API keys: fill name, pick a scope, Create — htmx swaps the panel (no reload).
  await Promise.all([
    page.waitForNavigation({ waitUntil: "networkidle0" }),
    page.click('nav a[href="/keys"]'),
  ]);
  await page.type("input[name='name']", "Puppeteer issued admin key");
  await page.select("select[name='scope']", "locks:write");
  await Promise.all([
    page.click("form[action='/keys'] button[type='submit']"),
    page.waitForFunction(() =>
      document
        .querySelector("[data-keys-status]")
        ?.textContent?.includes("Puppeteer issued admin key"),
    ),
  ]);
  assert.match(await pageText(page), /Puppeteer issued admin key/);

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
