// Playwright E2E for the real ADMIN Supabase -> Shared Auth cutover. These
// journeys intentionally disable the debug admin bypass used by the dashboard
// smoke tests and assert the browser-visible cookie/session boundary.
import assert from "node:assert/strict";
import { test } from "node:test";
import { chromium } from "playwright";
import {
  browserAuthFixture,
  chromeExecutablePath,
  startDualAuthAdmin,
  unavailableReason,
} from "./admin-dual-auth-harness.mjs";

const ADMIN_COOKIE = "fiducia_admin_session";

test("playwright upgrades an admin provider login to a Shared Auth browser session", async (t) => {
  const unavailable = unavailableReason();
  if (unavailable) {
    t.skip(unavailable);
    return;
  }
  const server = await startDualAuthAdmin("admin");
  t.after(() => server.stop());
  const browser = await chromium.launch({
    executablePath: chromeExecutablePath(),
    headless: true,
  });
  t.after(() => browser.close());
  const context = await browser.newContext();
  const page = await context.newPage();
  const pageErrors = [];
  page.on("pageerror", (error) => pageErrors.push(error.message));

  await submitLogin(page, server.url);
  await page.waitForURL(`${server.url}/`);
  await page.getByRole("heading", { name: "Dashboard" }).waitFor();
  await page.getByText(browserAuthFixture.email, { exact: true }).waitFor();

  const cookies = await context.cookies(server.url);
  const sessionCookie = cookies.find((cookie) => cookie.name === ADMIN_COOKIE);
  assert.ok(sessionCookie, "successful login must create the admin session cookie");
  assert.equal(sessionCookie.httpOnly, true);
  assert.equal(sessionCookie.sameSite, "Strict");
  assert.equal(sessionCookie.value, server.auth.sharedSessionToken);
  assert.notEqual(
    sessionCookie.value,
    server.auth.adminProviderToken,
    "the raw Supabase provider token must never become the admin cookie",
  );
  assert.equal(
    cookies.some((cookie) => cookie.name === "fiducia_admin_login_csrf"),
    false,
    "the one-time login CSRF cookie must be cleared after upgrade",
  );

  assert.ok(
    server.authRequests.some(
      (request) =>
        request.method === "POST" && request.path === "/auth/v1/token",
    ),
  );
  assert.ok(
    server.authRequests.some(
      (request) =>
        request.method === "POST" &&
        request.path === "/auth/exchange" &&
        request.credential === "admin-provider",
    ),
  );
  assert.ok(
    server.authRequests.some(
      (request) =>
        request.method === "POST" &&
        request.path === "/auth/introspect" &&
        request.credential === "introspection-service" &&
        request.token === "admin-shared-session",
    ),
  );
  assert.ok(
    server.authRequests.some(
      (request) =>
        request.method === "GET" && request.path === "/.well-known/jwks.json",
    ),
    "the redirected dashboard must verify the upgraded Shared Auth JWT locally",
  );
  assert.deepEqual(pageErrors, []);
});

test("playwright rejects a customer-project token even when it carries an admin role", async (t) => {
  const unavailable = unavailableReason();
  if (unavailable) {
    t.skip(unavailable);
    return;
  }
  const server = await startDualAuthAdmin("customer-project");
  t.after(() => server.stop());
  const browser = await chromium.launch({
    executablePath: chromeExecutablePath(),
    headless: true,
  });
  t.after(() => browser.close());
  const context = await browser.newContext();
  const page = await context.newPage();

  const response = await submitLogin(page, server.url);
  assert.equal(response.status(), 200);
  await page
    .getByRole("alert")
    .filter({ hasText: "Shared Auth could not authorize this admin identity." })
    .waitFor();
  assert.equal(new URL(page.url()).pathname, "/login");

  const cookies = await context.cookies(server.url);
  assert.equal(
    cookies.some((cookie) => cookie.name === ADMIN_COOKIE),
    false,
    "a role name from the customer Supabase project must not mint an admin cookie",
  );
  assert.ok(
    server.authRequests.some(
      (request) =>
        request.path === "/auth/exchange" &&
        request.credential === "customer-provider",
    ),
  );
  assert.ok(
    server.authRequests.some(
      (request) =>
        request.path === "/auth/introspect" &&
        request.token === "customer-shared-session",
    ),
    "the negative journey must reach the coherent-exchange project check",
  );
});

test("playwright fails closed when login verification has no reusable session upgrade", async (t) => {
  const unavailable = unavailableReason();
  if (unavailable) {
    t.skip(unavailable);
    return;
  }
  const server = await startDualAuthAdmin("existing-shared-no-upgrade");
  t.after(() => server.stop());
  const browser = await chromium.launch({
    executablePath: chromeExecutablePath(),
    headless: true,
  });
  t.after(() => browser.close());
  const context = await browser.newContext();
  const page = await context.newPage();

  const response = await submitLogin(page, server.url);
  assert.equal(response.status(), 503);
  assert.match(
    (await page.locator("body").textContent()) ?? "",
    /shared_auth_session_upgrade_missing/,
  );

  const cookies = await context.cookies(server.url);
  assert.equal(
    cookies.some((cookie) => cookie.name === ADMIN_COOKIE),
    false,
    "an already-valid identity without an exchange upgrade must not be persisted",
  );
  assert.ok(
    server.authRequests.some(
      (request) => request.path === "/.well-known/jwks.json",
    ),
  );
  assert.equal(
    server.authRequests.some((request) => request.path === "/auth/exchange"),
    false,
    "a Shared Auth JWT is verified locally and cannot fabricate an exchange upgrade",
  );
});

async function submitLogin(page, baseUrl) {
  await page.goto(`${baseUrl}/login`, { waitUntil: "networkidle" });
  await page.fill('input[name="email"]', browserAuthFixture.email);
  await page.fill('input[name="password"]', browserAuthFixture.password);
  const responsePromise = page.waitForResponse(
    (response) =>
      response.request().method() === "POST" &&
      new URL(response.url()).pathname === "/login",
  );
  await page.getByRole("button", { name: "Sign in" }).click();
  return responsePromise;
}
