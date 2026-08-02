// Playwright browser E2E: boots a fully isolated axum admin server and
// drives the operator-only dashboard and infra-scale HTMX flow.
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

  // Dashboard renders under the debug-only dev-admin session and carries the
  // production response hardening even on the local HTTP harness.
  const dashboardResponse = await page.goto(`${server.url}/`, {
    waitUntil: "networkidle",
  });
  assert.ok(dashboardResponse, "dashboard navigation must return an HTTP response");
  const dashboardHeaders = dashboardResponse.headers();
  assert.equal(dashboardHeaders["cache-control"], "no-store");
  assert.equal(dashboardHeaders["x-content-type-options"], "nosniff");
  assert.equal(dashboardHeaders["x-frame-options"], "DENY");
  assert.equal(dashboardHeaders["referrer-policy"], "same-origin");
  const csp = dashboardHeaders["content-security-policy"] ?? "";
  assert.match(csp, /default-src 'self'/);
  assert.match(csp, /script-src 'self' 'wasm-unsafe-eval'/);
  assert.match(csp, /frame-ancestors 'none'/);
  assert.match(csp, /base-uri 'none'/);
  assert.match(csp, /form-action 'self'/);
  assert.match(csp, /object-src 'none'/);
  assert.doesNotMatch(csp, /'unsafe-inline'/);
  assert.doesNotMatch(csp, /script-src[^;]*'unsafe-eval'/);

  await assertVisibleText(page, "Dashboard");
  await assertVisibleText(page, "Welcome");

  assert.equal(await page.locator('nav a[href="/keys"]').count(), 0);
  assert.equal(await page.locator('nav a[href="/account"]').count(), 0);

  // A context-sharing request proves that the dev-admin browser session is not
  // enough to authorize a mutation from a foreign Origin. When this harness owns
  // the strict control-plane stub, the rejected request must not reach it.
  const crossOrigin = await page.request.post(`${server.url}/infra/scale`, {
    headers: { origin: "https://attacker.example" },
    form: { csrf_token: "forged", target_nodes: "9" },
  });
  assert.equal(crossOrigin.status(), 403);
  assert.equal((await crossOrigin.json()).error, "admin_request_rejected");
  if (server.ownsControlPlane) {
    assert.equal(server.brainRequests.length, 0);
  }

  // Infra: set target_nodes, Apply — htmx swaps the infra panel in place.
  await page.locator('nav a[href="/infra"]').click();
  await assertVisibleText(page, "Cluster & infra");
  await assertVisibleText(page, "Scale");
  await page.fill("input[name='target_nodes']", "7");
  await page.getByRole("button", { name: "Apply" }).click();
  await assertVisibleText(page, "Scale to 7 nodes requested.");

  // The owned stub turns the browser journey into a contract test: every
  // admin-to-brain request carries the trusted-hop secret, and scale preserves
  // the replication baseline. External-server smoke runs still validate the UI
  // and browser boundary without pretending they can inspect another process.
  if (server.ownsControlPlane) {
    const scaleRequests = server.brainRequests.filter(
      (request) => request.method === "POST" && request.path === "/v1/scale",
    );
    assert.equal(scaleRequests.length, 1);
    assert.equal(scaleRequests[0].authorized, true);
    assert.deepEqual(scaleRequests[0].body, {
      target_nodes: 7,
      replication_factor: 3,
    });
    assert.ok(
      server.brainRequests
        .filter((request) => request.path.startsWith("/v1/"))
        .every((request) => request.authorized),
      "every admin-to-brain request must carry the trusted-hop credential",
    );
    assert.ok(
      server.brainRequests.some(
        (request) => request.method === "GET" && request.path === "/v1/nodes",
      ),
    );
    assert.ok(
      server.brainRequests.some(
        (request) => request.method === "GET" && request.path === "/v1/placement",
      ),
    );
  }

  assert.deepEqual(pageErrors, []);
});

async function assertVisibleText(page, text) {
  await page.getByText(text).first().waitFor({ state: "visible" });
}
