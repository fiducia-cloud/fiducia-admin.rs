// Real-browser/API-context coverage for the operator scale boundary. The test
// boots the real Axum admin app and proves invalid values are rejected before a
// request can cross the trusted admin-to-brain hop.
import assert from "node:assert/strict";
import { test } from "node:test";
import { chromium } from "playwright";
import {
  chromeExecutablePath,
  startAdmin,
  unavailableReason,
} from "./admin-browser-harness.mjs";

function scaleRequests(server) {
  return server.brainRequests.filter(
    (request) => request.method === "POST" && request.path === "/v1/scale",
  );
}

test(
  "playwright rejects forged, cross-origin, and invalid scale requests before the control plane",
  { timeout: 180_000 },
  async (t) => {
    const unavailable = unavailableReason();
    if (unavailable) {
      t.skip(unavailable);
      return;
    }

    const server = await startAdmin();
    let browser;
    let page;
    const pageErrors = [];

    t.after(async () => {
      await page?.close().catch(() => {});
      await browser?.close().catch(() => {});
      await server.stop();
    });

    browser = await chromium.launch({
      executablePath: chromeExecutablePath(),
      headless: true,
    });
    page = await browser.newPage({ viewport: { height: 900, width: 1440 } });
    page.on("pageerror", (error) => pageErrors.push(error.message));

    const infra = await page.goto(`${server.url}/infra`, {
      waitUntil: "networkidle",
    });
    assert.ok(infra, "infra navigation must return an HTTP response");
    assert.equal(infra.status(), 200);
    await page.getByText("Cluster & infra").first().waitFor();

    const scaleForm = page.locator('form[action="/infra/scale"]').first();
    const validCsrf = await scaleForm
      .locator('input[name="csrf_token"]')
      .inputValue();
    assert.ok(validCsrf, "scale form must carry an operator-bound CSRF token");

    const postScale = (csrfToken, targetNodes, origin = server.url) =>
      page.request.post(`${server.url}/infra/scale`, {
        headers: { origin },
        form: {
          csrf_token: csrfToken,
          target_nodes: String(targetNodes),
        },
        maxRedirects: 0,
      });

    // The browser may hold a valid dev-admin session, but neither a forged CSRF
    // value nor a foreign Origin may borrow it to reach the control plane.
    const forged = await postScale("forged", 7);
    assert.equal(forged.status(), 403);
    assert.equal((await forged.json()).error, "admin_request_rejected");

    const crossOrigin = await postScale(
      validCsrf,
      7,
      "https://attacker.example",
    );
    assert.equal(crossOrigin.status(), 403);
    assert.equal(
      (await crossOrigin.json()).error,
      "admin_request_rejected",
    );

    // Values below the replication floor and values that cannot fit the durable
    // audit row's signed i32 column are clean 400s. The rejection shape is stable
    // and does not expose internal persistence or control-plane details.
    for (const target of [0, 1, 2, 2_147_483_648]) {
      const response = await postScale(validCsrf, target);
      assert.equal(response.status(), 400, `target ${target} must be rejected`);
      assert.deepEqual(await response.json(), {
        error: "invalid_target_nodes",
        min: 3,
      });
    }

    // Values that cannot deserialize into u32 are rejected by the request
    // extractor before the handler. Accept Axum's 400/422 distinction across
    // dependency upgrades, while still requiring a non-success response.
    for (const target of ["-1", "not-a-number", "4294967296"]) {
      const response = await postScale(validCsrf, target);
      assert.ok(
        [400, 422].includes(response.status()),
        `malformed target ${target} must be rejected`,
      );
    }

    if (server.ownsControlPlane) {
      assert.equal(
        scaleRequests(server).length,
        0,
        "no rejected scale request may reach fiducia-brain",
      );

      // The exact replication-floor value remains valid. This positive control
      // proves the preceding zero-request assertion is caused by validation, not
      // by a broken harness or unreachable control plane.
      const accepted = await postScale(validCsrf, 3);
      assert.equal(accepted.status(), 303);
      assert.equal(accepted.headers().location, "/infra");
      const requests = scaleRequests(server);
      assert.equal(requests.length, 1);
      assert.equal(requests[0].authorized, true);
      assert.deepEqual(requests[0].body, {
        target_nodes: 3,
        replication_factor: 3,
      });
    }

    assert.deepEqual(pageErrors, []);
  },
);
