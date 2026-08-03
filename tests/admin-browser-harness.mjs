// Repo-local boot recipe for the admin dashboard E2E.
//
// The genuinely-shared pieces (Chrome discovery + the server lifecycle) come
// from @fiducia/test-config; only the admin-specific boot arguments and strict
// control-plane stub live here, next to the app they boot. Specs stay in this
// repo's tests/.
import { createServer } from "node:http";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { startServer } from "@fiducia/test-config/harness";

export { chromeExecutablePath, launchOptions } from "@fiducia/test-config/harness";

const testsDir = dirname(fileURLToPath(import.meta.url));
const repoRoot = resolve(testsDir, "..");
const TEST_INTERNAL_SECRET =
  "fiducia-admin-browser-e2e-internal-secret-not-for-production";

const requiredSpawnEnv = ["DATABASE_URL"];

// The app deliberately fails closed without its isolated admin database. The
// harness owns deterministic loopback stubs for every other required startup
// dependency, so CI cannot silently skip because an unrelated service URL was
// omitted.
export function unavailableReason() {
  if (process.env.FIDUCIA_ADMIN_TEST_URL) return null;
  const missing = requiredSpawnEnv.filter((name) => !process.env[name]);
  return missing.length
    ? `set FIDUCIA_ADMIN_TEST_URL or configure: ${missing.join(", ")}`
    : null;
}

function startStubControlPlane() {
  const requests = [];
  const server = createServer((req, res) => {
    void handleStubRequest(req, res, requests).catch((error) => {
      const payload = JSON.stringify({
        ok: false,
        error: "stub_internal_error",
        detail: error instanceof Error ? error.message : String(error),
      });
      res.writeHead(500, {
        "content-type": "application/json",
        "content-length": Buffer.byteLength(payload),
      });
      res.end(payload);
    });
  });

  return new Promise((resolvePromise, rejectPromise) => {
    server.once("error", rejectPromise);
    server.listen(0, "127.0.0.1", () => {
      let stopped = false;
      resolvePromise({
        url: `http://127.0.0.1:${server.address().port}`,
        requests,
        stop: () =>
          new Promise((resolveStop, rejectStop) => {
            if (stopped) {
              resolveStop();
              return;
            }
            stopped = true;
            server.closeAllConnections?.();
            server.close((error) => {
              if (error) rejectStop(error);
              else resolveStop();
            });
          }),
      });
    });
  });
}

async function handleStubRequest(req, res, requests) {
  const respond = (status, body) => {
    const payload = JSON.stringify(body);
    res.writeHead(status, {
      "content-type": "application/json",
      "content-length": Buffer.byteLength(payload),
    });
    res.end(payload);
  };

  const path = new URL(req.url, "http://stub").pathname;
  if (req.method === "GET" && path === "/healthz") {
    respond(200, { ok: true });
    return;
  }

  const authorized =
    req.headers["x-fiducia-internal-auth"] === TEST_INTERNAL_SECRET;
  if (!authorized) {
    requests.push({ method: req.method, path, authorized, body: null });
    respond(401, { ok: false, error: "missing_internal_auth" });
    return;
  }

  if (req.method === "GET" && path === "/v1/nodes") {
    requests.push({ method: req.method, path, authorized, body: null });
    respond(200, { nodes: [] });
    return;
  }

  if (req.method === "GET" && path === "/v1/placement") {
    requests.push({ method: req.method, path, authorized, body: null });
    respond(200, { shards: [] });
    return;
  }

  if (req.method === "POST" && path === "/v1/scale") {
    const body = await readJsonBody(req);
    requests.push({ method: req.method, path, authorized, body });
    if (
      !Number.isInteger(body.target_nodes) ||
      body.target_nodes < 3 ||
      body.replication_factor !== 3
    ) {
      respond(400, { ok: false, error: "invalid_scale_contract" });
      return;
    }
    respond(200, { ok: true });
    return;
  }

  requests.push({ method: req.method, path, authorized, body: null });
  respond(404, {
    ok: false,
    error: `stub-control-plane: no route for ${req.method} ${path}`,
  });
}

async function readJsonBody(req) {
  const chunks = [];
  let bytes = 0;
  for await (const chunk of req) {
    bytes += chunk.length;
    if (bytes > 64 * 1024) {
      throw new Error("stub request body exceeded 64 KiB");
    }
    chunks.push(chunk);
  }
  const raw = Buffer.concat(chunks).toString("utf8");
  return raw ? JSON.parse(raw) : {};
}

// Boots the real fiducia-admin (axum) via `cargo run`. The Rust build happens in
// the harness (no npm build step); the debug-only admin session bypass removes
// the identity-provider dependency from requests. A strict local control-plane
// stub still verifies every trusted-hop request and records its typed payload.
export async function startAdmin() {
  if (process.env.FIDUCIA_ADMIN_TEST_URL) {
    return {
      url: process.env.FIDUCIA_ADMIN_TEST_URL.replace(/\/$/, ""),
      ownsControlPlane: false,
      brainRequests: [],
      stop: async () => {},
    };
  }

  const controlPlane = await startStubControlPlane();
  let server;
  const stop = async () => {
    const failures = [];
    try {
      await server?.stop();
    } catch (error) {
      failures.push(error);
    }
    try {
      await controlPlane.stop();
    } catch (error) {
      failures.push(error);
    }
    if (failures.length) {
      throw new AggregateError(failures, "admin E2E stack cleanup failed");
    }
  };

  try {
    server = await startServer({
      command: "cargo",
      args: ["run", "--locked"],
      cwd: repoRoot,
      env: {
        FIDUCIA_ADMIN_DEV_SESSION: "admin",
        FIDUCIA_INSECURE_COOKIES: "1",
        SHARED_AUTH_URL: controlPlane.url,
        SHARED_AUTH_ISSUER: "https://auth.fiducia.invalid",
        SHARED_AUTH_AUDIENCE: "fiducia-admin",
        SHARED_AUTH_INTROSPECT_SECRET: TEST_INTERNAL_SECRET,
        FIDUCIA_BRAIN_URL: controlPlane.url,
        FIDUCIA_INTERNAL_SECRET: TEST_INTERNAL_SECRET,
        SUPABASE_URL: controlPlane.url,
        SUPABASE_PUBLISHABLE_KEY: "stub-publishable-key",
      },
      readyPath: "/healthz",
      startupTimeoutMs: 300000,
    });
  } catch (error) {
    try {
      await stop();
    } catch (cleanupError) {
      throw new AggregateError(
        [error, cleanupError],
        "admin stack startup and cleanup failed",
      );
    }
    throw error;
  }

  return {
    url: server.url,
    ownsControlPlane: true,
    brainRequests: controlPlane.requests,
    stop,
  };
}
