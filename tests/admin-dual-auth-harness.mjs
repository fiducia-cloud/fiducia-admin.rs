import { spawnSync } from "node:child_process";
import { generateKeyPairSync, sign as signBytes } from "node:crypto";
import { createServer } from "node:http";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { startServer } from "@fiducia/test-config/harness";

export { chromeExecutablePath } from "@fiducia/test-config/harness";

const repoRoot = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const INTERNAL_SECRET =
  "fiducia-admin-browser-e2e-internal-secret-not-for-production";
const ISSUER = "https://auth.fiducia.invalid";
const AUDIENCE = "fiducia-admin";
const SUBJECT = "11111111-1111-4111-8111-111111111111";
const EMAIL = "operator@example.invalid";
const PASSWORD = "browser-e2e-password";
const SESSION_ID = "22222222-2222-4222-8222-222222222222";
const SCENARIOS = new Set([
  "admin",
  "customer-project",
  "existing-shared-no-upgrade",
]);

export const browserAuthFixture = Object.freeze({
  email: EMAIL,
  password: PASSWORD,
  subject: SUBJECT,
});

export function unavailableReason() {
  if (process.env.FIDUCIA_ADMIN_TEST_URL) {
    return "the dual-auth contract requires the repo-owned authority stub";
  }
  return process.env.DATABASE_URL ? null : "configure DATABASE_URL";
}

export async function startDualAuthAdmin(scenario) {
  if (!SCENARIOS.has(scenario)) {
    throw new Error(`unsupported admin browser auth scenario: ${scenario}`);
  }
  if (scenario === "admin") seedEnabledOperator();

  const authority = await startAuthority(scenario);
  let server;
  const stop = async () => {
    const failures = [];
    try {
      await server?.stop();
    } catch (error) {
      failures.push(error);
    }
    try {
      await authority.stop();
    } catch (error) {
      failures.push(error);
    }
    if (failures.length) {
      throw new AggregateError(failures, "admin dual-auth E2E cleanup failed");
    }
  };

  try {
    server = await startServer({
      command: "cargo",
      args: ["run", "--locked"],
      cwd: repoRoot,
      env: {
        FIDUCIA_ADMIN_DEV_SESSION: "",
        FIDUCIA_INSECURE_COOKIES: "1",
        SHARED_AUTH_URL: authority.url,
        SHARED_AUTH_ISSUER: ISSUER,
        SHARED_AUTH_AUDIENCE: AUDIENCE,
        SHARED_AUTH_INTROSPECT_SECRET: INTERNAL_SECRET,
        FIDUCIA_BRAIN_URL: authority.url,
        FIDUCIA_INTERNAL_SECRET: INTERNAL_SECRET,
        SUPABASE_URL: authority.url,
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
        "admin dual-auth startup and cleanup failed",
      );
    }
    throw error;
  }

  return {
    url: server.url,
    authRequests: authority.requests,
    auth: {
      adminProviderToken: authority.fixture.adminProviderToken,
      customerProviderToken: authority.fixture.customerProviderToken,
      sharedSessionToken: authority.fixture.sharedSessionToken,
    },
    stop,
  };
}

function startAuthority(scenario) {
  const requests = [];
  const fixture = createFixture(scenario);
  const server = createServer((req, res) => {
    void handleRequest(req, res, fixture, requests).catch((error) => {
      respond(res, 500, {
        error: "stub_internal_error",
        detail: error instanceof Error ? error.message : String(error),
      });
    });
  });

  return new Promise((resolvePromise, rejectPromise) => {
    server.once("error", rejectPromise);
    server.listen(0, "127.0.0.1", () => {
      let stopped = false;
      resolvePromise({
        url: `http://127.0.0.1:${server.address().port}`,
        fixture,
        requests,
        stop: () =>
          new Promise((resolveStop, rejectStop) => {
            if (stopped) return resolveStop();
            stopped = true;
            server.closeAllConnections?.();
            server.close((error) =>
              error ? rejectStop(error) : resolveStop(),
            );
          }),
      });
    });
  });
}

function createFixture(scenario) {
  const { privateKey, publicKey } = generateKeyPairSync("ec", {
    namedCurve: "P-256",
  });
  const kid = "fiducia-admin-browser-e2e";
  const jwk = {
    ...publicKey.export({ format: "jwk" }),
    alg: "ES256",
    kid,
    use: "sig",
  };
  const adminClaims = claims("fiducia-admin", ["operator"], "shared-admin-e2e");
  const customerClaims = claims(
    "fiducia-customer",
    ["admin"],
    "shared-customer-e2e",
  );
  return {
    scenario,
    jwk,
    adminProviderToken: "supabase-admin-provider-token",
    customerProviderToken: "supabase-customer-provider-token",
    adminClaims,
    customerClaims,
    sharedSessionToken: signJwt(privateKey, kid, adminClaims),
    customerSessionToken: signJwt(privateKey, kid, customerClaims),
  };
}

function claims(project, roles, sub) {
  const now = Math.floor(Date.now() / 1000);
  return {
    iss: ISSUER,
    aud: AUDIENCE,
    sub,
    provider: "supabase",
    provider_tenant: project,
    provider_subject: SUBJECT,
    project,
    supabase_user_id: SUBJECT,
    sid: SESSION_ID,
    email: EMAIL,
    email_verified: true,
    roles,
    iat: now,
    exp: now + 600,
  };
}

function signJwt(privateKey, kid, body) {
  const header = Buffer.from(
    JSON.stringify({ alg: "ES256", kid, typ: "JWT" }),
  ).toString("base64url");
  const payload = Buffer.from(JSON.stringify(body)).toString("base64url");
  const input = `${header}.${payload}`;
  const signature = signBytes("sha256", Buffer.from(input), {
    dsaEncoding: "ieee-p1363",
    key: privateKey,
  });
  return `${input}.${signature.toString("base64url")}`;
}

async function handleRequest(req, res, fixture, requests) {
  const path = new URL(req.url, "http://stub").pathname;
  if (req.method === "GET" && path === "/healthz") {
    respond(res, 200, { ok: true });
    return;
  }
  if (req.method === "GET" && path === "/.well-known/jwks.json") {
    requests.push({ method: req.method, path, credential: "none" });
    respond(res, 200, { keys: [fixture.jwk] });
    return;
  }
  if (req.method === "POST" && path === "/auth/v1/token") {
    const body = await readJson(req);
    requests.push({ method: req.method, path, credential: "publishable" });
    if (
      req.headers.apikey !== "stub-publishable-key" ||
      body.email !== EMAIL ||
      body.password !== PASSWORD
    ) {
      respond(res, 401, { error: "invalid_credentials" });
      return;
    }
    const accessToken =
      fixture.scenario === "admin"
        ? fixture.adminProviderToken
        : fixture.scenario === "customer-project"
          ? fixture.customerProviderToken
          : fixture.sharedSessionToken;
    respond(res, 200, { access_token: accessToken });
    return;
  }
  if (req.method === "GET" && path === "/auth/v1/user") {
    const token = bearer(req);
    requests.push({
      method: req.method,
      path,
      credential: label(token, fixture),
    });
    if (token === fixture.adminProviderToken) {
      await new Promise((resolvePromise) => setTimeout(resolvePromise, 150));
      respond(res, 200, {
        id: SUBJECT,
        email: EMAIL,
        email_confirmed_at: "2026-08-02T00:00:00Z",
      });
    } else {
      respond(res, 401, { error: "invalid_provider_token" });
    }
    return;
  }
  if (req.method === "POST" && path === "/auth/exchange") {
    const token = bearer(req);
    requests.push({
      method: req.method,
      path,
      credential: label(token, fixture),
    });
    if (token === fixture.adminProviderToken) {
      respond(
        res,
        200,
        exchange(fixture.sharedSessionToken, fixture.adminClaims),
      );
    } else if (token === fixture.customerProviderToken) {
      respond(
        res,
        200,
        exchange(fixture.customerSessionToken, fixture.customerClaims),
      );
    } else {
      respond(res, 401, { error: "invalid_provider_token" });
    }
    return;
  }
  if (req.method === "POST" && path === "/auth/introspect") {
    const serviceToken = bearer(req);
    const body = await readJson(req);
    requests.push({
      method: req.method,
      path,
      credential:
        serviceToken === INTERNAL_SECRET ? "introspection-service" : "invalid",
      token: label(body.token, fixture),
    });
    if (serviceToken !== INTERNAL_SECRET) {
      respond(res, 401, { active: false });
    } else if (body.token === fixture.sharedSessionToken) {
      respond(res, 200, introspection(fixture.adminClaims));
    } else if (body.token === fixture.customerSessionToken) {
      respond(res, 200, introspection(fixture.customerClaims));
    } else {
      respond(res, 200, { active: false });
    }
    return;
  }

  respond(res, 404, { error: `no stub route for ${req.method} ${path}` });
}

function exchange(accessToken, value) {
  return {
    access_token: accessToken,
    shared_user_id: value.sub,
    provider: value.provider,
    provider_tenant: value.provider_tenant,
    provider_subject: value.provider_subject,
    roles: value.roles,
  };
}

function introspection(value) {
  return {
    active: true,
    sub: value.sub,
    provider: value.provider,
    provider_tenant: value.provider_tenant,
    provider_subject: value.provider_subject,
    project: value.project,
    supabase_user_id: value.supabase_user_id,
    sid: value.sid,
    email: value.email,
    email_verified: value.email_verified,
    roles: value.roles,
  };
}

function bearer(req) {
  const value = req.headers.authorization;
  return typeof value === "string" && value.startsWith("Bearer ")
    ? value.slice(7)
    : "";
}

function label(token, fixture) {
  if (token === fixture.adminProviderToken) return "admin-provider";
  if (token === fixture.customerProviderToken) return "customer-provider";
  if (token === fixture.sharedSessionToken) return "admin-shared-session";
  if (token === fixture.customerSessionToken) return "customer-shared-session";
  return token ? "unknown" : "none";
}

function respond(res, status, value) {
  if (res.writableEnded) return;
  const body = JSON.stringify(value);
  res.writeHead(status, {
    "content-type": "application/json",
    "content-length": Buffer.byteLength(body),
  });
  res.end(body);
}

async function readJson(req) {
  const chunks = [];
  let bytes = 0;
  for await (const chunk of req) {
    bytes += chunk.length;
    if (bytes > 64 * 1024) throw new Error("stub body exceeded 64 KiB");
    chunks.push(chunk);
  }
  const body = Buffer.concat(chunks).toString("utf8");
  return body ? JSON.parse(body) : {};
}

function seedEnabledOperator() {
  const databaseUrl = process.env.DATABASE_URL;
  if (!databaseUrl) throw new Error("DATABASE_URL is required");
  const sql = `
    insert into operators (supabase_user_id, email, role, disabled)
    values ('${SUBJECT}', '${EMAIL}', 'operator', false)
    on conflict (supabase_user_id) do update
      set email = excluded.email,
          role = excluded.role,
          disabled = false;
  `;
  const result = spawnSync(
    "psql",
    [databaseUrl, "--set", "ON_ERROR_STOP=1", "--command", sql],
    { encoding: "utf8", env: process.env },
  );
  if (result.error) {
    throw new Error(`failed to launch psql: ${result.error.message}`);
  }
  if (result.status !== 0) {
    throw new Error(
      `failed to seed E2E operator: ${result.stderr || `psql exited ${result.status}`}`,
    );
  }
}
