// Repo-local boot recipe for the admin dashboard E2E.
//
// The genuinely-shared pieces (Chrome discovery + the server lifecycle) come
// from @fiducia/test-config; only the admin-specific boot arguments live here,
// next to the app they boot. Specs stay in this repo's tests/.
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { startServer } from "@fiducia/test-config/harness";

export { chromeExecutablePath, launchOptions } from "@fiducia/test-config/harness";

const testsDir = dirname(fileURLToPath(import.meta.url));
const repoRoot = resolve(testsDir, "..");

const requiredSpawnEnv = [
  "DATABASE_URL",
  "FIDUCIA_AUTH_URL",
  "FIDUCIA_BRAIN_URL",
  "FIDUCIA_INTERNAL_SECRET",
  "SUPABASE_URL",
  "SUPABASE_PUBLISHABLE_KEY",
];

// The app deliberately fails closed without its admin database and upstream
// configuration. Reuse a fully configured server, or supply everything needed
// for the harness to spawn one; never weaken production startup for an E2E.
export function unavailableReason() {
  if (process.env.FIDUCIA_ADMIN_TEST_URL) return null;
  const missing = requiredSpawnEnv.filter((name) => !process.env[name]);
  return missing.length
    ? `set FIDUCIA_ADMIN_TEST_URL or configure: ${missing.join(", ")}`
    : null;
}

// Boots the real fiducia-admin (axum) via `cargo run`. The Rust build happens in
// the harness (no npm build step); the debug-only admin session bypass removes
// the auth-service dependency from requests, but startup and infra operations
// still exercise the configured admin DB and brain service.
export function startAdmin() {
  return startServer({
    command: "cargo",
    args: ["run"],
    cwd: repoRoot,
    env: {
      FIDUCIA_ADMIN_DEV_SESSION: "admin",
      FIDUCIA_INSECURE_COOKIES: "1",
    },
    readyPath: "/healthz",
    reuseUrlEnv: "FIDUCIA_ADMIN_TEST_URL",
    startupTimeoutMs: 180000,
  });
}
