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

// Boots the real fiducia-admin (axum) via `cargo run`. The Rust build happens in
// the harness (no npm build step). It runs with ONLY the dev-session bypass and
// an explicitly empty DATABASE_URL, proving the dashboard renders fully with no
// admin DB. Set FIDUCIA_ADMIN_TEST_URL to run against an already-running server.
export function startAdmin() {
  return startServer({
    command: "cargo",
    args: ["run"],
    cwd: repoRoot,
    env: {
      FIDUCIA_ADMIN_DEV_SESSION: "admin",
      // Force the no-DB path regardless of the ambient shell — the E2E boots
      // with the dev session alone.
      DATABASE_URL: "",
    },
    readyPath: "/healthz",
    reuseUrlEnv: "FIDUCIA_ADMIN_TEST_URL",
    startupTimeoutMs: 180000,
  });
}
