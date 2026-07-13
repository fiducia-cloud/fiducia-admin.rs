# tests — browser end-to-end tests

Node-driven browser E2E for the admin dashboard. Each spec reuses the URL in
`FIDUCIA_ADMIN_TEST_URL`, or boots the real axum binary through the shared Cargo
harness when all required database/upstream environment variables are present.
Missing external configuration produces an explicit skip: the app's fail-closed
admin DB boundary is never weakened for a test. The specs drive the operator
dashboard and infra-scale flows through headless Chrome, exercising HTMX swaps
end to end.

- **`admin-browser-harness.mjs`** — the shared boot recipe: Chrome discovery and
  the Cargo-driven server lifecycle come from `@fiducia/test-config`; only the
  admin-specific launch args and prerequisite check live here. Exports
  `startAdmin()` and `unavailableReason()`.
- **`admin-playwright.test.mjs`** — the same flows driven with Playwright.
- **`admin-puppeteer.test.mjs`** — the same flows driven with Puppeteer.

Two engines cover the same journey so the dashboard is verified against both.
Rust unit tests live inline with their modules in `src/`, not here. Those tests
always exercise exact Host/Origin enforcement, login and session CSRF binding,
cookie-versus-bearer provenance, release cookie invariants, canonical sync
fingerprints, and replay-mismatch rejection even when external browser
prerequisites are unavailable.
