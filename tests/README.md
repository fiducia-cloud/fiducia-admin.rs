# tests — browser end-to-end tests

Node-driven browser E2E for the admin dashboard. Each spec boots the real axum
binary (via `cargo run` with only the dev-session bypass and an empty
`DATABASE_URL`, proving the UI renders with no admin DB) and drives the dashboard,
operator dashboard and infra-scale flows through a headless Chrome — exercising the HTMX
progressive-enhancement swaps end to end.

- **`admin-browser-harness.mjs`** — the shared boot recipe: Chrome discovery and
  the `cargo run` server lifecycle come from `@fiducia/test-config`; only the
  admin-specific launch args live here. Exports `startAdmin()`.
- **`admin-playwright.test.mjs`** — the same flows driven with Playwright.
- **`admin-puppeteer.test.mjs`** — the same flows driven with Puppeteer.

Two engines cover the same journey so the dashboard is verified against both.
Rust unit tests live inline with their modules in `src/`, not here.
