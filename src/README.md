# src — the admin dashboard server

The Rust source for `fiducia-admin`, a server-rendered admin web app on the MASH
stack (Maud + Axum + SeaORM + HTMX). It's a thin authenticated web tier: it renders
HTML, but the data and actions live in sibling services. Auth is a Supabase
session verified through `fiducia-auth`. The server exchanges login credentials
with Supabase and rejects identities without both a trusted operator role and an
enabled, subject-keyed record in the isolated admin database.

- **`main.rs`** — the binary entrypoint: builds the axum `Router`, wires the
  routes (`/login`, `/`, `/infra`, `/healthz`, plus the
  `/admin/ws` sync socket and `/api/admin/sync/{table}` write path), the
  hardening middleware, and the required ADMIN SeaORM connection (a separate DB from
  the customer plane). Also serves the vendored
  `htmx.min.js` / `fiducia-sync.js` assets compiled into the binary.
- **`request_security.rs`** — validates the exact configured admin `Host` and
  `Origin`, rejects same-site sibling origins, and signs/verifies
  credential-bound HMAC CSRF tokens.
- **`entity/`** — SeaORM models for the isolated admin Postgres schema.
- **`session.rs`** — resolves the caller's session (bearer header or
  release-prefixed host-only cookie) via `fiducia-auth` `GET /v1/me`, accepts
  only trusted `admin`/`operator` roles, distinguishes explicit bearer
  credentials from ambient cookies, and provides the debug-build-only local
  auth bypass. The sync write path binds each durable key to the canonical
  operator/write fingerprint and commits claim + mutation + outcome atomically.
- **`upstream.rs`** — the outbound HTTP calls to `fiducia-brain` (nodes /
  placement / scale); failures surface as
  explicit dependency errors instead of fabricated empty results.
- **`views.rs`** — the Maud HTML templates (layout, pages, and the HTMX
  swap-fragment helpers), with auto-escaping as the XSS guarantee.
