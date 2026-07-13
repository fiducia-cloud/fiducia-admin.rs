# src — the admin dashboard server

The Rust source for `fiducia-admin`, a server-rendered admin web app on the MASH
stack (Maud + Axum + SQLx + HTMX). It's a thin authenticated web tier: it renders
HTML, but the data and actions live in sibling services. The server exchanges
login credentials with Supabase, verifies the session through `fiducia-auth`,
and rejects identities without the separately configured admin role.

- **`main.rs`** — the binary entrypoint: builds the axum `Router`, wires the
  routes (`/login`, `/`, `/account`, `/keys`, `/infra`, `/healthz`, plus the
  `/admin/ws` sync socket and `/api/admin/sync/{table}` write path), the
  hardening middleware, and the required ADMIN Postgres pool (a separate DB from
  the customer plane). Also serves the vendored
  `htmx.min.js` / `fiducia-sync.js` assets compiled into the binary.
- **`session.rs`** — resolves the caller's session (bearer header or
  `fiducia_admin_session` cookie) via `fiducia-auth` `GET /v1/me`, computes the `admin`
  role, and provides the local-dev auth bypass (debug-only).
- **`upstream.rs`** — the outbound HTTP calls to `fiducia-auth` (accounts / API
  keys) and `fiducia-brain` (nodes / placement / scale); failures surface as
  explicit dependency errors instead of fabricated empty results.
- **`views.rs`** — the Maud HTML templates (layout, pages, and the HTMX
  swap-fragment helpers), with auto-escaping as the XSS guarantee.
