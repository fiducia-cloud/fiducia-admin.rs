# src — the admin dashboard server

The Rust source for `fiducia-admin`, a server-rendered admin web app on the MASH
stack (Maud + Axum + SeaORM + HTMX). It's a thin authenticated web tier: it renders
HTML, but the data and actions live in sibling services. Auth is a Supabase
session verified through `fiducia-auth`. The server exchanges login credentials
with Supabase and rejects identities without a trusted operator role.

- **`main.rs`** — the binary entrypoint: builds the axum `Router`, wires the
  routes (`/login`, `/`, `/infra`, `/healthz`, plus the
  `/admin/ws` sync socket and `/api/admin/sync/{table}` write path), the
  hardening middleware, and the required ADMIN SeaORM connection (a separate DB from
  the customer plane). Also serves the vendored
  `htmx.min.js` / `fiducia-sync.js` assets compiled into the binary.
- **`entity/`** — SeaORM models for the isolated admin Postgres schema.
- **`session.rs`** — resolves the caller's session (bearer header or
  `fiducia_admin_session` cookie) via `fiducia-auth` `GET /v1/me`, accepts only
  trusted `admin`/`operator` roles, and provides the local-dev auth bypass.
- **`upstream.rs`** — the outbound HTTP calls to `fiducia-brain` (nodes /
  placement / scale); failures surface as
  explicit dependency errors instead of fabricated empty results.
- **`views.rs`** — the Maud HTML templates (layout, pages, and the HTMX
  swap-fragment helpers), with auto-escaping as the XSS guarantee.
