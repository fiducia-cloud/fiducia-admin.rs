# src — the admin dashboard server

The Rust source for `fiducia-admin`, a server-rendered admin web app on the MASH
stack (Maud + Axum + SQLx + HTMX). It's a thin authenticated web tier: it renders
HTML, but the data and actions live in sibling services. Auth is a Supabase
session verified through `fiducia-auth`.

- **`main.rs`** — the binary entrypoint: builds the axum `Router`, wires the
  routes (`/login`, `/`, `/account`, `/keys`, `/infra`, `/healthz`, plus the
  `/admin/ws` sync socket and `/api/admin/sync/{table}` write path), the
  hardening middleware, and the optional ADMIN Postgres pool (a separate DB from
  the customer plane; the app boots fully without it). Also serves the vendored
  `htmx.min.js` / `fiducia-sync.js` assets compiled into the binary.
- **`session.rs`** — resolves the caller's session (bearer header or
  `fiducia_session` cookie) via `fiducia-auth` `GET /v1/me`, computes the `admin`
  role, and provides the local-dev auth bypass (debug-only).
- **`upstream.rs`** — the outbound HTTP calls to `fiducia-auth` (accounts / API
  keys) and `fiducia-brain` (nodes / placement / scale); failures degrade to
  empty results so the page still renders.
- **`views.rs`** — the Maud HTML templates (layout, pages, and the HTMX
  swap-fragment helpers), with auto-escaping as the XSS guarantee.
