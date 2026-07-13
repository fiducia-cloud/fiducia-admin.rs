# fiducia-admin

The server-rendered **admin dashboard** for [fiducia.cloud](https://fiducia.cloud).
A Rust + axum web app that serves HTML. It is deployed independently from both
the customer portal (`fiducia-customer-ui.web`) and the customer API
(`fiducia-backend.rs`), with its own routes and session cookie.

## Admin-only areas

| Area | Who | Backed by |
|------|-----|-----------|
| Operator account / org context | **admins** | `fiducia-auth` (Supabase) |
| **API keys** (create/list/revoke) | **admins** | `fiducia-auth` |
| **Infra ops** (scale, nodes, shard placement) | **admins** | `fiducia-brain` |

It's a thin web tier: it renders HTML, but data + actions live in `fiducia-auth`
(accounts/keys) and `fiducia-brain` (infra). Auth is a Supabase session verified
through `fiducia-auth`. The login form sends email/password only to this admin
service. The service exchanges them with Supabase Auth, verifies the returned
access token with `fiducia-auth` `GET /v1/me`, and only then sets the HttpOnly
`fiducia_admin_session` cookie. It rejects valid customer identities that are not
on the admin allowlist. Raw access-token paste is not a login flow.

## Routes

| Route | Purpose |
|-------|---------|
| `GET /login` · `POST /login` | server-side Supabase sign-in |
| `POST /logout` | expire the admin-only session cookie |
| `GET /` | dashboard |
| `GET /account` | org + members |
| `GET /keys` · `POST /keys` · `POST /keys/{id}/revoke` | API key management |
| `GET /infra` · `POST /infra/scale` | cluster ops (admin only) |
| `GET /healthz` | liveness |

## Layout

| File | Responsibility |
|------|----------------|
| `src/main.rs` | routes + role gating (`require` / `require_admin`) |
| `src/views.rs` | server-rendered HTML templates |
| `src/session.rs` | Supabase session resolution (verified via fiducia-auth) |
| `src/upstream.rs` | HTTP calls to fiducia-auth / fiducia-brain |

## Run locally

```bash
FIDUCIA_ADMIN_DEV_SESSION=admin cargo run    # :8096, click through the UI without real auth
```

> **Security:** `FIDUCIA_ADMIN_DEV_SESSION` is a full auth bypass (any request
> becomes that user). It is honored **only in debug builds**. A release binary
> ignores it and logs an error, unless you also set
> `FIDUCIA_ALLOW_INSECURE_DEV_SESSION=1` — never do that in production.

Required service env: `DATABASE_URL`, `FIDUCIA_AUTH_URL`, `FIDUCIA_BRAIN_URL`,
and `FIDUCIA_INTERNAL_SECRET`. Real login additionally requires `SUPABASE_URL`
and `SUPABASE_ANON_KEY`. The Supabase service-role key is neither required nor
accepted. `PORT` and `OTEL_EXPORTER_OTLP_ENDPOINT` are optional.
The service fails startup without its Postgres audit/idempotency ledger, and
upstream failures return an explicit dependency error rather than empty data.
Telemetry via [`fiducia-telemetry`](https://github.com/fiducia-cloud/fiducia-telemetry.rs).

Customer sessions and admin sessions are deliberately not interchangeable. The
admin app uses a distinct cookie name, enforces `SameSite=Strict`, defaults to
`Secure`, verifies every request through `fiducia-auth`, and applies its own
admin allowlists before exposing infrastructure operations.

## Related

- [`fiducia-auth.rs`](https://github.com/fiducia-cloud/fiducia-auth.rs) · [`fiducia-brain.rs`](https://github.com/fiducia-cloud/fiducia-brain.rs) · [`fiducia-backend.rs`](https://github.com/fiducia-cloud/fiducia-backend.rs)
