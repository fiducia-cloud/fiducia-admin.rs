# fiducia-admin

The server-rendered **admin dashboard** for [fiducia.cloud](https://fiducia.cloud).
A Rust + axum web app that serves HTML — this is the *authenticated* app, distinct
from [`fiducia-backend`](https://github.com/fiducia-cloud/fiducia-backend.rs)
(the public marketing site). **Skeleton.**

## Two role-gated areas

| Area | Who | Backed by |
|------|-----|-----------|
| Account / org + members | any signed-in user | `fiducia-auth` (Supabase) |
| **API keys** (create/list/revoke) | any signed-in user | `fiducia-auth` |
| **Infra ops** (scale, nodes, shard placement) | **admins** | `fiducia-brain` |

It's a thin web tier: it renders HTML, but data + actions live in `fiducia-auth`
(accounts/keys) and `fiducia-brain` (infra). Auth is a Supabase session verified
through `fiducia-auth`.

## Routes

| Route | Purpose |
|-------|---------|
| `GET /login` | sign-in page (Supabase) |
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

Env: `PORT`, `FIDUCIA_AUTH_URL`, `FIDUCIA_BRAIN_URL`, `OTEL_EXPORTER_OTLP_ENDPOINT`.
Telemetry via [`fiducia-telemetry`](https://github.com/fiducia-cloud/fiducia-telemetry.rs).

## Related

- [`fiducia-auth.rs`](https://github.com/fiducia-cloud/fiducia-auth.rs) · [`fiducia-brain.rs`](https://github.com/fiducia-cloud/fiducia-brain.rs) · [`fiducia-backend.rs`](https://github.com/fiducia-cloud/fiducia-backend.rs)
