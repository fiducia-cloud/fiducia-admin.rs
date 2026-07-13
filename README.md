# fiducia-admin

The server-rendered, operator-only **admin dashboard** for
[fiducia.cloud](https://fiducia.cloud). It is a separate Rust deployment built
with Maud, Axum, SeaORM, and HTMX. It has its own host-only session cookie,
admin routes, database, realtime channel, and browser storage. Customer account
and API-key workflows live exclusively in `fiducia-customer-ui.web` plus the
customer BFF.

## Operator boundary

Every non-public route requires both a verified `admin` or `operator` role from
Supabase `app_metadata` (returned by `fiducia-auth /v1/me`) and a matching,
enabled operator record in the isolated admin database. The registry lookup uses
the immutable Supabase user id, never an email allowlist. Email addresses and
ordinary Supabase `authenticated` membership never grant admin access.

The sign-in form exchanges operator credentials directly with Supabase Auth,
then verifies the returned access token and trusted role through `fiducia-auth`
before issuing `fiducia_admin_session` as `HttpOnly; SameSite=Strict; Secure`.

## Routes

| Route | Purpose |
|-------|---------|
| `GET/POST /login` | server-mediated Supabase sign-in |
| `POST /logout` | clear the admin-only session cookie |
| `GET /` | operator dashboard |
| `GET /infra` · `POST /infra/scale` | cluster operations |
| `GET/POST /api/admin/sync/{table}` | authorized admin-plane sync |
| `GET /admin/ws` | authorized admin-plane realtime stream |
| `GET /healthz` | liveness |

## Layout

| File | Responsibility |
|------|----------------|
| `src/main.rs` | routes + role gating (`require` / `require_admin`) |
| `src/entity/` | SeaORM models for the isolated admin Postgres schema |
| `src/views.rs` | server-rendered HTML templates |
| `src/session.rs` | Supabase session + trusted-role resolution through `fiducia-auth` |
| `src/upstream.rs` | operator-only HTTP calls to `fiducia-brain` |

## Run locally

```bash
FIDUCIA_ADMIN_DEV_SESSION=admin cargo run    # :8096, click through the UI without real auth
```

> **Security:** `FIDUCIA_ADMIN_DEV_SESSION` is a full auth bypass (any request
> becomes that user). It is honored **only in debug builds** — the code path is
> compiled out of release binaries entirely. A release binary ignores the
> variable and logs an error; no other variable can re-enable it.

The service fails startup without its Postgres audit/idempotency ledger, and
upstream failures return an explicit dependency error rather than empty data.
Telemetry via [`fiducia-telemetry`](https://github.com/fiducia-cloud/fiducia-telemetry.rs).

## Configuration (environment)

| Var | Type | Secret? | Meaning | Secure default (unset) |
|-----|------|---------|---------|------------------------|
| `DATABASE_URL` | string | **yes** (creds) | Admin-plane Postgres (its OWN DB — a security boundary, never the customer DB). Required at startup. | — (required) |
| `FIDUCIA_AUTH_URL` | string | no | Base URL of `fiducia-auth` for session verification. Required. | — (required) |
| `FIDUCIA_BRAIN_URL` | string | no | Base URL of `fiducia-brain` (infra ops). Required. | — (required) |
| `FIDUCIA_INTERNAL_SECRET` | string | **yes** (secret) | Cluster trusted-hop secret sent to the brain. Required; never logged. | — (required) |
| `SUPABASE_URL` | string | no | Supabase project URL used for operator sign-in. | — (required) |
| `SUPABASE_PUBLISHABLE_KEY` | string | no | Browser-safe Supabase publishable key used by the server-mediated password exchange. | — (required) |
| `PORT` | integer | no | Listen port. | `8096` |
| `OTEL_EXPORTER_OTLP_ENDPOINT` | string | no | OpenTelemetry collector endpoint (optional). | telemetry off |
| `TEST_DATABASE_URL` | string | **yes** (creds) | Postgres URL for the DB-backed integration test only; unset → that test skips. | — (tests only) |
| `FIDUCIA_ADMIN_DEV_SESSION` | bool | no | **INSECURE** — full auth bypass (`user`\|`admin` fabricated session); debug builds only, compiled out of release. | unset (secure) |
| `FIDUCIA_INSECURE_COOKIES` | bool | no | **INSECURE** — drops `Secure` from the session cookie (plain-http dev). | off → cookie is `Secure` |

### ⚠️ Insecure-mode flags — MUST be OFF/unset in production

`FIDUCIA_ADMIN_DEV_SESSION` and `FIDUCIA_INSECURE_COOKIES` are
local-development escape hatches. **Both are secure-by-default**:
each activates only when explicitly set to a truthy value (`1`/`true`), and an
unset variable always resolves to the safe behavior (no bypass, no all-admins,
`Secure` cookies). The dev-session bypass is additionally **compiled out of
release builds** — a release binary logs an error and ignores it, and there is
no environment variable that re-enables it. **Never set either of these in
production** — they disable authentication or transport protections.

### Bridging CLI flags to env (flags-2-env)

`scripts/with-flags2env.sh` maps `--flag` arguments to the env vars above via the
pinned [`flags-2-env`](https://github.com/ORESoftware/flags-2-env) submodule
(`vendor/flags-2-env`) and the `.cli-flags.toml` schema, then execs the command:

```bash
scripts/with-flags2env.sh --port 8096 -- cargo run
```

The schema is audited in CI (`.github/workflows/cli-flags.yml`). Build the pinned
parser once with `make -C vendor/flags-2-env all`.

## Security

Hardening in place (verified this audit):

- **Secure-by-default flags.** All three insecure-mode toggles above default to
  the safe value and cannot silently activate in production (see the callout).
- **Transport / session.** The host-specific `fiducia_admin_session` cookie is
  `HttpOnly; SameSite=Strict; Secure` by default. Admin authorization comes only
  from the `fiducia-auth`-verified `admin` or `operator` role copied from trusted
  Supabase `app_metadata`, plus the enabled subject-keyed operator registry.
- **Complete route gate.** Dashboard, infra, sync catch-up/write, and WebSocket
  handshake paths all enforce the operator role. Customer account/API-key routes
  are not compiled into this service.
- **Templating.** All HTML is rendered with Maud, which HTML-escapes every
  dynamic interpolation by construction (stored-XSS defense, covered by tests).
- **Persistence.** SeaORM owns the Postgres connection and all application CRUD
  through typed admin-plane entities. Raw SQL is limited to applying the
  canonical schema in the opt-in real-Postgres integration test.
- **Request stack.** Body cap (64 KiB), 30 s request timeout, and a panic-catch
  layer are applied to every route; the isolated admin Postgres plane is never
  the customer DB.

Accepted advisories (no clean in-semver fix; recorded in `.cargo/audit.toml`
with rationale, `cargo audit` runs clean):

- **`rsa` RUSTSEC-2023-0071** (Marvin timing side-channel) — present only in the
  inactive MySQL side of SeaORM's transitive SQLx dependency graph; this service
  enables only PostgreSQL, so the RSA code is not compiled.
- **`proc-macro-error` RUSTSEC-2024-0370** (unmaintained) — build-time only (via
  `maud_macros`), never linked into the running binary.
- **`proc-macro-error2` RUSTSEC-2026-0173** (unmaintained) — build-time only (via
  SeaORM's derive macros), never linked into the running binary.

## Related

- [`fiducia-auth.rs`](https://github.com/fiducia-cloud/fiducia-auth.rs) · [`fiducia-brain.rs`](https://github.com/fiducia-cloud/fiducia-brain.rs) · [`fiducia-backend.rs`](https://github.com/fiducia-cloud/fiducia-backend.rs)
