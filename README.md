# fiducia-admin

The server-rendered, operator-only **admin dashboard** for
[fiducia.cloud](https://fiducia.cloud). It is a separate Rust deployment built
with Maud, Axum, SeaORM, and HTMX. It has its own host-only session cookie,
admin routes, database, realtime channel, and browser storage. Customer account
and API-key workflows live exclusively in the separate Rust MASH customer app,
`fiducia-backend.rs`. The static `fiducia-ui.web` repository is marketing only.

## Operator boundary

Every non-public route requires both a verified `admin` or `operator` role from
Supabase `app_metadata` (returned by `fiducia-auth /v1/me`) and a matching,
enabled operator record in the isolated admin database. The registry lookup uses
the immutable Supabase user id, never an email allowlist. Email addresses and
ordinary Supabase `authenticated` membership never grant admin access.

The sign-in form exchanges operator credentials directly with Supabase Auth,
then verifies the returned access token and trusted role through `fiducia-auth`
before issuing a host-only session cookie as
`HttpOnly; SameSite=Strict; Secure`. Release builds name it
`__Host-fiducia_admin_session`, so browsers reject sibling-domain cookie
collisions; debug builds retain the unprefixed name for explicit HTTP-local mode.

Cookie-authenticated mutations use a credential-bound HMAC CSRF token and
require the exact configured admin `Origin` and `Host`; same-site sibling
subdomains are deliberately not trusted. Bearer-authenticated API requests are
not ambient-cookie CSRF targets, but all authenticated routes still require the
canonical `Host`, and writes reject a supplied non-admin `Origin`.

## Routes

| Route | Purpose |
|-------|---------|
| `GET/POST /login` | server-mediated Supabase sign-in |
| `POST /logout` | clear the admin-only session cookie |
| `GET /` | operator dashboard |
| `GET /infra` · `POST /infra/scale` | cluster operations |
| `GET /api/admin/sync/{table}?cursor=N&limit=M` | ordered catch-up changes (`changes`, `next_cursor`, `has_more`) |
| `POST /api/admin/sync/{table}` | version-CAS mutation with mandatory `Idempotency-Key` |
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

After supplying the required service and database configuration below:

```bash
FIDUCIA_ADMIN_DEV_SESSION=admin cargo run    # browse http://127.0.0.1:8096
```

> **Security:** `FIDUCIA_ADMIN_DEV_SESSION` is a full auth bypass (any request
> becomes that user). It is honored **only in debug builds** — the code path is
> compiled out of release binaries entirely. A release binary ignores the
> variable and logs an error; no other variable can re-enable it.

The service fails startup when its admin-plane Postgres connection is unavailable.
The canonical schema must be applied before serving traffic; missing audit, sync,
or idempotency relations fail closed when their routes use them. Upstream failures
return an explicit dependency error rather than fabricated empty data.
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
| `FIDUCIA_ADMIN_ORIGIN` | origin | no | Exact public admin origin used for `Host`/`Origin` enforcement (scheme + authority only); release builds require HTTPS. | debug: `http://127.0.0.1:$PORT`; release: required |
| `FIDUCIA_ADMIN_CSRF_SECRET` | string | **yes** | HMAC key for credential-bound CSRF tokens; at least 32 bytes. Required in release builds. | debug-only fixed key; release: required |
| `PORT` | integer | no | Listen port. | `8096` |
| `OTEL_EXPORTER_OTLP_ENDPOINT` | string | no | OpenTelemetry collector endpoint (optional). | telemetry off |
| `TEST_DATABASE_URL` | string | **yes** (creds) | Postgres URL for the DB-backed integration test only; unset → that test skips. | — (tests only) |
| `FIDUCIA_ADMIN_DEV_SESSION` | `user`\|`admin` | no | **INSECURE** — full auth bypass with a fabricated session; debug builds only, compiled out of release. | unset (secure) |
| `FIDUCIA_INSECURE_COOKIES` | bool | no | **INSECURE** — drops `Secure` from admin cookies for plain-HTTP development; debug builds only. | off → cookies are `Secure` |

### ⚠️ Insecure-mode flags — MUST be OFF/unset in production

`FIDUCIA_ADMIN_DEV_SESSION` and `FIDUCIA_INSECURE_COOKIES` are
local-development escape hatches. **Both are secure-by-default**: the former
requires the explicit value `user` or `admin`, while the latter requires `1` or
`true`. The auth bypass is **compiled out of release builds**, and release
binaries always emit `Secure` cookies even if the cookie escape variable is
present. **Never set either variable in production.**

### Bridging CLI flags to env (flags-2-env)

`scripts/with-flags2env.sh` maps `--flag` arguments to the env vars above via the
pinned [`flags-2-env`](https://github.com/ORESoftware/flags-2-env) submodule
(`vendor/flags-2-env`) and the `.cli-flags.toml` schema, then execs the command:

```bash
scripts/with-flags2env.sh --port 8096 -- cargo run
```

The schema is audited by the CLI flag contract step in CI
(`.github/workflows/ci.yml`). Build the pinned parser once with
`make -C vendor/flags-2-env all`.

### Reproducible container inputs

The container build fetches `fiducia-interfaces` at
`bbd8b52ce729ec34b0a9bff4dda6d0a448181797` and `fiducia-sync` at
`5d3660511b3bfe951d0a66f9d7737497e0d1401f`. Both build arguments must be
40-character lowercase commit ids; the Dockerfile checks out each commit in
detached mode and verifies `HEAD` before compiling with `cargo --locked`. CI uses
the same immutable refs. Update the pins only with the corresponding schema,
generated browser bundle, and test results in one reviewed change.

## Security

Hardening in place (verified this audit):

- **Secure-by-default flags.** Both insecure-mode toggles default to the safe
  value and are ineffective in release binaries (see the callout).
- **Transport / session.** The host-specific session cookie is
  `HttpOnly; SameSite=Strict; Secure` by default and uses the browser-enforced
  `__Host-` prefix in release builds. Admin authorization comes only from the
  `fiducia-auth`-verified `admin` or `operator` role copied from trusted Supabase
  `app_metadata`, plus the enabled subject-keyed operator registry.
- **Origin / CSRF boundary.** Login, logout, infra mutations, browser sync
  writes, and WebSocket handshakes reject sibling origins. Form and sync writes
  additionally require a constant-time-verified HMAC token bound to the exact
  verified credential; canonical-host checks also cover bearer API writes.
- **Complete route gate.** Dashboard, infra, sync catch-up/write, and WebSocket
  handshake paths all enforce the operator role. Customer account/API-key routes
  are not compiled into this service.
- **Templating.** All HTML is rendered with Maud, which HTML-escapes every
  dynamic interpolation by construction (stored-XSS defense, covered by tests).
- **Persistence.** SeaORM owns the Postgres connection and all application CRUD
  through typed admin-plane entities. Sync keys are bound to a canonical request
  fingerprint; key claim, row mutation, and committed version are one database
  transaction, and realtime publication occurs only after commit. Historical
  keys without a reconstructable fingerprint fail closed and must be retried
  with a newly minted key. Every mutation requires a nonempty durable key and an
  exact `base_version`; the guarded update returns `409 version_conflict` instead
  of overwriting a newer row. Catch-up uses a separate transactional
  `sync_sequence` cursor plus durable delete tombstones—per-row `version` is never
  used as a table-wide cursor. Raw SQL is limited to the single-snapshot catch-up
  UNION and applying the canonical schema in the opt-in real-Postgres test.
- **Request stack.** Body cap (64 KiB), 30 s request timeout, panic catch, CSP
  frame denial, `X-Frame-Options: DENY`, MIME-sniff prevention, and a no-referrer
  policy apply across the service. Dynamic/login responses are `no-store`; the
  isolated admin Postgres plane is never the customer DB.

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
