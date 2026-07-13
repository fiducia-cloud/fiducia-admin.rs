# fiducia-admin

The server-rendered **admin dashboard** for [fiducia.cloud](https://fiducia.cloud).
A Rust + axum web app that serves HTML. It is deployed independently from both
the customer portal (`fiducia-customer-ui.web`) and the customer API
(`fiducia-backend.rs`), with its own routes and session cookie.

## Admin-only areas

| Area | Who | Backed by |
|------|-----|-----------|
| Operator account / org context | **admins** | `fiducia-auth` (Supabase) |
| **Infra ops** (scale, nodes, shard placement) | **admins** | `fiducia-brain` |

It's a thin web tier: it renders HTML, while identity lives in `fiducia-auth`
and infrastructure actions live in `fiducia-brain`. The login form sends
email/password only to this admin
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
| `GET /infra` · `POST /infra/scale` | cluster ops (admin only) |
| `GET /healthz` | liveness |

## Layout

| File | Responsibility |
|------|----------------|
| `src/main.rs` | routes + role gating (`require` / `require_admin`) |
| `src/views.rs` | server-rendered HTML templates |
| `src/session.rs` | Supabase session resolution (verified via fiducia-auth) |
| `src/upstream.rs` | HTTP calls to fiducia-brain |

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

## Configuration (environment)

| Var | Type | Secret? | Meaning | Secure default (unset) |
|-----|------|---------|---------|------------------------|
| `DATABASE_URL` | string | **yes** (creds) | Admin-plane Postgres (its OWN DB — a security boundary, never the customer DB). Required at startup. | — (required) |
| `FIDUCIA_AUTH_URL` | string | no | Base URL of `fiducia-auth` for session verification. Required. | — (required) |
| `FIDUCIA_BRAIN_URL` | string | no | Base URL of `fiducia-brain` (infra ops). Required. | — (required) |
| `FIDUCIA_INTERNAL_SECRET` | string | **yes** (secret) | Cluster trusted-hop secret sent to the brain. Required; never logged. | — (required) |
| `SUPABASE_URL` | string | no | Supabase project used for the server-side password exchange. | unset → real login unavailable |
| `SUPABASE_ANON_KEY` | string | browser-public | Supabase anon key used only for password exchange; never a service-role key. | unset → real login unavailable |
| `FIDUCIA_ADMIN_EMAILS` | string | no | Comma/space-separated email allowlist granted the `admin` role. | empty → **no admins** |
| `FIDUCIA_ADMIN_USER_IDS` | string | no | Comma-separated user-id allowlist granted the `admin` role. | empty → no admins |
| `PORT` | integer | no | Listen port. | `8096` |
| `OTEL_EXPORTER_OTLP_ENDPOINT` | string | no | OpenTelemetry collector endpoint (optional). | telemetry off |
| `TEST_DATABASE_URL` | string | **yes** (creds) | Postgres URL for the DB-backed integration test only; unset → that test skips. | — (tests only) |
| `FIDUCIA_ADMIN_ALL_USERS` | bool | no | **INSECURE** — grants `admin` to EVERY authenticated user. | off (secure) |
| `FIDUCIA_ADMIN_DEV_SESSION` | bool | no | **INSECURE** — full auth bypass (`user`\|`admin` fabricated session). | unset (secure) |
| `FIDUCIA_ALLOW_INSECURE_DEV_SESSION` | bool | no | **INSECURE** — forces the dev bypass ON in release builds. | off (secure) |
| `FIDUCIA_INSECURE_COOKIES` | bool | no | **INSECURE** — drops `Secure` from the session cookie (plain-http dev). | off → cookie is `Secure` |

### ⚠️ Insecure-mode flags — MUST be OFF/unset in production

`FIDUCIA_ADMIN_ALL_USERS`, `FIDUCIA_ADMIN_DEV_SESSION`,
`FIDUCIA_ALLOW_INSECURE_DEV_SESSION`, and `FIDUCIA_INSECURE_COOKIES` are
local-development escape hatches. **Every one of them is secure-by-default**:
each activates only when explicitly set to a truthy value (`1`/`true`), and an
unset variable always resolves to the safe behavior (no bypass, no all-admins,
`Secure` cookies). The dev-session bypass is additionally ignored in release
builds unless `FIDUCIA_ALLOW_INSECURE_DEV_SESSION=1` is set. **Never set any of
these in production** — they disable authentication or transport protections.

### Bridging CLI flags to env (flags-2-env)

`scripts/with-flags2env.sh` maps `--flag` arguments to the env vars above via the
pinned [`flags-2-env`](https://github.com/ORESoftware/flags-2-env) submodule
(`vendor/flags-2-env`) and the `.cli-flags.toml` schema, then execs the command:

```bash
FIDUCIA_ADMIN_EMAILS=you@acme.com scripts/with-flags2env.sh --port 8096 -- cargo run
```

The schema is audited in CI (`.github/workflows/cli-flags.yml`). Build the pinned
parser once with `make -C vendor/flags-2-env all`.

## Security

Hardening in place (verified this audit):

- **Secure-by-default flags.** All four insecure-mode toggles above default to
  the safe value and cannot silently activate in production (see the callout).
- **Transport / session.** The `fiducia_admin_session` cookie is
  `HttpOnly; SameSite=Strict; Secure`
  by default. Admin role comes only from the `fiducia-auth`-verified email/id
  allowlist (`FIDUCIA_ADMIN_EMAILS` / `FIDUCIA_ADMIN_USER_IDS`); no list → no
  admins.
- **Templating.** All HTML is rendered with Maud, which HTML-escapes every
  dynamic interpolation by construction (stored-XSS defense, covered by tests).
- **SQL.** Every query is parameterized (`$1…`) — no string-built SQL.
- **Request stack.** Body cap (64 KiB), 30 s request timeout, and a panic-catch
  layer are applied to every route; the isolated admin Postgres plane is never
  the customer DB.

Accepted advisories (no clean in-semver fix; recorded in `.cargo/audit.toml`
with rationale, `cargo audit` runs clean):

- **`rsa` RUSTSEC-2023-0071** (Marvin timing side-channel) — transitive via a
  feature-gated `sqlx` path; no patched release exists upstream. Re-evaluate
  when one lands.
- **`proc-macro-error` RUSTSEC-2024-0370** (unmaintained) — build-time only (via
  `maud_macros`), never linked into the running binary.

## Related

- [`fiducia-auth.rs`](https://github.com/fiducia-cloud/fiducia-auth.rs) · [`fiducia-brain.rs`](https://github.com/fiducia-cloud/fiducia-brain.rs) · [`fiducia-backend.rs`](https://github.com/fiducia-cloud/fiducia-backend.rs)
