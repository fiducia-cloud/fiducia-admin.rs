# fiducia-admin

The server-rendered, operator-only **admin dashboard** for
[fiducia.cloud](https://fiducia.cloud). It is a separate Rust deployment built
with Maud, Axum, SeaORM, and HTMX. It has its own host-only session cookie,
admin routes, database, realtime channel, and browser storage. Customer account
and API-key workflows live exclusively in the separate Rust MASH customer app,
`fiducia-customer.rs`. The static `fiducia-marketing.web` repository is marketing only.

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
| `GET /cluster` | cluster insight page (summary, shards, nodes, events) |
| `GET /cluster/{shards,nodes,events}` | polled htmx fragments (full page without `HX-Request`) |
| `GET /api/admin/cluster/{overview,shards,events,metrics}` | cluster insight as JSON for bearer/API callers |
| `GET /api/admin/sync/{table}?cursor=N&limit=M` | ordered catch-up changes (`changes`, `next_cursor`, `has_more`) |
| `POST /api/admin/sync/{table}` | version-CAS mutation with mandatory `Idempotency-Key` |
| `GET /admin/ws` | authorized admin-plane realtime stream |
| `GET /healthz` | liveness |

## Layout

| File | Responsibility |
|------|----------------|
| `src/main.rs` | routes + role gating (`require` / `require_admin`) |
| `src/cluster_insight.rs` | Cluster Insight clients: node observe fan-out, Loki event extraction, Prometheus queries |
| `src/entity/` | SeaORM models for the isolated admin Postgres schema |
| `src/views.rs` | server-rendered HTML templates |
| `src/session.rs` | Supabase session + trusted-role resolution through `fiducia-auth` |
| `src/upstream.rs` | operator-only HTTP calls to `fiducia-brain` |

## Cluster insight

`GET /cluster` is the read-only observability page for the coordination plane.
It renders three panels that poll their own htmx fragment endpoints
(`/cluster/shards` and `/cluster/nodes` every 5 s, `/cluster/events` every
15 s; each fragment route serves the full page to non-htmx requests, exactly
like the infra pattern). The same data is served as JSON under
`/api/admin/cluster/*` for bearer/API callers.

**Data sources** (all fetched per request; nothing is cached or persisted):

- **fiducia-brain** — `GET /v1/status` feeds the summary cards (cluster id,
  shard count × RF, placement generation, brain leader/HA/availability, node
  counts by health, placement gaps); `GET /v1/nodes` feeds the node registry
  table and, by default, node discovery. The overview API additionally returns
  `/v1/config` and `/v1/policies`. All brain calls present
  `FIDUCIA_INTERNAL_SECRET` in the `x-fiducia-internal-auth` trusted-hop header.
- **fiducia-node** — `GET /v1/observe/shards` and `GET /v1/observe/metrics`,
  fanned out **concurrently to every node** with a 3 s per-node timeout. These
  two paths are exempt from the node's org-scope middleware (they are node
  introspection with no tenant state — see fiducia-node `org_scope::is_exempt`),
  so the calls need only the internal-auth header, no `x-fiducia-org-id`.
  A down node never breaks the page: its fetch error is carried per node into
  the tables and the JSON (`node_observations[].error`). Per-shard rows are
  merged across all nodes' reports with the **leader's view winning** per shard
  (only the leader knows per-peer replication lag and quorum).
- **Loki** (optional, `FIDUCIA_LOKI_URL`) — the events panel runs one
  `query_range` over `{namespace="fiducia"}` with line filters, then parses
  each JSON log line in Rust (fiducia-telemetry's tracing JSON layer flattens
  event fields to the top level) and classifies raft leader transfers,
  elections/step-downs, check-quorum step-downs, brain membership changes
  (registered/draining/dead), and placement (re)assignments into typed events.
  `?since_minutes=` is clamped to `[1, 1440]`, default 30.
- **Prometheus** (optional, `FIDUCIA_PROMETHEUS_URL`) — the summary card runs
  the instant query `up{namespace="fiducia"}` and counts up targets (an empty
  result renders as a count of 0, since scrape config is deployment-specific);
  the metrics API adds a 15-minute range of the same query.
- **Grafana** (optional, `FIDUCIA_GRAFANA_PUBLIC_URL`) — when set, the events
  panel and the Prometheus card render best-effort Grafana Explore deep links
  with the exact LogQL/PromQL prefilled.

Node discovery: `FIDUCIA_NODE_URLS` (comma-separated base URLs) wins when set;
otherwise targets come from the brain's `/v1/nodes` — each node's heartbeated
`address` (`host:port`), normalized to `http://` when no scheme is given.

**Security posture:** every cluster page, fragment, and `/api/admin/cluster/*`
route sits behind the same operator gate as the rest of the app
(`require_admin` for HTML, `require_admin_api` for JSON: verified operator role
**and** enabled operator registry row). All routes are read-only GETs — no
mutation, no CSRF surface. The brain and node calls carry
`FIDUCIA_INTERNAL_SECRET`; Prometheus and Loki are unauthenticated in-cluster
services, which is why their URLs are optional, operator-supplied
configuration and their query results are rendered (HTML-escaped by Maud) but
never executed or persisted.

## Run locally

After supplying the required service and database configuration below:

```bash
FIDUCIA_ADMIN_DEV_SESSION=admin cargo run --locked    # browse http://127.0.0.1:8096
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
| `FIDUCIA_PROMETHEUS_URL` | string | no | Prometheus base URL (e.g. `http://dd-prometheus.observability.svc.cluster.local:9090`) for the Cluster Insight summary probe. Optional. | insight card shows "not configured" |
| `FIDUCIA_LOKI_URL` | string | no | Loki base URL (e.g. `http://dd-loki.observability.svc.cluster.local:3100`) for the Cluster Insight events panel. Optional. | events panel shows "not configured" |
| `FIDUCIA_GRAFANA_PUBLIC_URL` | string | no | Public Grafana base URL or path prefix (e.g. `/telemetry`) for Explore deep links. Optional. | no deep-link buttons |
| `FIDUCIA_NODE_URLS` | string | no | Comma-separated fiducia-node client-plane base URLs; overrides brain `/v1/nodes` discovery for the observe fan-out. Optional. | discover from `fiducia-brain` |
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
scripts/with-flags2env.sh --port 8096 -- cargo run --locked
```

The schema is audited by the CLI flag contract step in CI
(`.github/workflows/ci.yml`). Build the pinned parser once with
`make -C vendor/flags-2-env all`.

### Reproducible container inputs

The container build fetches `fiducia-interfaces` at
`487e470c45ab5851e8f6f3b1dc048fe067fbf408` and `fiducia-sync` at
`b9545140932995f75af8b3c5514cb4379404264c`. Both build arguments must be
40-character lowercase commit ids; the Dockerfile checks out each commit in
detached mode and verifies `HEAD` before compiling with
`cargo build --release --locked`. CI uses
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
- **Complete route gate.** Dashboard, infra, cluster insight (page, fragments,
  and JSON), sync catch-up/write, and WebSocket handshake paths all enforce the
  operator role. Customer account/API-key routes are not compiled into this
  service.
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

- [`fiducia-auth.rs`](https://github.com/fiducia-cloud/fiducia-auth.rs) · [`fiducia-brain.rs`](https://github.com/fiducia-cloud/fiducia-brain.rs) · [`fiducia-customer.rs`](https://github.com/fiducia-cloud/fiducia-customer.rs)
