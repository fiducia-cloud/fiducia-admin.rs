//! fiducia-admin — the server-rendered admin dashboard (MASH: Maud + Axum + SeaORM
//! + HTMX).
//!
//! This web app is operator-only: cluster and infrastructure operations live
//! here, while customer accounts, API keys, preferences, and security sessions
//! live in the separately deployed customer application.
//!
//! Auth starts at the isolated ADMIN Supabase project and is upgraded through
//! Shared Auth before any reusable browser session is persisted.
//! authenticated app — distinct from `fiducia-backend`, which serves the public
//! marketing site.
//!
//! ADMIN plane isolation: `DATABASE_URL` points at the admin app's OWN Postgres
//! (operators, infra_operations, admin_audit_log) — a separate instance from the
//! customer DB. That is a security boundary; this service never connects to the
//! customer database, and startup fails closed when the admin DB is unavailable.

mod cluster_insight;
mod cron_debug;
mod entity;
mod request_security;
mod session;
mod upstream;
mod views;

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use std::{io, result};

use axum::{
    extract::{
        ws::{Message, WebSocket, WebSocketUpgrade},
        Form, Path, Query, Request, State,
    },
    http::{
        header::{CONTENT_TYPE, LOCATION, SET_COOKIE},
        HeaderMap, HeaderName, HeaderValue, StatusCode,
    },
    middleware::{self, Next},
    response::{IntoResponse, Response},
    routing::{get, post},
    Json, Router,
};
use fiducia_sync_core::{ChangeEvent, ChangeOp, WriteAck};
use sea_orm::sea_query::{Expr, OnConflict};
use sea_orm::{
    ActiveModelTrait, ActiveValue::Set, ColumnTrait, ConnectOptions, ConnectionTrait, Database,
    DatabaseConnection, DatabaseTransaction, DbBackend, DbErr, EntityTrait, FromQueryResult,
    QueryFilter, QueryOrder, QuerySelect, Statement, TransactionTrait,
};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use tokio::sync::broadcast;
use tower_http::{
    catch_panic::CatchPanicLayer, limit::RequestBodyLimitLayer, timeout::TimeoutLayer,
    trace::TraceLayer,
};
use uuid::Uuid;

use entity::{
    admin_audit_log, admin_broadcast_notices, infra_operations, operators, sync_idempotency_keys,
};
use infra_operations::Model as InfraOperationsRow;
use request_security::{RequestSecurity, RequestSecurityError};
use session::{Session, ADMIN_SESSION_COOKIE, LOGIN_CSRF_COOKIE};

const SERVICE: &str = "fiducia-admin";

/// Bound request handling time (slow-loris / hung-upstream protection).
const REQUEST_TIMEOUT_SECS: u64 = 30;
/// Cap request bodies (HTML form posts are tiny).
const MAX_BODY_BYTES: usize = 64 * 1024;
/// Bound attacker-controlled idempotency/echo keys before persisting them.
const MAX_WRITE_KEY_BYTES: usize = 256;
const DEFAULT_CATCHUP_PAGE_SIZE: u64 = 100;
const MAX_CATCHUP_PAGE_SIZE: u64 = 500;
/// Minimum node count a scale request may target — the multi-cloud replication
/// baseline. Mirrors the `infra_operations` sync-write guard so both write paths
/// enforce the same floor.
const MIN_SCALE_TARGET_NODES: u32 = 3;
const CSRF_HEADER: &str = "x-fiducia-csrf";

/// The vendored htmx bundle, compiled into the binary and served same-origin at
/// `/assets/htmx.min.js`. No CDN — the dashboard (and the offline E2E) get htmx
/// without a network round-trip or a third-party origin in the trust boundary.
const HTMX_JS: &str = include_str!("../assets/htmx.min.js");

/// The vendored, self-contained @fiducia/sync admin browser bundle (wasm inlined),
/// served same-origin at `/assets/fiducia-sync.js`. Built by
/// `fiducia-sync/sdk: npm run build:admin-bundle`. Single-binary, no CDN.
const SYNC_JS: &str = include_str!("../assets/fiducia-sync.js");

/// Page stylesheet, served at `/assets/admin.css`. Lives in a file rather than an
/// inline `<style>` so the CSP in `security_headers` can omit
/// `style-src 'unsafe-inline'`.
const ADMIN_CSS: &str = include_str!("../assets/admin.css");

/// Page bootstrap, served at `/assets/admin-init.js`: hardens the htmx config
/// (disables `allowScriptTags`/`allowEval`) and boots the sync client. External
/// for the same CSP reason as `ADMIN_CSS`.
const ADMIN_INIT_JS: &str = include_str!("../assets/admin-init.js");

struct AppState {
    auth_url: String,
    brain_url: String,
    supabase_url: String,
    supabase_publishable_key: String,
    /// Admin-plane SeaORM connection. `None` is only used by failure-path tests.
    db: Option<DatabaseConnection>,
    /// Fans `fiducia:sync` frames out to `/admin/ws` subscribers.
    stream_tx: broadcast::Sender<String>,
    /// Exact canonical admin origin + credential-bound CSRF signer.
    request_security: RequestSecurity,
    /// Cluster Insight observability plane — all optional. Unset URLs render as
    /// "not configured" cards on `/cluster`, never as errors.
    prometheus_url: Option<String>,
    loki_url: Option<String>,
    grafana_public_url: Option<String>,
    /// Explicit fiducia-node client-plane base URLs. Empty → discover node
    /// addresses from the brain's `/v1/nodes` membership snapshot.
    node_urls: Vec<String>,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Hold the guard for the whole of `main`: v0.2.1's `init` returns a
    // `#[must_use]` TelemetryGuard that shuts the OTLP exporters down on drop.
    let _telemetry = fiducia_telemetry::init(SERVICE);

    let port: u16 = std::env::var("PORT")
        .ok()
        .and_then(|p| p.parse().ok())
        .unwrap_or(8096);
    let db = connect_admin_db().await?;
    required_env("FIDUCIA_INTERNAL_SECRET")?;
    let request_security = RequestSecurity::from_env(port)?;
    let (stream_tx, _) = broadcast::channel::<String>(256);

    let shared_auth_url = required_env("SHARED_AUTH_URL")?;
    session::initialize(&shared_auth_url).map_err(|error| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("invalid Shared Auth configuration: {error}"),
        )
    })?;
    let supabase_url = required_env("SUPABASE_URL")?;
    let supabase_publishable_key = required_env("SUPABASE_PUBLISHABLE_KEY")?;

    let state = Arc::new(AppState {
        auth_url: shared_auth_url,
        brain_url: required_env("FIDUCIA_BRAIN_URL")?,
        supabase_url,
        supabase_publishable_key,
        db: Some(db),
        stream_tx,
        request_security,
        prometheus_url: optional_env("FIDUCIA_PROMETHEUS_URL"),
        loki_url: optional_env("FIDUCIA_LOKI_URL"),
        grafana_public_url: validated_grafana_public_url()?,
        node_urls: csv_env("FIDUCIA_NODE_URLS"),
    });

    let app = cron_debug::cron_admin_routes(Router::new())
        .route("/healthz", get(health))
        .route("/assets/htmx.min.js", get(htmx_js))
        .route("/assets/fiducia-sync.js", get(sync_js))
        .route("/assets/admin.css", get(admin_css))
        .route("/assets/admin-init.js", get(admin_init_js))
        .route("/login", get(login).post(login_submit))
        .route("/logout", post(logout))
        .route("/", get(dashboard))
        .route("/infra", get(infra_page))
        .route("/infra/scale", post(scale))
        .route("/audit", get(audit_page))
        .route("/notices", get(notices_page).post(create_notice))
        // Cluster Insight (read-only): HTML page + polled htmx fragments behind
        // the operator gate, and JSON views of the same data for API callers.
        .route("/cluster", get(cluster_page))
        .route("/cluster/shards", get(cluster_shards_fragment))
        .route("/cluster/nodes", get(cluster_nodes_fragment))
        .route("/cluster/events", get(cluster_events_fragment))
        .route("/api/admin/cluster/overview", get(cluster_overview_api))
        .route("/api/admin/cluster/shards", get(cluster_shards_api))
        .route("/api/admin/cluster/events", get(cluster_events_api))
        .route("/api/admin/cluster/metrics", get(cluster_metrics_api))
        .route("/api/admin/audit", get(audit_api))
        // Local-first sync write path (mirrors the customer plane): the sync
        // client POSTs a queued optimistic write; we persist via SeaORM and return
        // the committed row version, then broadcast the change to WS subscribers.
        .route("/api/admin/sync/:table", post(sync_write).get(sync_catchup))
        .route("/admin/ws", get(admin_ws))
        .with_state(state)
        // Hardening stack (outermost last): catch handler panics → 500, cap
        // request time/body size, and attach security headers to every response
        // those inner layers produce (including their error responses).
        .layer(TraceLayer::new_for_http())
        .layer(TimeoutLayer::new(Duration::from_secs(REQUEST_TIMEOUT_SECS)))
        .layer(RequestBodyLimitLayer::new(MAX_BODY_BYTES))
        .layer(CatchPanicLayer::new())
        .layer(middleware::from_fn(security_headers));

    let addr = SocketAddr::from(([0, 0, 0, 0], port));
    tracing::info!("{SERVICE} listening on http://{addr}");
    let listener = tokio::net::TcpListener::bind(addr).await?;
    axum::serve(listener, app)
        .with_graceful_shutdown(shutdown_signal())
        .await?;
    Ok(())
}

/// Resolve when the process is asked to stop, so in-flight requests can finish.
///
/// Every k8s rollout sends SIGTERM. Without this, `axum::serve` is aborted the
/// instant the runtime unwinds, severing in-flight operator mutations —
/// including the window between an `infra_operations` audit write and the brain
/// call it authorizes — and cutting open `/admin/ws` sockets mid-frame. Waiting
/// on both SIGTERM (k8s) and Ctrl-C (local) lets the connection drain first.
async fn shutdown_signal() {
    let ctrl_c = async {
        let _ = tokio::signal::ctrl_c().await;
    };
    #[cfg(unix)]
    let terminate = async {
        match tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate()) {
            Ok(mut sig) => {
                sig.recv().await;
            }
            Err(error) => {
                tracing::error!(%error, "failed to install SIGTERM handler");
                std::future::pending::<()>().await;
            }
        }
    };
    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();

    tokio::select! {
        _ = ctrl_c => {}
        _ = terminate => {}
    }
    tracing::info!("shutdown signal received; draining in-flight requests");
}

/// Connect to the isolated admin Postgres plane; missing/unreachable storage is
/// fatal because an operator action without its audit trail is not acceptable.
async fn connect_admin_db() -> Result<DatabaseConnection, Box<dyn std::error::Error>> {
    let url = required_env("DATABASE_URL")?;
    let mut options = ConnectOptions::new(url);
    options
        .max_connections(5)
        // SeaORM defaults `sqlx_logging` to ON at INFO, which emits every
        // statement *with its bound values* into the tracing pipeline that
        // `fiducia_telemetry::init` ships off-box. On this plane those values are
        // operator emails, broadcast notice bodies, and audit rows — none of
        // which belong in a log sink. The customer plane already disables this.
        .sqlx_logging(false)
        // Bound the failure modes a single `max_connections` cannot: without an
        // acquire timeout a slow-query storm queues requests until the outer
        // layer fires, and without `max_lifetime` an RDS/pgbouncer failover
        // hands out dead connections indefinitely.
        .acquire_timeout(Duration::from_secs(5))
        .connect_timeout(Duration::from_secs(5))
        .idle_timeout(Duration::from_secs(600))
        .max_lifetime(Duration::from_secs(1800));
    let db = Database::connect(options).await?;
    db.ping().await?;
    tracing::info!("admin DB connected — infra_operations audit is live");
    Ok(db)
}

fn required_env(name: &str) -> result::Result<String, io::Error> {
    std::env::var(name)
        .ok()
        .filter(|value| !value.trim().is_empty())
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, format!("{name} must be set")))
}

/// Optional configuration: unset or blank means "feature off", not an error.
fn optional_env(name: &str) -> Option<String> {
    std::env::var(name)
        .ok()
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty())
}

/// Validate `FIDUCIA_GRAFANA_PUBLIC_URL` at startup (L8). The value becomes a
/// clickable `href` on the cluster page, so it must be empty (feature off), an
/// http(s):// URL, or a root-relative path (`/telemetry`) — never a
/// `javascript:`/`data:` scheme or a protocol-relative `//host` that would
/// navigate off-origin. A set-but-invalid value fails startup closed.
fn validated_grafana_public_url() -> result::Result<Option<String>, io::Error> {
    match optional_env("FIDUCIA_GRAFANA_PUBLIC_URL") {
        None => Ok(None),
        Some(value) if grafana_public_url_is_valid(&value) => Ok(Some(value)),
        Some(value) => Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!(
                "FIDUCIA_GRAFANA_PUBLIC_URL must be an http(s):// URL or a root-relative \
                 path starting with '/': got {value:?}"
            ),
        )),
    }
}

fn grafana_public_url_is_valid(value: &str) -> bool {
    let value = value.trim();
    if value.starts_with("http://") || value.starts_with("https://") {
        return true;
    }
    // Root-relative path only; reject protocol-relative `//host` (off-origin).
    value.starts_with('/') && !value.starts_with("//")
}

/// Comma-separated optional list (`FIDUCIA_NODE_URLS`); blank entries dropped.
fn csv_env(name: &str) -> Vec<String> {
    optional_env(name)
        .map(|value| {
            value
                .split(',')
                .map(str::trim)
                .filter(|entry| !entry.is_empty())
                .map(str::to_string)
                .collect()
        })
        .unwrap_or_default()
}

async fn health() -> Json<Value> {
    Json(json!({ "status": "ok", "service": SERVICE }))
}

/// Serve the vendored htmx bundle (same-origin, offline).
async fn htmx_js() -> impl IntoResponse {
    (
        [(CONTENT_TYPE, "application/javascript; charset=utf-8")],
        HTMX_JS,
    )
}

/// Serve the vendored, self-contained @fiducia/sync admin bundle (same-origin).
async fn sync_js() -> impl IntoResponse {
    (
        [(CONTENT_TYPE, "application/javascript; charset=utf-8")],
        SYNC_JS,
    )
}

/// Serve the page stylesheet (same-origin, CSP-friendly).
async fn admin_css() -> impl IntoResponse {
    ([(CONTENT_TYPE, "text/css; charset=utf-8")], ADMIN_CSS)
}

/// Serve the page bootstrap (same-origin, CSP-friendly).
async fn admin_init_js() -> impl IntoResponse {
    (
        [(CONTENT_TYPE, "application/javascript; charset=utf-8")],
        ADMIN_INIT_JS,
    )
}

fn redirect(to: &str) -> Response {
    (StatusCode::SEE_OTHER, [(LOCATION, to)]).into_response()
}

/// True when the request came from htmx (so the handler returns a fragment rather
/// than redirecting). Absent header → a plain form submit → progressive redirect.
fn is_htmx(headers: &HeaderMap) -> bool {
    headers.contains_key("hx-request")
}

fn csrf_token(st: &AppState, session: &Session) -> String {
    st.request_security.csrf_token(session.csrf_binding())
}

fn request_security_error(error: RequestSecurityError) -> Response {
    tracing::warn!(reason = error.code(), "rejected untrusted admin request");
    (
        StatusCode::FORBIDDEN,
        Json(json!({ "error": "admin_request_rejected", "reason": error.code() })),
    )
        .into_response()
}

fn require_form_security(
    headers: &HeaderMap,
    st: &AppState,
    session: &Session,
    provided_csrf: &str,
) -> Result<(), RequestSecurityError> {
    st.request_security
        .require_same_origin(headers)
        .and_then(|()| {
            st.request_security
                .verify_csrf_token(session.csrf_binding(), provided_csrf)
        })
}

fn require_sync_write_security(
    headers: &HeaderMap,
    st: &AppState,
    session: &Session,
) -> Result<(), RequestSecurityError> {
    if session.is_browser_session() {
        st.request_security.require_same_origin(headers)?;
        let provided = headers
            .get(CSRF_HEADER)
            .and_then(|value| value.to_str().ok())
            .unwrap_or_default();
        st.request_security
            .verify_csrf_token(session.csrf_binding(), provided)
    } else {
        // Explicit bearer callers are not ambient-cookie CSRF targets. They may
        // omit Origin, but still cannot address the service through another Host.
        st.request_security.require_api_host(headers)
    }
}

/// Response-side clickjacking and cross-origin form defenses. Request-side
/// Origin/Host/CSRF checks live beside each authenticated mutation below.
async fn security_headers(request: Request, next: Next) -> Response {
    let sensitive_response =
        !request.uri().path().starts_with("/assets/") && request.uri().path() != "/healthz";
    let mut response = next.run(request).await;
    let headers = response.headers_mut();
    if sensitive_response {
        headers.insert(
            HeaderName::from_static("cache-control"),
            HeaderValue::from_static("no-store"),
        );
    }
    // A real allowlist, not just framing/form controls. The previous policy set
    // no `default-src` and no `script-src`, so script execution was entirely
    // unrestricted — and every admin fragment is swapped into the DOM with
    // htmx's `innerHTML`, so any HTML that reached a swap target could execute.
    //
    // Each source is load-bearing:
    //   default-src 'self'      — deny by default; no third-party origin.
    //   script-src  'self'      — only our vendored, same-origin bundles.
    //   'wasm-unsafe-eval'      — `assets/fiducia-sync.js` inlines wasm and calls
    //                             WebAssembly.instantiate; without this the sync
    //                             client fails to boot. It permits wasm
    //                             compilation ONLY, not JS eval()/new Function.
    //   style-src   'self'      — the stylesheet is external and no `style=`
    //                             attributes remain, so no 'unsafe-inline'.
    //   connect-src 'self'      — same-origin XHR plus the /admin/ws WebSocket.
    //   img-src 'self' data:    — inline data: badges/icons.
    headers.insert(
        HeaderName::from_static("content-security-policy"),
        HeaderValue::from_static(
            "default-src 'self'; \
             script-src 'self' 'wasm-unsafe-eval'; \
             style-src 'self'; \
             img-src 'self' data:; \
             connect-src 'self'; \
             font-src 'self'; \
             frame-ancestors 'none'; \
             base-uri 'none'; \
             form-action 'self'; \
             object-src 'none'",
        ),
    );
    headers.insert(
        HeaderName::from_static("x-frame-options"),
        HeaderValue::from_static("DENY"),
    );
    headers.insert(
        HeaderName::from_static("x-content-type-options"),
        HeaderValue::from_static("nosniff"),
    );
    // `same-origin`, NOT `no-referrer`: under `no-referrer` browsers serialize
    // the Origin of a form POST as `null` (Fetch spec, request-origin
    // serialization follows the referrer policy), so `require_same_origin`
    // would reject every real-browser login while hand-crafted clients that
    // set Origin themselves sail through — the exact inversion of the intent.
    // `same-origin` still never leaks the referrer cross-origin and keeps the
    // Origin header intact for the CSRF origin gate. Proven by the real-
    // Chromium journeys in fiducia-e2e (`npm run test:browser`).
    headers.insert(
        HeaderName::from_static("referrer-policy"),
        HeaderValue::from_static("same-origin"),
    );
    response
}

/// Require any signed-in user, else redirect to /login.
async fn require(headers: &HeaderMap, st: &AppState) -> Result<Session, Response> {
    let session = session::current(headers, &st.auth_url)
        .await
        .ok_or_else(|| redirect("/login"))?;
    st.request_security
        .require_host(headers)
        .map_err(request_security_error)?;
    Ok(session)
}

/// Require the admin role, else 403.
async fn require_admin(headers: &HeaderMap, st: &AppState) -> Result<Session, Response> {
    let s = require(headers, st).await?;
    if !s.is_admin {
        let csrf = csrf_token(st, &s);
        return Err((StatusCode::FORBIDDEN, views::forbidden(&s, Some(&csrf))).into_response());
    }
    match operator_is_enabled(st, &s).await {
        Ok(true) => Ok(s),
        Ok(false) => {
            let csrf = csrf_token(st, &s);
            Err((StatusCode::FORBIDDEN, views::forbidden(&s, Some(&csrf))).into_response())
        }
        Err(error) => Err(dependency_error("operator_registry_unavailable", error)),
    }
}

/// Require the admin role for JSON/API routes. Same gate as `require_admin` but
/// returns a JSON error body (not an HTML page), so API callers get a machine-
/// readable 401/403. Guards the `/api/admin/sync/*` write endpoints.
async fn require_admin_api(headers: &HeaderMap, st: &AppState) -> Result<Session, Response> {
    match require(headers, st).await {
        Ok(s) if s.is_admin => match operator_is_enabled(st, &s).await {
            Ok(true) => Ok(s),
            Ok(false) => {
                Err((StatusCode::FORBIDDEN, Json(json!({ "error": "forbidden" }))).into_response())
            }
            Err(error) => Err(dependency_error("operator_registry_unavailable", error)),
        },
        Ok(_) => {
            Err((StatusCode::FORBIDDEN, Json(json!({ "error": "forbidden" }))).into_response())
        }
        Err(_) => Err((
            StatusCode::UNAUTHORIZED,
            Json(json!({ "error": "unauthenticated" })),
        )
            .into_response()),
    }
}

async fn enabled_operator(
    st: &AppState,
    session: &Session,
) -> Result<Option<operators::Model>, DbErr> {
    if cfg!(debug_assertions) && session.user_id == "dev-admin" {
        return Ok(None);
    }
    let Ok(subject) = Uuid::parse_str(&session.user_id) else {
        return Ok(None);
    };
    let db = st.db.as_ref().ok_or_else(database_unavailable)?;
    let operator = operators::Entity::find()
        .filter(operators::Column::SupabaseUserId.eq(subject))
        .filter(operators::Column::Disabled.eq(false))
        .one(db)
        .await?;
    Ok(operator.filter(|operator| operator_registry_role_allows_access(&operator.role)))
}

fn operator_registry_role_allows_access(role: &str) -> bool {
    matches!(role, "owner" | "admin" | "operator")
}

async fn operator_is_enabled(st: &AppState, session: &Session) -> Result<bool, DbErr> {
    if cfg!(debug_assertions) && session.user_id == "dev-admin" {
        return Ok(true);
    }
    Ok(enabled_operator(st, session).await?.is_some())
}

async fn login(State(st): State<Arc<AppState>>) -> Response {
    login_page(&st, None)
}

#[derive(Debug, Deserialize)]
struct LoginForm {
    csrf_token: String,
    email: String,
    password: String,
}

#[derive(Debug, Deserialize)]
struct SupabasePasswordSession {
    access_token: String,
}

async fn login_submit(
    State(st): State<Arc<AppState>>,
    headers: HeaderMap,
    Form(form): Form<LoginForm>,
) -> Response {
    if let Err(error) = require_login_security(&headers, &st, &form.csrf_token) {
        return request_security_error(error);
    }
    let email = form.email.trim();
    if email.is_empty() || form.password.is_empty() {
        return login_page(&st, Some("Email and password are required."));
    }

    let token_url = format!(
        "{}/auth/v1/token?grant_type=password",
        st.supabase_url.trim_end_matches('/')
    );
    let client = match reqwest::Client::builder()
        .timeout(Duration::from_secs(10))
        .build()
    {
        Ok(client) => client,
        Err(error) => return upstream_error("supabase_login_failed", "supabase", error),
    };
    let response = match client
        .post(token_url)
        .header("apikey", &st.supabase_publishable_key)
        .json(&json!({ "email": email, "password": form.password }))
        .send()
        .await
    {
        Ok(response) => response,
        Err(error) => return upstream_error("supabase_login_failed", "supabase", error),
    };
    if !response.status().is_success() {
        return login_page(&st, Some("Supabase rejected those credentials."));
    }
    let password_session = match response.json::<SupabasePasswordSession>().await {
        Ok(session) => session,
        Err(error) => return upstream_error("supabase_login_failed", "supabase", error),
    };
    let Some(verified) = session::from_bearer(&st.auth_url, &password_session.access_token).await
    else {
        return login_page(
            &st,
            Some("Shared Auth could not authorize this admin identity."),
        );
    };
    let session = verified.session;
    let Some(session_upgrade) = verified.session_upgrade else {
        return dependency_error(
            "shared_auth_session_upgrade_missing",
            "Shared Auth authorized the provider token without issuing a reusable session",
        );
    };
    if !session.is_admin {
        return (StatusCode::FORBIDDEN, views::forbidden(&session, None)).into_response();
    }
    match operator_is_enabled(&st, &session).await {
        Ok(true) => {}
        Ok(false) => {
            return (StatusCode::FORBIDDEN, views::forbidden(&session, None)).into_response()
        }
        Err(error) => return dependency_error("operator_registry_unavailable", error),
    }

    let mut response = redirect("/");
    append_set_cookie(
        &mut response,
        &make_session_cookie(session_upgrade.access_token()),
    );
    append_set_cookie(&mut response, &clear_login_csrf_cookie());
    response
}

fn login_page(st: &AppState, message: Option<&str>) -> Response {
    let nonce = format!("{}{}", Uuid::new_v4().simple(), Uuid::new_v4().simple());
    let binding = format!("login\0{nonce}");
    let csrf = st.request_security.csrf_token(&binding);
    let mut response = views::login(message, &csrf).into_response();
    append_set_cookie(&mut response, &make_login_csrf_cookie(&nonce));
    response
}

fn require_login_security(
    headers: &HeaderMap,
    st: &AppState,
    provided_csrf: &str,
) -> Result<(), RequestSecurityError> {
    st.request_security.require_same_origin(headers)?;
    let nonce = session::cookie_value(headers, LOGIN_CSRF_COOKIE)
        .ok_or(RequestSecurityError::InvalidCsrfToken)?;
    st.request_security
        .verify_csrf_token(&format!("login\0{nonce}"), provided_csrf)
}

fn append_set_cookie(response: &mut Response, cookie: &str) {
    response.headers_mut().append(
        SET_COOKIE,
        HeaderValue::from_str(cookie).expect("server-generated cookie is a valid header value"),
    );
}

fn explicitly_enabled(value: Option<&str>) -> bool {
    value.is_some_and(|value| matches!(value.trim().to_ascii_lowercase().as_str(), "1" | "true"))
}

const fn cookie_secure_suffix_for(
    release_hardened: bool,
    insecure_http_explicitly_enabled: bool,
) -> &'static str {
    if release_hardened || !insecure_http_explicitly_enabled {
        "; Secure"
    } else {
        ""
    }
}

/// Debug builds may opt into plain-HTTP cookies for local development. Release
/// binaries always emit `Secure`, even if a stale environment variable remains.
#[cfg(debug_assertions)]
fn cookie_secure_suffix() -> &'static str {
    cookie_secure_suffix_for(
        false,
        explicitly_enabled(std::env::var("FIDUCIA_INSECURE_COOKIES").ok().as_deref()),
    )
}

#[cfg(not(debug_assertions))]
fn cookie_secure_suffix() -> &'static str {
    let insecure_requested =
        explicitly_enabled(std::env::var("FIDUCIA_INSECURE_COOKIES").ok().as_deref());
    if insecure_requested {
        tracing::error!(
            "FIDUCIA_INSECURE_COOKIES is set but IGNORED: release builds always emit Secure cookies"
        );
    }
    cookie_secure_suffix_for(true, insecure_requested)
}

fn make_login_csrf_cookie(nonce: &str) -> String {
    format!(
        "{LOGIN_CSRF_COOKIE}={nonce}; Path=/; HttpOnly; SameSite=Strict; Max-Age=600{}",
        cookie_secure_suffix()
    )
}

fn clear_login_csrf_cookie() -> String {
    format!(
        "{LOGIN_CSRF_COOKIE}=; Path=/; HttpOnly; SameSite=Strict; Max-Age=0{}",
        cookie_secure_suffix()
    )
}

fn make_session_cookie(token: &str) -> String {
    format!(
        "{ADMIN_SESSION_COOKIE}={token}; Path=/; HttpOnly; SameSite=Strict{}",
        cookie_secure_suffix()
    )
}

fn clear_session_cookie() -> String {
    format!(
        "{ADMIN_SESSION_COOKIE}=; Path=/; HttpOnly; SameSite=Strict; Max-Age=0{}",
        cookie_secure_suffix()
    )
}

#[derive(Debug, Deserialize)]
struct CsrfForm {
    csrf_token: String,
}

async fn logout(
    State(st): State<Arc<AppState>>,
    headers: HeaderMap,
    Form(form): Form<CsrfForm>,
) -> Response {
    let session = match require(&headers, &st).await {
        Ok(session) => session,
        Err(response) => return response,
    };
    if let Err(error) = require_form_security(&headers, &st, &session, &form.csrf_token) {
        return request_security_error(error);
    }
    let mut response = redirect("/login");
    append_set_cookie(&mut response, &clear_session_cookie());
    response
}

async fn dashboard(State(st): State<Arc<AppState>>, headers: HeaderMap) -> Response {
    match require_admin(&headers, &st).await {
        Ok(s) => {
            let csrf = csrf_token(&st, &s);
            views::dashboard(&s, &csrf).into_response()
        }
        Err(r) => r,
    }
}

async fn infra_page(State(st): State<Arc<AppState>>, headers: HeaderMap) -> Response {
    let s = match require_admin(&headers, &st).await {
        Ok(s) => s,
        Err(r) => return r,
    };
    let nodes = match upstream::nodes(&st.brain_url).await {
        Ok(nodes) => nodes,
        Err(err) => return upstream_error("brain_nodes_failed", "fiducia-brain", err),
    };
    let placement = match upstream::placement(&st.brain_url).await {
        Ok(placement) => placement,
        Err(err) => return upstream_error("brain_placement_failed", "fiducia-brain", err),
    };
    let recent = match recent_ops(&st).await {
        Ok(rows) => rows,
        Err(err) => return dependency_error("infra_audit_read_failed", err),
    };
    let csrf = csrf_token(&st, &s);
    views::infra(&s, &csrf, &nodes, &placement, &recent).into_response()
}

#[derive(Debug, Default, Deserialize)]
struct AuditQuery {
    limit: Option<u16>,
}

#[derive(Serialize)]
struct AdminAuditEvent {
    id: Uuid,
    actor: Option<String>,
    action: String,
    target: Option<String>,
    request_id: Option<String>,
    created_at: String,
}

fn audit_limit(requested: Option<u16>) -> u64 {
    requested.map(u64::from).unwrap_or(50).clamp(1, 100)
}

fn admin_audit_event(row: admin_audit_log::Model) -> AdminAuditEvent {
    AdminAuditEvent {
        id: row.id,
        actor: row.actor,
        action: row.action,
        target: row.target,
        request_id: row.request_id,
        created_at: row.created_at.to_rfc3339(),
    }
}

async fn audit_page(
    State(st): State<Arc<AppState>>,
    headers: HeaderMap,
    Query(query): Query<AuditQuery>,
) -> Response {
    let session = match require_admin(&headers, &st).await {
        Ok(session) => session,
        Err(response) => return response,
    };
    let rows = match recent_admin_audit(&st, audit_limit(query.limit)).await {
        Ok(rows) => rows,
        Err(error) => return dependency_error("admin_audit_read_failed", error),
    };
    views::audit(&session, &csrf_token(&st, &session), &rows).into_response()
}

async fn audit_api(
    State(st): State<Arc<AppState>>,
    headers: HeaderMap,
    Query(query): Query<AuditQuery>,
) -> Response {
    if let Err(response) = require_admin_api(&headers, &st).await {
        return response;
    }
    match recent_admin_audit(&st, audit_limit(query.limit)).await {
        Ok(rows) => Json(json!({
            "events": rows.into_iter().map(admin_audit_event).collect::<Vec<_>>()
        }))
        .into_response(),
        Err(error) => dependency_error("admin_audit_read_failed", error),
    }
}

async fn notices_page(State(st): State<Arc<AppState>>, headers: HeaderMap) -> Response {
    let session = match require_admin(&headers, &st).await {
        Ok(session) => session,
        Err(response) => return response,
    };
    let rows = match recent_notices(&st, 50).await {
        Ok(rows) => rows,
        Err(error) => return dependency_error("notices_read_failed", error),
    };
    views::notices(&session, &csrf_token(&st, &session), &rows, None).into_response()
}

#[derive(Debug, Deserialize)]
struct NoticeForm {
    csrf_token: String,
    severity: String,
    title: String,
    #[serde(default)]
    body: String,
}

const NOTICE_SEVERITIES: [&str; 3] = ["info", "warning", "critical"];
const MAX_NOTICE_TITLE_CHARS: usize = 200;
const MAX_NOTICE_BODY_CHARS: usize = 2000;

async fn create_notice(
    State(st): State<Arc<AppState>>,
    headers: HeaderMap,
    Form(form): Form<NoticeForm>,
) -> Response {
    let session = match require_admin(&headers, &st).await {
        Ok(session) => session,
        Err(response) => return response,
    };
    if let Err(error) = require_form_security(&headers, &st, &session, &form.csrf_token) {
        return request_security_error(error);
    }
    // Validate against the same bounds the schema enforces, before any write, so
    // a bad request is a clean 400 rather than a database constraint error.
    let title = form.title.trim();
    let body = form.body.trim();
    if !NOTICE_SEVERITIES.contains(&form.severity.as_str())
        || title.is_empty()
        || title.chars().count() > MAX_NOTICE_TITLE_CHARS
        || body.chars().count() > MAX_NOTICE_BODY_CHARS
    {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({ "error": "invalid_notice" })),
        )
            .into_response();
    }
    if let Err(error) = record_notice(&st, &session, &form.severity, title, body).await {
        return dependency_error("notice_write_failed", error);
    }
    let rows = match recent_notices(&st, 50).await {
        Ok(rows) => rows,
        Err(error) => return dependency_error("notices_read_failed", error),
    };
    if is_htmx(&headers) {
        views::notice_table(&rows, Some("Notice published.")).into_response()
    } else {
        redirect("/notices")
    }
}

#[derive(Debug, Deserialize)]
struct ScaleForm {
    csrf_token: String,
    target_nodes: u32,
}

async fn scale(
    State(st): State<Arc<AppState>>,
    headers: HeaderMap,
    Form(form): Form<ScaleForm>,
) -> Response {
    let s = match require_admin(&headers, &st).await {
        Ok(s) => s,
        Err(r) => return r,
    };
    if let Err(error) = require_form_security(&headers, &st, &s, &form.csrf_token) {
        return request_security_error(error);
    }
    // Validate the target BEFORE the audit write and the brain side effect. A
    // `u32` above `i32::MAX` would otherwise wrap negative when persisted into the
    // audit record's `i32` column, silently corrupting the durable record while
    // the brain receives the un-wrapped value.
    if !scale_target_is_valid(form.target_nodes) {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({ "error": "invalid_target_nodes", "min": MIN_SCALE_TARGET_NODES })),
        )
            .into_response();
    }
    // Write the audit intent before the external side effect. An operator action
    // is never executed without a durable record.
    if let Err(err) = record_scale(&st, &s, form.target_nodes).await {
        return dependency_error("infra_audit_write_failed", err);
    }
    let scaled = match upstream::set_scale(&st.brain_url, form.target_nodes).await {
        Ok(scaled) => scaled,
        Err(err) => return upstream_error("brain_scale_failed", "fiducia-brain", err),
    };
    if !scaled {
        return (
            StatusCode::BAD_GATEWAY,
            Json(json!({ "error": "brain_scale_failed", "dependency": "fiducia-brain" })),
        )
            .into_response();
    }
    if is_htmx(&headers) {
        let nodes = match upstream::nodes(&st.brain_url).await {
            Ok(nodes) => nodes,
            Err(err) => return upstream_error("brain_nodes_failed", "fiducia-brain", err),
        };
        let placement = match upstream::placement(&st.brain_url).await {
            Ok(placement) => placement,
            Err(err) => return upstream_error("brain_placement_failed", "fiducia-brain", err),
        };
        let recent = match recent_ops(&st).await {
            Ok(rows) => rows,
            Err(err) => return dependency_error("infra_audit_read_failed", err),
        };
        views::infra_panel(&nodes, &placement, &recent, Some(form.target_nodes)).into_response()
    } else {
        redirect("/infra")
    }
}

// ---- Cluster Insight (read-only observability) --------------------------------

/// Everything one `/cluster` render needs from the brain + the node fan-out.
/// Brain failures abort the render (the page is meaningless without the
/// authority view); node fetch failures are carried per-node in `observations`.
struct ClusterData {
    status: Value,
    nodes: Vec<Value>,
    observations: Vec<cluster_insight::NodeObservation>,
    merged: Vec<cluster_insight::MergedShard>,
    quorum: cluster_insight::ClusterQuorum,
}

async fn cluster_data(st: &AppState) -> Result<ClusterData, Response> {
    let status = upstream::status(&st.brain_url)
        .await
        .map_err(|err| upstream_error("brain_status_failed", "fiducia-brain", err))?;
    let nodes = upstream::nodes(&st.brain_url)
        .await
        .map_err(|err| upstream_error("brain_nodes_failed", "fiducia-brain", err))?;
    // Explicit FIDUCIA_NODE_URLS wins; otherwise dial the addresses the nodes
    // heartbeat into the brain — trust-checked so a spoofed brain address can't
    // harvest the cluster secret (H1) — and capped in count (M3).
    let policy = cluster_insight::NodeHostPolicy::from_env();
    let mut targets = if st.node_urls.is_empty() {
        cluster_insight::targets_from_brain_nodes(&nodes, &policy)
    } else {
        cluster_insight::explicit_node_targets(&st.node_urls, &policy)
    };
    let truncated_from = cluster_insight::truncate_targets(&mut targets);
    let observations = cluster_insight::observe_shards_fanout(&targets).await;
    let merged = cluster_insight::merge_shards(&observations);
    let mut quorum = cluster_insight::cluster_quorum(&observations, &merged);
    quorum.targets_truncated_from = truncated_from;
    Ok(ClusterData {
        status,
        nodes,
        observations,
        merged,
        quorum,
    })
}

/// The summary card's Prometheus probe (optional plane: unset → NotConfigured).
async fn prom_scrape(st: &AppState) -> cluster_insight::PromScrape {
    let Some(url) = &st.prometheus_url else {
        return cluster_insight::PromScrape::NotConfigured;
    };
    match cluster_insight::prom_instant_query(url, cluster_insight::PROM_FIDUCIA_UP_QUERY).await {
        Ok(series) => cluster_insight::PromScrape::Up {
            targets: series
                .iter()
                .filter(|sample| {
                    sample
                        .get("value")
                        .and_then(|value| value.get(1))
                        .and_then(Value::as_str)
                        == Some("1")
                })
                .count(),
        },
        Err(err) => cluster_insight::PromScrape::Error {
            error: upstream::error_class(&*err),
        },
    }
}

/// The events panel state (optional plane: unset → NotConfigured; a Loki error
/// renders inside the panel so the rest of the page stays useful).
async fn loki_events(st: &AppState, since_minutes: i64) -> views::EventsPanel {
    let Some(url) = &st.loki_url else {
        return views::EventsPanel::NotConfigured;
    };
    match cluster_insight::recent_cluster_events(url, since_minutes).await {
        Ok(events) => views::EventsPanel::Events(events),
        Err(err) => views::EventsPanel::Error(upstream::error_class(&*err)),
    }
}

/// Render the complete `/cluster` page (also served by the fragment routes for
/// non-htmx requests, mirroring how infra serves both).
async fn render_cluster_page(st: &AppState, s: &Session) -> Response {
    let data = match cluster_data(st).await {
        Ok(data) => data,
        Err(response) => return response,
    };
    let prometheus = prom_scrape(st).await;
    let events = loki_events(st, cluster_insight::EVENTS_DEFAULT_MINUTES).await;
    let grafana = st.grafana_public_url.as_deref();
    let csrf = csrf_token(st, s);
    views::cluster(
        s,
        &csrf,
        views::cluster_status_panel(
            &data.status,
            &data.merged,
            &data.quorum,
            &prometheus,
            grafana,
        ),
        views::cluster_nodes_panel(&data.nodes, &data.observations),
        views::cluster_events_panel(&events, cluster_insight::EVENTS_DEFAULT_MINUTES, grafana),
    )
    .into_response()
}

async fn cluster_page(State(st): State<Arc<AppState>>, headers: HeaderMap) -> Response {
    match require_admin(&headers, &st).await {
        Ok(s) => render_cluster_page(&st, &s).await,
        Err(response) => response,
    }
}

/// `/cluster/shards` — summary cards + merged shard table (htmx fragment; full
/// page without the `HX-Request` header).
async fn cluster_shards_fragment(State(st): State<Arc<AppState>>, headers: HeaderMap) -> Response {
    let s = match require_admin(&headers, &st).await {
        Ok(s) => s,
        Err(response) => return response,
    };
    if !is_htmx(&headers) {
        return render_cluster_page(&st, &s).await;
    }
    let data = match cluster_data(&st).await {
        Ok(data) => data,
        Err(response) => return response,
    };
    let prometheus = prom_scrape(&st).await;
    views::cluster_status_panel(
        &data.status,
        &data.merged,
        &data.quorum,
        &prometheus,
        st.grafana_public_url.as_deref(),
    )
    .into_response()
}

/// `/cluster/nodes` — node registry table (htmx fragment; full page otherwise).
async fn cluster_nodes_fragment(State(st): State<Arc<AppState>>, headers: HeaderMap) -> Response {
    let s = match require_admin(&headers, &st).await {
        Ok(s) => s,
        Err(response) => return response,
    };
    if !is_htmx(&headers) {
        return render_cluster_page(&st, &s).await;
    }
    let data = match cluster_data(&st).await {
        Ok(data) => data,
        Err(response) => return response,
    };
    views::cluster_nodes_panel(&data.nodes, &data.observations).into_response()
}

#[derive(Debug, Deserialize)]
struct EventsParams {
    #[serde(default)]
    since_minutes: Option<i64>,
}

/// `/cluster/events` — recent-events panel (htmx fragment; full page otherwise).
async fn cluster_events_fragment(
    State(st): State<Arc<AppState>>,
    Query(params): Query<EventsParams>,
    headers: HeaderMap,
) -> Response {
    let s = match require_admin(&headers, &st).await {
        Ok(s) => s,
        Err(response) => return response,
    };
    if !is_htmx(&headers) {
        return render_cluster_page(&st, &s).await;
    }
    let since_minutes = cluster_insight::clamp_since_minutes(params.since_minutes);
    let events = loki_events(&st, since_minutes).await;
    views::cluster_events_panel(&events, since_minutes, st.grafana_public_url.as_deref())
        .into_response()
}

/// `GET /api/admin/cluster/overview` — the whole insight snapshot as JSON:
/// brain status/config/policies, node registry, per-node observe outcomes
/// (including per-node errors), merged shards, the quorum rollup, and the
/// Prometheus probe.
async fn cluster_overview_api(State(st): State<Arc<AppState>>, headers: HeaderMap) -> Response {
    if let Err(response) = require_admin_api(&headers, &st).await {
        return response;
    }
    let data = match cluster_data(&st).await {
        Ok(data) => data,
        Err(response) => return response,
    };
    let config = match upstream::config(&st.brain_url).await {
        Ok(config) => config,
        Err(err) => return upstream_error("brain_config_failed", "fiducia-brain", err),
    };
    let policies = match upstream::policies(&st.brain_url).await {
        Ok(policies) => policies.get("policies").cloned().unwrap_or(Value::Null),
        Err(err) => return upstream_error("brain_policies_failed", "fiducia-brain", err),
    };
    let prometheus = prom_scrape(&st).await;
    Json(json!({
        "cluster": data.status,
        "config": config,
        "policies": policies,
        "nodes": data.nodes,
        "node_observations": data.observations,
        "shards": data.merged,
        "quorum": data.quorum,
        "prometheus": prometheus,
        "generated_at_ms": cluster_insight::now_ms(),
    }))
    .into_response()
}

/// `GET /api/admin/cluster/shards` — the merged shard map + per-node outcomes.
async fn cluster_shards_api(State(st): State<Arc<AppState>>, headers: HeaderMap) -> Response {
    if let Err(response) = require_admin_api(&headers, &st).await {
        return response;
    }
    let data = match cluster_data(&st).await {
        Ok(data) => data,
        Err(response) => return response,
    };
    Json(json!({
        "shards": data.merged,
        "quorum": data.quorum,
        "node_observations": data.observations,
        "generated_at_ms": cluster_insight::now_ms(),
    }))
    .into_response()
}

/// `GET /api/admin/cluster/events?since_minutes=` — classified Loki events.
/// `since_minutes` is clamped (default 30, max 1440). With Loki unconfigured the
/// response says so instead of erroring.
async fn cluster_events_api(
    State(st): State<Arc<AppState>>,
    Query(params): Query<EventsParams>,
    headers: HeaderMap,
) -> Response {
    if let Err(response) = require_admin_api(&headers, &st).await {
        return response;
    }
    let since_minutes = cluster_insight::clamp_since_minutes(params.since_minutes);
    let Some(loki_url) = &st.loki_url else {
        return Json(json!({
            "configured": false,
            "since_minutes": since_minutes,
            "events": [],
        }))
        .into_response();
    };
    match cluster_insight::recent_cluster_events(loki_url, since_minutes).await {
        Ok(events) => Json(json!({
            "configured": true,
            "since_minutes": since_minutes,
            "events": events,
        }))
        .into_response(),
        Err(err) => upstream_error("loki_query_failed", "loki", err),
    }
}

/// `GET /api/admin/cluster/metrics` — the `/v1/observe/metrics` per-operation
/// counters fanned out from every node (per-node errors carried in place).
/// With Prometheus configured, also a 15-minute `up{namespace="fiducia"}`
/// range so callers see scrape-target stability next to the counters.
async fn cluster_metrics_api(State(st): State<Arc<AppState>>, headers: HeaderMap) -> Response {
    if let Err(response) = require_admin_api(&headers, &st).await {
        return response;
    }
    let policy = cluster_insight::NodeHostPolicy::from_env();
    let mut targets = if st.node_urls.is_empty() {
        let nodes = match upstream::nodes(&st.brain_url).await {
            Ok(nodes) => nodes,
            Err(err) => return upstream_error("brain_nodes_failed", "fiducia-brain", err),
        };
        cluster_insight::targets_from_brain_nodes(&nodes, &policy)
    } else {
        cluster_insight::explicit_node_targets(&st.node_urls, &policy)
    };
    let targets_truncated_from = cluster_insight::truncate_targets(&mut targets);
    let nodes = cluster_insight::observe_metrics_fanout(&targets).await;
    let prometheus_up_range = match &st.prometheus_url {
        None => Value::Null,
        Some(url) => {
            let end = cluster_insight::now_ms() / 1000;
            match cluster_insight::prom_range_query(
                url,
                cluster_insight::PROM_FIDUCIA_UP_QUERY,
                end - 900,
                end,
                60,
            )
            .await
            {
                Ok(series) => json!(series),
                // The optional plane degrades in place, like the per-node errors.
                Err(err) => json!({ "error": upstream::error_class(&*err) }),
            }
        }
    };
    Json(json!({
        "nodes": nodes,
        "prometheus_up_range": prometheus_up_range,
        "targets_truncated_from": targets_truncated_from,
        "generated_at_ms": cluster_insight::now_ms(),
    }))
    .into_response()
}

// ---- Admin DB vertical (P2): infra_operations audit + sync broadcast ---------

/// Recent control-plane operations, newest first, as display JSON.
async fn recent_ops(st: &AppState) -> Result<Vec<Value>, DbErr> {
    let db = st.db.as_ref().ok_or_else(database_unavailable)?;
    let rows = infra_operations::Entity::find()
        .order_by_desc(infra_operations::Column::CreatedAt)
        .limit(10)
        .all(db)
        .await?;
    Ok(rows
        .iter()
        .filter_map(|row| serde_json::to_value(row).ok())
        .collect())
}

/// Read a bounded operator audit feed. The browser/API projection below never
/// returns raw metadata, source IPs, or user agents from this security log.
async fn recent_admin_audit(
    st: &AppState,
    limit: u64,
) -> Result<Vec<admin_audit_log::Model>, DbErr> {
    let db = st.db.as_ref().ok_or_else(database_unavailable)?;
    admin_audit_log::Entity::find()
        .order_by_desc(admin_audit_log::Column::CreatedAt)
        .limit(limit)
        .all(db)
        .await
}

async fn recent_notices(
    st: &AppState,
    limit: u64,
) -> Result<Vec<admin_broadcast_notices::Model>, DbErr> {
    let db = st.db.as_ref().ok_or_else(database_unavailable)?;
    admin_broadcast_notices::Entity::find()
        .order_by_desc(admin_broadcast_notices::Column::StartsAt)
        .limit(limit)
        .all(db)
        .await
}

/// Publish a broadcast notice and its operator audit record in one transaction,
/// mirroring `record_scale`: an operator action is never durable without a
/// matching audit row. `operator_id`/`actor` come from the authorized session.
async fn record_notice(
    st: &AppState,
    s: &Session,
    severity: &str,
    title: &str,
    body: &str,
) -> Result<admin_broadcast_notices::Model, DbErr> {
    let db = st.db.as_ref().ok_or_else(database_unavailable)?;
    let operator_id = match enabled_operator(st, s).await? {
        Some(operator) => Some(operator.id),
        None if cfg!(debug_assertions) && s.user_id == "dev-admin" => None,
        None => {
            return Err(DbErr::Custom(
                "operator registry authorization changed before notice write".to_string(),
            ))
        }
    };
    let transaction = db.begin().await?;
    let row = admin_broadcast_notices::ActiveModel {
        operator_id: Set(operator_id),
        severity: Set(severity.to_string()),
        title: Set(title.to_string()),
        body: Set(body.to_string()),
        ..Default::default()
    }
    .insert(&transaction)
    .await?;
    admin_audit_log::ActiveModel {
        actor_operator_id: Set(operator_id),
        actor: Set(s.email.clone()),
        action: Set("notice.published".to_string()),
        target: Set(Some(row.id.to_string())),
        request_id: Set(None),
        meta: Set(json!({ "severity": severity, "notice_id": row.id })),
        ..Default::default()
    }
    .insert(&transaction)
    .await?;
    transaction.commit().await?;
    Ok(row)
}

/// A scale target must meet the replication floor and fit the audit record's
/// `i32` column, so persistence can never silently wrap it.
fn scale_target_is_valid(target_nodes: u32) -> bool {
    target_nodes >= MIN_SCALE_TARGET_NODES && i32::try_from(target_nodes).is_ok()
}

/// Insert the control-plane intent and its operator audit record in one
/// transaction. The brain call cannot happen unless both durable records exist;
/// a websocket broadcast occurs only after the transaction commits.
async fn record_scale(
    st: &AppState,
    s: &Session,
    target_nodes: u32,
) -> Result<InfraOperationsRow, DbErr> {
    let db = st.db.as_ref().ok_or_else(database_unavailable)?;
    let operator_id = match enabled_operator(st, s).await? {
        Some(operator) => Some(operator.id),
        None if cfg!(debug_assertions) && s.user_id == "dev-admin" => None,
        None => {
            return Err(DbErr::Custom(
                "operator registry authorization changed before audit write".to_string(),
            ))
        }
    };
    let transaction = db.begin().await?;
    let row = infra_operations::ActiveModel {
        operator_id: Set(operator_id),
        action: Set("scale".to_string()),
        target_nodes: Set(Some(target_nodes as i32)),
        status: Set("requested".to_string()),
        params: Set(json!({ "target_nodes": target_nodes, "replication_factor": 3 })),
        ..Default::default()
    }
    .insert(&transaction)
    .await?;
    admin_audit_log::ActiveModel {
        actor_operator_id: Set(operator_id),
        actor: Set(s.email.clone()),
        action: Set("infra.scale.requested".to_string()),
        target: Set(Some("fiducia-brain".to_string())),
        request_id: Set(None),
        // Keep the rich operational context in the append-only log while the
        // page/API intentionally expose only the narrow event projection.
        meta: Set(json!({ "target_nodes": target_nodes, "operation_id": row.id })),
        ..Default::default()
    }
    .insert(&transaction)
    .await?;
    transaction.commit().await?;
    broadcast_infra_change(st, &row, None);
    Ok(row)
}

mod sync;
pub(crate) use sync::*;

mod streaming;
pub(crate) use streaming::*;

fn database_unavailable() -> DbErr {
    DbErr::Custom("admin database connection unavailable".to_string())
}

fn dependency_error(code: &str, error: impl std::fmt::Display) -> Response {
    tracing::error!(code, error = %error, "required admin dependency failed");
    (
        StatusCode::SERVICE_UNAVAILABLE,
        Json(json!({ "error": code, "dependency": "postgres" })),
    )
        .into_response()
}

fn upstream_error(code: &str, dependency: &str, error: impl std::fmt::Display) -> Response {
    tracing::error!(code, dependency, error = %error, "required admin upstream failed");
    (
        StatusCode::BAD_GATEWAY,
        Json(json!({ "error": code, "dependency": dependency })),
    )
        .into_response()
}

#[cfg(test)]
fn test_request_security() -> RequestSecurity {
    RequestSecurity::new(
        "https://admin.fiducia.cloud",
        b"0123456789abcdef0123456789abcdef".to_vec(),
    )
    .unwrap()
}

#[cfg(test)]
mod sync_tests;

#[cfg(test)]
mod auth_flow_tests;

#[cfg(test)]
mod cluster_tests;

#[cfg(test)]
mod csrf_tests;

#[cfg(test)]
mod interface_contract_tests;

#[cfg(test)]
mod db_tests;
