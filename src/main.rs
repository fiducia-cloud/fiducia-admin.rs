//! fiducia-admin — the server-rendered admin dashboard (MASH: Maud + Axum + SeaORM
//! + HTMX).
//!
//! This web app is operator-only: cluster and infrastructure operations live
//! here, while customer accounts, API keys, preferences, and security sessions
//! live in the separately deployed customer application.
//!
//! Auth is a Supabase session (verified through `fiducia-auth`). This is the
//! authenticated app — distinct from `fiducia-backend`, which serves the public
//! marketing site.
//!
//! ADMIN plane isolation: `DATABASE_URL` points at the admin app's OWN Postgres
//! (operators, infra_operations, admin_audit_log) — a separate instance from the
//! customer DB. That is a security boundary; this service never connects to the
//! customer database, and startup fails closed when the admin DB is unavailable.

mod cluster_insight;
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

use entity::{admin_audit_log, infra_operations, operators, sync_idempotency_keys};
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
    fiducia_telemetry::init(SERVICE);

    let port: u16 = std::env::var("PORT")
        .ok()
        .and_then(|p| p.parse().ok())
        .unwrap_or(8096);
    let db = connect_admin_db().await?;
    required_env("FIDUCIA_INTERNAL_SECRET")?;
    let request_security = RequestSecurity::from_env(port)?;
    let (stream_tx, _) = broadcast::channel::<String>(256);

    let state = Arc::new(AppState {
        auth_url: required_env("FIDUCIA_AUTH_URL")?,
        brain_url: required_env("FIDUCIA_BRAIN_URL")?,
        supabase_url: required_env("SUPABASE_URL")?,
        supabase_publishable_key: required_env("SUPABASE_PUBLISHABLE_KEY")?,
        db: Some(db),
        stream_tx,
        request_security,
        prometheus_url: optional_env("FIDUCIA_PROMETHEUS_URL"),
        loki_url: optional_env("FIDUCIA_LOKI_URL"),
        grafana_public_url: validated_grafana_public_url()?,
        node_urls: csv_env("FIDUCIA_NODE_URLS"),
    });

    let app = Router::new()
        .route("/healthz", get(health))
        .route("/assets/htmx.min.js", get(htmx_js))
        .route("/assets/fiducia-sync.js", get(sync_js))
        .route("/login", get(login).post(login_submit))
        .route("/logout", post(logout))
        .route("/", get(dashboard))
        .route("/infra", get(infra_page))
        .route("/infra/scale", post(scale))
        .route("/audit", get(audit_page))
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
    axum::serve(listener, app).await?;
    Ok(())
}

/// Connect to the isolated admin Postgres plane; missing/unreachable storage is
/// fatal because an operator action without its audit trail is not acceptable.
async fn connect_admin_db() -> Result<DatabaseConnection, Box<dyn std::error::Error>> {
    let url = required_env("DATABASE_URL")?;
    let mut options = ConnectOptions::new(url);
    options.max_connections(5);
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
    headers.insert(
        HeaderName::from_static("content-security-policy"),
        HeaderValue::from_static(
            "frame-ancestors 'none'; base-uri 'none'; form-action 'self'; object-src 'none'",
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
    let Some(session) = session::from_bearer(&st.auth_url, &password_session.access_token).await
    else {
        return login_page(&st, Some("The identity could not be verified."));
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
        &make_session_cookie(&password_session.access_token),
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

/// One queued optimistic write from the sync client (mirrors the customer plane).
#[derive(Debug, Deserialize)]
struct SyncWriteRequest {
    id: String,
    #[serde(default)]
    op: Option<String>,
    #[serde(default)]
    payload: Option<Value>,
    #[serde(default)]
    base_version: Option<i64>,
    /// Client-minted durable identity used for both HTTP idempotency and exact
    /// realtime echo matching. Mutations require this either here or in the
    /// Idempotency-Key header; canonical clients send both.
    #[serde(default)]
    key: Option<String>,
}

/// The @fiducia/sync write path, generic in `{table}` (only `infra_operations` is
/// DB-wired today). Persists the queued optimistic write, returns the committed row
/// version (a shared `WriteAck`) so the client adopts it and clears `dirty`, and
/// broadcasts the change. Honors the client's Idempotency-Key so a retry replays
/// the original ack instead of re-running the UPDATE (which re-bumps version).
async fn sync_write(
    State(st): State<Arc<AppState>>,
    Path(table): Path<String>,
    headers: HeaderMap,
    Json(req): Json<SyncWriteRequest>,
) -> Response {
    let session = match require_admin_api(&headers, &st).await {
        Ok(session) => session,
        Err(response) => return response,
    };
    if let Err(error) = require_sync_write_security(&headers, &st, &session) {
        return request_security_error(error);
    }
    let idem_key = match validated_write_key(&headers, &req) {
        Ok(key) => key,
        Err(error) => return write_key_error(error),
    };
    let fingerprint = sync_write_fingerprint(&session, &table, &req);
    let outcome = match table.as_str() {
        "infra_operations" => sync_write_infra_operations(&st, &req, &idem_key, &fingerprint).await,
        _ => {
            return (
                StatusCode::NOT_FOUND,
                Json(json!({ "error": "unsupported_sync_table", "table": table })),
            )
                .into_response()
        }
    };
    match outcome {
        Ok(SyncWriteOutcome::Replay(version)) => ack(&req.id, version),
        Ok(SyncWriteOutcome::Committed(row)) => {
            // Publish only after the row update and idempotency outcome commit
            // together. A websocket echo must never expose a rolled-back write.
            broadcast_infra_change(&st, &row, Some(&idem_key));
            ack(&req.id, row.version)
        }
        Err(SyncWriteError::InvalidId) => (
            StatusCode::BAD_REQUEST,
            Json(json!({ "error": "invalid_row_id" })),
        )
            .into_response(),
        Err(SyncWriteError::InvalidOperation) => (
            StatusCode::BAD_REQUEST,
            Json(json!({ "error": "invalid_sync_operation" })),
        )
            .into_response(),
        Err(SyncWriteError::InvalidPayload) => (
            StatusCode::BAD_REQUEST,
            Json(json!({ "error": "invalid_sync_payload" })),
        )
            .into_response(),
        Err(SyncWriteError::MissingBaseVersion) => (
            StatusCode::BAD_REQUEST,
            Json(json!({ "error": "base_version_required" })),
        )
            .into_response(),
        Err(SyncWriteError::InvalidBaseVersion) => (
            StatusCode::BAD_REQUEST,
            Json(json!({ "error": "invalid_base_version" })),
        )
            .into_response(),
        Err(SyncWriteError::VersionConflict { expected, actual }) => (
            StatusCode::CONFLICT,
            Json(json!({
                "error": "version_conflict",
                "expected_version": expected,
                "actual_version": actual,
            })),
        )
            .into_response(),
        Err(SyncWriteError::NotFound) => (
            StatusCode::NOT_FOUND,
            Json(json!({ "error": "row_not_found" })),
        )
            .into_response(),
        Err(SyncWriteError::IdempotencyInFlight) => (
            StatusCode::CONFLICT,
            Json(json!({ "error": "idempotency_in_flight" })),
        )
            .into_response(),
        Err(SyncWriteError::IdempotencyMismatch) => (
            StatusCode::CONFLICT,
            Json(json!({ "error": "idempotency_key_reused" })),
        )
            .into_response(),
        Err(SyncWriteError::Database(err)) => dependency_error("sync_write_failed", err),
    }
}

/// Reconcile the HTTP Idempotency-Key with the same durable key carried in the
/// queued-write body. Canonical clients send both. A mismatch is rejected: the
/// server must never persist under one identity and publish a different one as
/// the purported own-echo token.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum WriteKeyError {
    Missing,
    Invalid,
    Mismatch,
}

fn validated_write_key(
    headers: &HeaderMap,
    request: &SyncWriteRequest,
) -> Result<String, WriteKeyError> {
    let mut header_values = headers.get_all("idempotency-key").iter();
    let header_key = match header_values.next() {
        Some(value) => Some(value.to_str().map_err(|_| WriteKeyError::Invalid)?),
        None => None,
    };
    if header_values.next().is_some() {
        return Err(WriteKeyError::Invalid);
    }
    let body_key = request.key.as_deref();

    for key in [header_key, body_key].into_iter().flatten() {
        if key.is_empty()
            || key.len() > MAX_WRITE_KEY_BYTES
            || !key.bytes().all(|byte| byte.is_ascii_graphic())
        {
            return Err(WriteKeyError::Invalid);
        }
    }
    if let (Some(header_key), Some(body_key)) = (header_key, body_key) {
        if header_key != body_key {
            return Err(WriteKeyError::Mismatch);
        }
    }

    header_key
        .or(body_key)
        .map(str::to_owned)
        .ok_or(WriteKeyError::Missing)
}

fn write_key_error(error: WriteKeyError) -> Response {
    let code = match error {
        WriteKeyError::Missing => "idempotency_key_required",
        WriteKeyError::Invalid => "invalid_write_key",
        WriteKeyError::Mismatch => "write_key_mismatch",
    };
    (StatusCode::BAD_REQUEST, Json(json!({ "error": code }))).into_response()
}

/// Bind an idempotency key to the full semantic write identity. Object keys are
/// hashed in sorted order so harmless JSON field reordering does not turn an
/// exact retry into a mismatch.
fn sync_write_fingerprint(session: &Session, table: &str, request: &SyncWriteRequest) -> String {
    let mut hasher = Sha256::new();
    hasher.update(b"fiducia-admin-sync-write-v1\0");
    fingerprint_field(&mut hasher, session.user_id.as_bytes());
    fingerprint_field(&mut hasher, table.as_bytes());
    fingerprint_field(&mut hasher, request.id.as_bytes());
    let operation = request.op.as_deref().unwrap_or("upsert");
    fingerprint_field(&mut hasher, operation.as_bytes());
    match request.base_version {
        Some(version) => {
            hasher.update([1]);
            hasher.update(version.to_be_bytes());
        }
        None => hasher.update([0]),
    }
    if operation == "delete" {
        fingerprint_json(&mut hasher, &Value::Null);
    } else if let Some(payload) = &request.payload {
        fingerprint_json(&mut hasher, payload);
    } else {
        fingerprint_json(&mut hasher, &json!({}));
    }
    format!("{:x}", hasher.finalize())
}

fn fingerprint_field(hasher: &mut Sha256, value: &[u8]) {
    hasher.update((value.len() as u64).to_be_bytes());
    hasher.update(value);
}

fn fingerprint_json(hasher: &mut Sha256, value: &Value) {
    match value {
        Value::Null => hasher.update([0]),
        Value::Bool(value) => hasher.update([1, u8::from(*value)]),
        Value::Number(value) => {
            hasher.update([2]);
            fingerprint_field(hasher, value.to_string().as_bytes());
        }
        Value::String(value) => {
            hasher.update([3]);
            fingerprint_field(hasher, value.as_bytes());
        }
        Value::Array(values) => {
            hasher.update([4]);
            hasher.update((values.len() as u64).to_be_bytes());
            for value in values {
                fingerprint_json(hasher, value);
            }
        }
        Value::Object(values) => {
            hasher.update([5]);
            hasher.update((values.len() as u64).to_be_bytes());
            let mut entries = values.iter().collect::<Vec<_>>();
            entries.sort_unstable_by_key(|(key, _)| *key);
            for (key, value) in entries {
                fingerprint_field(hasher, key.as_bytes());
                fingerprint_json(hasher, value);
            }
        }
    }
}

/// Idempotency decision for a claimed/seen key.
enum Idem {
    Replay(i64),
    InFlight,
    Proceed,
}

/// Claim an idempotency key inside the SAME transaction as the protected row
/// update. A concurrent duplicate blocks on the unique key and then observes the
/// committed outcome; a failed owner rolls back both its claim and mutation.
async fn idempotency_claim(
    transaction: &DatabaseTransaction,
    key: &str,
    request_fingerprint: &str,
) -> Result<Idem, SyncWriteError> {
    let claimed = sync_idempotency_keys::Entity::insert(sync_idempotency_keys::ActiveModel {
        key: Set(key.to_string()),
        request_fingerprint: Set(Some(request_fingerprint.to_string())),
        ..Default::default()
    })
    .on_conflict(
        OnConflict::column(sync_idempotency_keys::Column::Key)
            .do_nothing()
            .to_owned(),
    )
    .exec_without_returning(transaction)
    .await
    .map_err(SyncWriteError::Database)?;
    if claimed > 0 {
        return Ok(Idem::Proceed);
    }
    let record = sync_idempotency_keys::Entity::find_by_id(key)
        .one(transaction)
        .await
        .map_err(SyncWriteError::Database)?
        .ok_or_else(|| {
            SyncWriteError::Database(DbErr::Custom(
                "idempotency key disappeared after unique-key conflict".to_string(),
            ))
        })?;
    idempotency_decision(
        record.request_fingerprint.as_deref(),
        record.committed_version,
        request_fingerprint,
    )
}

fn idempotency_decision(
    stored_fingerprint: Option<&str>,
    committed_version: Option<i64>,
    request_fingerprint: &str,
) -> Result<Idem, SyncWriteError> {
    let Some(stored_fingerprint) = stored_fingerprint else {
        // A pre-upgrade row cannot prove which request it protected. Replaying
        // its version for an arbitrary new payload would turn an old key into a
        // confused-deputy acknowledgement, so require the caller to mint a new
        // key instead.
        return Err(SyncWriteError::IdempotencyMismatch);
    };
    if stored_fingerprint != request_fingerprint {
        return Err(SyncWriteError::IdempotencyMismatch);
    }
    Ok(match committed_version {
        Some(version) => Idem::Replay(version),
        None => Idem::InFlight,
    })
}

/// Complete the claimed key in the surrounding row-mutation transaction.
async fn idempotency_complete(
    transaction: &DatabaseTransaction,
    key: &str,
    request_fingerprint: &str,
    version: i64,
) -> Result<(), SyncWriteError> {
    let result = sync_idempotency_keys::Entity::update_many()
        .col_expr(
            sync_idempotency_keys::Column::CommittedVersion,
            Expr::value(version),
        )
        .filter(sync_idempotency_keys::Column::Key.eq(key))
        .filter(sync_idempotency_keys::Column::RequestFingerprint.eq(request_fingerprint))
        .exec(transaction)
        .await
        .map_err(SyncWriteError::Database)?;
    if result.rows_affected != 1 {
        return Err(SyncWriteError::Database(DbErr::Custom(
            "idempotency completion did not update its claimed key".to_string(),
        )));
    }
    Ok(())
}

#[derive(Debug, Deserialize)]
struct CatchupParams {
    /// `since` remains an accepted alias for clients of the dormant pre-launch
    /// endpoint, but it now means a global sync sequence, never a row version.
    #[serde(default, alias = "since")]
    cursor: i64,
    #[serde(default)]
    limit: Option<u64>,
}

#[derive(Debug, Clone, Serialize, FromQueryResult)]
struct SyncCatchupChange {
    sequence: i64,
    #[serde(rename = "table")]
    table_name: String,
    op: String,
    id: String,
    version: i64,
    row: Option<Value>,
}

struct SyncCatchupPage {
    changes: Vec<SyncCatchupChange>,
    next_cursor: i64,
    has_more: bool,
}

/// Catch-up hydration returns a stable page of live-row upserts and durable
/// delete tombstones ordered by the plane-wide, commit-visible sync sequence.
async fn sync_catchup(
    State(st): State<Arc<AppState>>,
    Path(table): Path<String>,
    Query(params): Query<CatchupParams>,
    headers: HeaderMap,
) -> Response {
    if let Err(response) = require_admin_api(&headers, &st).await {
        return response;
    }
    let page_size = params.limit.unwrap_or(DEFAULT_CATCHUP_PAGE_SIZE);
    if params.cursor < 0 || page_size == 0 || page_size > MAX_CATCHUP_PAGE_SIZE {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({
                "error": "invalid_catchup_cursor_or_limit",
                "max_limit": MAX_CATCHUP_PAGE_SIZE,
            })),
        )
            .into_response();
    }
    let page = match table.as_str() {
        "infra_operations" => {
            let Some(db) = &st.db else {
                return dependency_error("database_unavailable", database_unavailable());
            };
            match catchup_infra_operations(db, params.cursor, page_size).await {
                Ok(page) => page,
                Err(err) => return dependency_error("sync_catchup_failed", err),
            }
        }
        _ => {
            return (
                StatusCode::NOT_FOUND,
                Json(json!({ "error": "unsupported_sync_table", "table": table })),
            )
                .into_response()
        }
    };
    Json(json!({
        "table": table,
        "cursor": params.cursor,
        "next_cursor": page.next_cursor,
        "has_more": page.has_more,
        "changes": page.changes,
    }))
    .into_response()
}

/// Build the shared write-ack the @fiducia/sync client reconciles against.
fn ack(id: &str, committed_version: i64) -> Response {
    Json(WriteAck {
        id: id.to_string(),
        committed_version,
    })
    .into_response()
}

#[derive(Debug)]
enum SyncWriteOutcome {
    Replay(i64),
    Committed(Box<InfraOperationsRow>),
}

#[derive(Debug)]
enum SyncWriteError {
    InvalidId,
    InvalidOperation,
    InvalidPayload,
    MissingBaseVersion,
    InvalidBaseVersion,
    VersionConflict { expected: i64, actual: i64 },
    NotFound,
    IdempotencyInFlight,
    IdempotencyMismatch,
    Database(DbErr),
}

/// Persist one queued optimistic write and its idempotency result atomically.
/// The guarded UPDATE enforces `base_version`, the trigger bumps per-row version
/// and global sequence, and websocket publication happens only after commit.
async fn sync_write_infra_operations(
    st: &AppState,
    req: &SyncWriteRequest,
    write_key: &str,
    request_fingerprint: &str,
) -> Result<SyncWriteOutcome, SyncWriteError> {
    let id = Uuid::parse_str(&req.id).map_err(|_| SyncWriteError::InvalidId)?;
    let op = req.op.as_deref().unwrap_or("upsert");
    if !matches!(op, "upsert" | "delete") {
        return Err(SyncWriteError::InvalidOperation);
    }
    let expected_version = req.base_version.ok_or(SyncWriteError::MissingBaseVersion)?;
    if expected_version < 0 {
        return Err(SyncWriteError::InvalidBaseVersion);
    }
    let db = st
        .db
        .as_ref()
        .ok_or_else(|| SyncWriteError::Database(database_unavailable()))?;

    let transaction = db.begin().await.map_err(SyncWriteError::Database)?;
    let outcome = sync_write_infra_operations_in_transaction(
        &transaction,
        req,
        id,
        op,
        expected_version,
        write_key,
        request_fingerprint,
    )
    .await;
    match outcome {
        Ok(outcome) => {
            transaction
                .commit()
                .await
                .map_err(SyncWriteError::Database)?;
            Ok(outcome)
        }
        Err(error) => {
            transaction
                .rollback()
                .await
                .map_err(SyncWriteError::Database)?;
            Err(error)
        }
    }
}

async fn sync_write_infra_operations_in_transaction(
    transaction: &DatabaseTransaction,
    req: &SyncWriteRequest,
    id: Uuid,
    op: &str,
    expected_version: i64,
    write_key: &str,
    request_fingerprint: &str,
) -> Result<SyncWriteOutcome, SyncWriteError> {
    match idempotency_claim(transaction, write_key, request_fingerprint).await? {
        Idem::Replay(version) => return Ok(SyncWriteOutcome::Replay(version)),
        Idem::InFlight => return Err(SyncWriteError::IdempotencyInFlight),
        Idem::Proceed => {}
    }

    let current = infra_operations::Entity::find_by_id(id)
        .one(transaction)
        .await
        .map_err(SyncWriteError::Database)?
        .ok_or(SyncWriteError::NotFound)?;
    if current.version != expected_version {
        return Err(SyncWriteError::VersionConflict {
            expected: expected_version,
            actual: current.version,
        });
    }

    // The version predicate belongs to the UPDATE itself, not only to the read
    // above: two transactions may both observe the same base before either wins.
    let mut update = infra_operations::Entity::update_many()
        .filter(infra_operations::Column::Id.eq(id))
        .filter(infra_operations::Column::Version.eq(expected_version));

    if op == "delete" {
        // A control-plane op is an audit record, not a droppable row: a "delete"
        // marks it failed. Version still bumps via the trigger.
        update = update.col_expr(
            infra_operations::Column::Status,
            Expr::value("failed".to_string()),
        );
    } else {
        let payload = req.payload.clone().unwrap_or_else(|| json!({}));
        let status = payload
            .get("status")
            .and_then(Value::as_str)
            .map(str::to_owned);
        let target_nodes = payload
            .get("target_nodes")
            .and_then(Value::as_i64)
            .map(i32::try_from)
            .transpose()
            .map_err(|_| SyncWriteError::InvalidPayload)?;
        let error = payload
            .get("error")
            .and_then(Value::as_str)
            .map(str::to_owned);
        let mut changed = false;
        if let Some(status) = status {
            if !matches!(status.as_str(), "requested" | "applied" | "failed") {
                return Err(SyncWriteError::InvalidPayload);
            }
            update = update.col_expr(infra_operations::Column::Status, Expr::value(status));
            changed = true;
        }
        if let Some(target_nodes) = target_nodes {
            if target_nodes < 3 {
                return Err(SyncWriteError::InvalidPayload);
            }
            update = update.col_expr(
                infra_operations::Column::TargetNodes,
                Expr::value(Some(target_nodes)),
            );
            changed = true;
        }
        if let Some(error) = error {
            if error.len() > 500 {
                return Err(SyncWriteError::InvalidPayload);
            }
            update = update.col_expr(infra_operations::Column::Error, Expr::value(Some(error)));
            changed = true;
        }
        // Preserve the sync contract: even an empty patch is a committed write
        // whose trigger advances the row version.
        if !changed {
            update = update.col_expr(
                infra_operations::Column::Status,
                Expr::value(current.status),
            );
        }
    }

    let result = update
        .exec(transaction)
        .await
        .map_err(SyncWriteError::Database)?;
    if result.rows_affected != 1 {
        let actual = infra_operations::Entity::find_by_id(id)
            .one(transaction)
            .await
            .map_err(SyncWriteError::Database)?;
        return match actual {
            Some(row) => Err(SyncWriteError::VersionConflict {
                expected: expected_version,
                actual: row.version,
            }),
            None => Err(SyncWriteError::NotFound),
        };
    }
    let row = infra_operations::Entity::find_by_id(id)
        .one(transaction)
        .await
        .map_err(SyncWriteError::Database)?
        .ok_or(SyncWriteError::NotFound)?;
    idempotency_complete(transaction, write_key, request_fingerprint, row.version).await?;
    Ok(SyncWriteOutcome::Committed(Box::new(row)))
}

/// Load one bounded catch-up page in a single SQL snapshot. Splitting the live
/// row and tombstone reads into separate statements would allow a commit between
/// them to advance the returned cursor past a row the first statement did not see.
async fn catchup_infra_operations(
    db: &DatabaseConnection,
    cursor: i64,
    page_size: u64,
) -> Result<SyncCatchupPage, DbErr> {
    let fetch_limit = i64::try_from(page_size + 1)
        .map_err(|_| DbErr::Custom("catch-up page size overflow".to_string()))?;
    let statement = Statement::from_sql_and_values(
        DbBackend::Postgres,
        r#"
select live.sync_sequence as sequence,
       'infra_operations'::text as table_name,
       'upsert'::text as op,
       live.id::text as id,
       live.version as version,
       to_jsonb(live) as row
  from public.infra_operations live
 where live.sync_sequence > $1
union all
select tomb.sequence as sequence,
       tomb.table_name as table_name,
       'delete'::text as op,
       tomb.row_id as id,
       tomb.row_version as version,
       null::jsonb as row
  from public.sync_tombstones tomb
 where tomb.table_name = 'infra_operations'
   and tomb.sequence > $1
order by sequence
limit $2
"#,
        [cursor.into(), fetch_limit.into()],
    );
    let query_rows = db.query_all(statement).await?;
    let changes = query_rows
        .iter()
        .map(|row| SyncCatchupChange::from_query_result(row, ""))
        .collect::<Result<Vec<_>, _>>()?;
    Ok(finish_catchup_page(changes, cursor, page_size))
}

fn finish_catchup_page(
    mut changes: Vec<SyncCatchupChange>,
    cursor: i64,
    page_size: u64,
) -> SyncCatchupPage {
    let page_size = page_size as usize;
    let has_more = changes.len() > page_size;
    if has_more {
        changes.truncate(page_size);
    }
    let next_cursor = changes.last().map_or(cursor, |change| change.sequence);
    SyncCatchupPage {
        changes,
        next_cursor,
        has_more,
    }
}

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

/// Broadcast a single infra_operations upsert as a `fiducia:sync` frame, built from
/// the shared fiducia-sync-core ChangeEvent so server and client agree on one shape.
fn broadcast_infra_change(st: &AppState, row: &InfraOperationsRow, write_key: Option<&str>) {
    let change = ChangeEvent {
        table: "infra_operations".to_string(),
        op: ChangeOp::Upsert,
        id: row.id.to_string(),
        version: row.version,
        row: serde_json::to_value(row).unwrap_or_default(),
        at_ms: unix_epoch_ms() as i64,
        write_key: write_key.map(str::to_owned),
    };
    let frame = json!({ "event": "fiducia:sync", "changes": [change] });
    let _ = st.stream_tx.send(frame.to_string());
}

fn unix_epoch_ms() -> u128 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis()
}

/// The admin-plane sync socket: on connect, sends a hello frame, then forwards
/// every `fiducia:sync` broadcast frame verbatim (mirrors fiducia-backend's WS).
async fn admin_ws(
    State(st): State<Arc<AppState>>,
    headers: HeaderMap,
    ws: WebSocketUpgrade,
) -> Response {
    if let Err(response) = require_admin_api(&headers, &st).await {
        return response;
    }
    if let Err(error) = st.request_security.require_same_origin(&headers) {
        return request_security_error(error);
    }
    let rx = st.stream_tx.subscribe();
    ws.on_upgrade(move |socket| admin_ws_stream(socket, rx))
}

async fn admin_ws_stream(mut socket: WebSocket, mut rx: broadcast::Receiver<String>) {
    let hello = json!({ "event": "connected", "service": SERVICE }).to_string();
    if socket.send(Message::Text(hello)).await.is_err() {
        return;
    }
    loop {
        tokio::select! {
            frame = rx.recv() => match frame {
                Ok(payload) => {
                    if socket.send(Message::Text(payload)).await.is_err() {
                        return;
                    }
                }
                Err(broadcast::error::RecvError::Lagged(_)) => {}
                Err(broadcast::error::RecvError::Closed) => return,
            },
            msg = socket.recv() => match msg {
                Some(Ok(Message::Close(_))) | None => return,
                Some(Err(_)) => return,
                _ => {}
            }
        }
    }
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
mod sync_tests {
    use super::*;
    use axum::body::Body;
    use axum::http::Request;
    use tower::ServiceExt;

    pub(super) fn test_state() -> Arc<AppState> {
        Arc::new(AppState {
            auth_url: "http://localhost:8097".into(),
            brain_url: "http://localhost:8095".into(),
            supabase_url: "https://example.supabase.co".into(),
            supabase_publishable_key: "test-publishable-key".into(),
            db: None,
            stream_tx: broadcast::channel(16).0,
            request_security: test_request_security(),
            prometheus_url: None,
            loki_url: None,
            grafana_public_url: None,
            node_urls: Vec::new(),
        })
    }

    async fn post_sync(
        state: Arc<AppState>,
        table: &str,
        key: Option<&str>,
    ) -> axum::response::Response {
        let app = Router::new()
            .route("/api/admin/sync/:table", post(sync_write))
            .with_state(state);
        let mut builder = Request::builder()
            .method("POST")
            .uri(format!("/api/admin/sync/{table}"))
            .header(CONTENT_TYPE, "application/json");
        if let Some(k) = key {
            builder = builder.header("idempotency-key", k);
        }
        let body = json!({ "id": "op1", "op": "upsert" }).to_string();
        app.oneshot(builder.body(Body::from(body)).unwrap())
            .await
            .unwrap()
    }

    #[tokio::test]
    async fn sync_write_requires_an_operator_session_before_table_or_database_access() {
        let response = post_sync(test_state(), "infra_operations", None).await;
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);

        let unsupported = post_sync(test_state(), "operators", None).await;
        assert_eq!(unsupported.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn serves_the_vendored_sync_bundle() {
        let app = Router::new().route("/assets/fiducia-sync.js", get(sync_js));
        let resp = app
            .oneshot(
                Request::builder()
                    .uri("/assets/fiducia-sync.js")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let ct = resp
            .headers()
            .get(CONTENT_TYPE)
            .and_then(|v| v.to_str().ok())
            .unwrap_or("");
        assert!(ct.contains("javascript"), "ct={ct}");
        let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap();
        assert!(String::from_utf8_lossy(&bytes).contains("FiduciaSyncAdmin"));
    }

    #[test]
    fn durable_write_key_must_match_header_and_body() {
        let request = SyncWriteRequest {
            id: "op1".into(),
            op: Some("upsert".into()),
            payload: None,
            base_version: Some(7),
            key: Some("write-key-1".into()),
        };
        let mut headers = HeaderMap::new();
        headers.insert("idempotency-key", HeaderValue::from_static("write-key-1"));
        assert_eq!(
            validated_write_key(&headers, &request).unwrap(),
            "write-key-1"
        );

        headers.insert("idempotency-key", HeaderValue::from_static("write-key-2"));
        assert!(validated_write_key(&headers, &request).is_err());

        headers.append("idempotency-key", HeaderValue::from_static("write-key-1"));
        assert_eq!(
            validated_write_key(&headers, &request),
            Err(WriteKeyError::Invalid)
        );

        let invalid_body = SyncWriteRequest {
            key: Some("not a header-safe key".into()),
            ..request
        };
        assert_eq!(
            validated_write_key(&HeaderMap::new(), &invalid_body),
            Err(WriteKeyError::Invalid)
        );
    }

    #[test]
    fn every_mutation_requires_a_nonempty_key_but_body_only_is_accepted() {
        let mut request = SyncWriteRequest {
            id: "op1".into(),
            op: Some("upsert".into()),
            payload: None,
            base_version: Some(7),
            key: None,
        };
        assert_eq!(
            validated_write_key(&HeaderMap::new(), &request),
            Err(WriteKeyError::Missing)
        );

        request.key = Some("body-only-key".into());
        assert_eq!(
            validated_write_key(&HeaderMap::new(), &request).unwrap(),
            "body-only-key"
        );
    }

    #[test]
    fn catchup_page_advances_only_through_returned_global_sequences() {
        let change = |sequence| SyncCatchupChange {
            sequence,
            table_name: "infra_operations".to_string(),
            op: "upsert".to_string(),
            id: format!("op-{sequence}"),
            version: 1,
            row: Some(json!({ "id": format!("op-{sequence}") })),
        };
        let page = finish_catchup_page(vec![change(10), change(11), change(12)], 9, 2);
        assert_eq!(page.changes.len(), 2);
        assert_eq!(page.next_cursor, 11);
        assert!(page.has_more);

        let empty = finish_catchup_page(Vec::new(), page.next_cursor, 2);
        assert_eq!(empty.next_cursor, 11);
        assert!(!empty.has_more);
    }

    #[tokio::test]
    async fn sync_mutation_requires_a_nonnegative_base_version_before_database_access() {
        let mut request = SyncWriteRequest {
            id: "00000000-0000-0000-0000-000000000001".into(),
            op: Some("upsert".into()),
            payload: Some(json!({ "status": "applied" })),
            base_version: None,
            key: Some("write-key-1".into()),
        };
        assert!(matches!(
            sync_write_infra_operations(&test_state(), &request, "write-key-1", "fingerprint")
                .await,
            Err(SyncWriteError::MissingBaseVersion)
        ));

        request.base_version = Some(-1);
        assert!(matches!(
            sync_write_infra_operations(&test_state(), &request, "write-key-1", "fingerprint")
                .await,
            Err(SyncWriteError::InvalidBaseVersion)
        ));
    }

    #[test]
    fn write_fingerprint_is_canonical_and_binds_every_semantic_identity() {
        let session = Session::test_admin_bearer("operator-a", "verified.jwt");
        let first = SyncWriteRequest {
            id: "00000000-0000-0000-0000-000000000001".into(),
            op: Some("upsert".into()),
            payload: Some(
                serde_json::from_str(r#"{"status":"applied","target_nodes":7}"#).unwrap(),
            ),
            base_version: Some(4),
            key: Some("write-key-1".into()),
        };
        let reordered = SyncWriteRequest {
            payload: Some(
                serde_json::from_str(r#"{"target_nodes":7,"status":"applied"}"#).unwrap(),
            ),
            ..SyncWriteRequest {
                id: first.id.clone(),
                op: first.op.clone(),
                payload: None,
                base_version: first.base_version,
                key: first.key.clone(),
            }
        };
        let fingerprint = sync_write_fingerprint(&session, "infra_operations", &first);
        assert_eq!(fingerprint.len(), 64);
        assert!(fingerprint.bytes().all(|byte| byte.is_ascii_hexdigit()));
        assert_eq!(
            fingerprint,
            sync_write_fingerprint(&session, "infra_operations", &reordered)
        );

        let changed_payload = SyncWriteRequest {
            payload: Some(json!({ "status": "failed", "target_nodes": 7 })),
            ..reordered
        };
        assert_ne!(
            fingerprint,
            sync_write_fingerprint(&session, "infra_operations", &changed_payload)
        );
        assert_ne!(
            fingerprint,
            sync_write_fingerprint(
                &Session::test_admin_bearer("operator-b", "verified.jwt"),
                "infra_operations",
                &first,
            )
        );
        assert_ne!(
            fingerprint,
            sync_write_fingerprint(&session, "other_table", &first)
        );
    }

    #[test]
    fn replay_requires_the_original_fingerprint() {
        assert!(matches!(
            idempotency_decision(Some("fingerprint-a"), Some(8), "fingerprint-a"),
            Ok(Idem::Replay(8))
        ));
        assert!(matches!(
            idempotency_decision(Some("fingerprint-a"), Some(8), "fingerprint-b"),
            Err(SyncWriteError::IdempotencyMismatch)
        ));
        // A completed pre-upgrade record has no reconstructable fingerprint;
        // fail closed rather than acknowledge an unprovable request.
        assert!(matches!(
            idempotency_decision(None, Some(8), "fingerprint-a"),
            Err(SyncWriteError::IdempotencyMismatch)
        ));
        assert!(matches!(
            idempotency_decision(Some("fingerprint-a"), None, "fingerprint-a"),
            Ok(Idem::InFlight)
        ));
    }
}

#[cfg(test)]
mod auth_flow_tests {
    use super::*;
    use axum::body::Body;
    use axum::http::Request;
    use tower::ServiceExt;

    pub(super) async fn spawn_mock(app: Router) -> (String, tokio::task::JoinHandle<()>) {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let task = tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });
        (format!("http://{address}"), task)
    }

    #[tokio::test]
    async fn login_requires_the_operator_registry_after_trusted_auth() {
        let supabase = Router::new().route(
            "/auth/v1/token",
            post(|| async { Json(json!({ "access_token": "verified.jwt" })) }),
        );
        let auth = Router::new().route(
            "/v1/me",
            get(|| async {
                Json(json!({
                    "user": {
                        "user_id": "00000000-0000-0000-0000-000000000001",
                        "email": "operator@example.com",
                        "orgs": ["org_admin"],
                        "roles": ["operator"]
                    }
                }))
            }),
        );
        let (supabase_url, supabase_task) = spawn_mock(supabase).await;
        let (auth_url, auth_task) = spawn_mock(auth).await;

        let state = Arc::new(AppState {
            auth_url,
            brain_url: "http://localhost:8095".into(),
            supabase_url,
            supabase_publishable_key: "public-publishable-key".into(),
            db: None,
            stream_tx: broadcast::channel(4).0,
            request_security: test_request_security(),
            prometheus_url: None,
            loki_url: None,
            grafana_public_url: None,
            node_urls: Vec::new(),
        });
        let login_nonce = "registry-test-login-nonce";
        let login_csrf = state
            .request_security
            .csrf_token(&format!("login\0{login_nonce}"));
        let app = Router::new()
            .route("/login", post(login_submit))
            .with_state(state);
        let response = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/login")
                    .header("host", "admin.fiducia.cloud")
                    .header("origin", "https://admin.fiducia.cloud")
                    .header("sec-fetch-site", "same-origin")
                    .header("cookie", format!("{LOGIN_CSRF_COOKIE}={login_nonce}"))
                    .header(CONTENT_TYPE, "application/x-www-form-urlencoded")
                    .body(Body::from(format!(
                        "csrf_token={login_csrf}&email=operator%40example.com&password=correct-horse"
                    )))
                    .unwrap(),
            )
            .await
            .unwrap();

        supabase_task.abort();
        auth_task.abort();

        assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
        assert!(response.headers().get(SET_COOKIE).is_none());
    }

    #[test]
    fn logout_expires_only_the_admin_cookie() {
        let cookie = clear_session_cookie();
        assert!(cookie.starts_with(&format!("{ADMIN_SESSION_COOKIE}=")));
        assert!(cookie.contains("Max-Age=0"));
        assert!(cookie.contains("HttpOnly"));
        assert!(cookie.contains("SameSite=Strict"));
        assert!(cookie.contains("Path=/"));
        assert!(!cookie.contains("Domain="));
        assert!(!cookie.contains("fiducia_session="));
        if !cfg!(debug_assertions) {
            assert!(cookie.starts_with("__Host-"));
            assert!(cookie.contains("; Secure"));
        }
    }

    #[test]
    fn scale_target_rejects_below_floor_and_i32_overflow() {
        assert!(!scale_target_is_valid(0));
        assert!(!scale_target_is_valid(MIN_SCALE_TARGET_NODES - 1));
        assert!(scale_target_is_valid(MIN_SCALE_TARGET_NODES));
        assert!(scale_target_is_valid(i32::MAX as u32));
        // Above i32::MAX would wrap negative in the audit record's i32 column.
        assert!(!scale_target_is_valid(i32::MAX as u32 + 1));
        assert!(!scale_target_is_valid(u32::MAX));
    }

    #[test]
    fn only_mutating_registry_roles_are_enabled() {
        for role in ["owner", "admin", "operator"] {
            assert!(operator_registry_role_allows_access(role), "role={role}");
        }
        for role in ["viewer", "authenticated", "customer", ""] {
            assert!(!operator_registry_role_allows_access(role), "role={role}");
        }
    }

    #[test]
    fn grafana_public_url_validation_rejects_dangerous_schemes() {
        // Allowed: http(s) URLs and root-relative paths (deep-link prefixes).
        assert!(grafana_public_url_is_valid("https://grafana.example.com"));
        assert!(grafana_public_url_is_valid("http://dd-grafana:3000"));
        assert!(grafana_public_url_is_valid("/telemetry"));
        // Rejected: anything that could become a dangerous or off-origin href.
        assert!(!grafana_public_url_is_valid("javascript:alert(1)"));
        assert!(!grafana_public_url_is_valid(
            "data:text/html,<script>1</script>"
        ));
        assert!(!grafana_public_url_is_valid("//evil.example.com"));
        assert!(!grafana_public_url_is_valid("ftp://grafana"));
        assert!(!grafana_public_url_is_valid("telemetry")); // not root-relative
                                                            // A set-but-invalid value fails startup closed; unset stays a no-op.
        std::env::set_var("FIDUCIA_GRAFANA_PUBLIC_URL", "javascript:alert(1)");
        assert!(validated_grafana_public_url().is_err());
        std::env::set_var("FIDUCIA_GRAFANA_PUBLIC_URL", "/telemetry");
        assert_eq!(
            validated_grafana_public_url().unwrap(),
            Some("/telemetry".to_string())
        );
        std::env::remove_var("FIDUCIA_GRAFANA_PUBLIC_URL");
        assert_eq!(validated_grafana_public_url().unwrap(), None);
    }

    #[test]
    fn insecure_cookie_escape_requires_an_explicit_truthy_value() {
        assert!(explicitly_enabled(Some("1")));
        assert!(explicitly_enabled(Some("true")));
        assert!(explicitly_enabled(Some(" TRUE ")));
        assert!(!explicitly_enabled(None));
        assert!(!explicitly_enabled(Some("0")));
        assert!(!explicitly_enabled(Some("yes")));
        assert_eq!(cookie_secure_suffix_for(false, true), "");
        assert_eq!(cookie_secure_suffix_for(false, false), "; Secure");
        assert_eq!(cookie_secure_suffix_for(true, true), "; Secure");
        assert_eq!(cookie_secure_suffix_for(true, false), "; Secure");
    }
}

#[cfg(test)]
mod cluster_tests {
    use super::auth_flow_tests::spawn_mock;
    use super::*;
    use axum::body::Body;
    use axum::http::Request;
    use tower::ServiceExt;

    fn cluster_router(state: Arc<AppState>) -> Router {
        Router::new()
            .route("/cluster", get(cluster_page))
            .route("/cluster/shards", get(cluster_shards_fragment))
            .route("/cluster/nodes", get(cluster_nodes_fragment))
            .route("/cluster/events", get(cluster_events_fragment))
            .route("/api/admin/cluster/overview", get(cluster_overview_api))
            .route("/api/admin/cluster/shards", get(cluster_shards_api))
            .route("/api/admin/cluster/events", get(cluster_events_api))
            .route("/api/admin/cluster/metrics", get(cluster_metrics_api))
            .with_state(state)
    }

    async fn get_with(router: Router, uri: &str, bearer: Option<&str>, htmx: bool) -> Response {
        let mut builder = Request::builder()
            .uri(uri)
            .header("host", "admin.fiducia.cloud");
        if let Some(token) = bearer {
            builder = builder.header("authorization", format!("Bearer {token}"));
        }
        if htmx {
            builder = builder.header("hx-request", "true");
        }
        router
            .oneshot(builder.body(Body::empty()).unwrap())
            .await
            .unwrap()
    }

    async fn body_json(response: Response) -> Value {
        let bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        serde_json::from_slice(&bytes).unwrap()
    }

    async fn body_text(response: Response) -> String {
        let bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        String::from_utf8_lossy(&bytes).into_owned()
    }

    /// A test AppState with the Cluster Insight upstreams under test control.
    fn insight_state(
        auth_url: String,
        brain_url: String,
        prometheus_url: Option<String>,
        loki_url: Option<String>,
        grafana_public_url: Option<String>,
        node_urls: Vec<String>,
    ) -> Arc<AppState> {
        Arc::new(AppState {
            auth_url,
            brain_url,
            supabase_url: "https://example.supabase.co".into(),
            supabase_publishable_key: "test-publishable-key".into(),
            db: None,
            stream_tx: broadcast::channel(16).0,
            request_security: test_request_security(),
            prometheus_url,
            loki_url,
            grafana_public_url,
            node_urls,
        })
    }

    #[tokio::test]
    async fn audit_routes_require_an_operator_session_before_database_access() {
        let app = Router::new()
            .route("/audit", get(audit_page))
            .route("/api/admin/audit", get(audit_api))
            .with_state(sync_tests::test_state());

        let page = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri("/audit")
                    .header("host", "admin.fiducia.cloud")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(page.status(), StatusCode::SEE_OTHER);

        let api = app
            .oneshot(
                Request::builder()
                    .uri("/api/admin/audit")
                    .header("host", "admin.fiducia.cloud")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(api.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn every_cluster_route_requires_a_session() {
        // Anonymous HTML routes redirect to the login page…
        for uri in [
            "/cluster",
            "/cluster/shards",
            "/cluster/nodes",
            "/cluster/events",
        ] {
            let response =
                get_with(cluster_router(sync_tests::test_state()), uri, None, false).await;
            assert_eq!(response.status(), StatusCode::SEE_OTHER, "uri={uri}");
            assert_eq!(
                response
                    .headers()
                    .get(LOCATION)
                    .and_then(|v| v.to_str().ok()),
                Some("/login"),
                "uri={uri}"
            );
        }
        // …and anonymous API routes get a machine-readable 401.
        for uri in [
            "/api/admin/cluster/overview",
            "/api/admin/cluster/shards",
            "/api/admin/cluster/events",
            "/api/admin/cluster/metrics",
        ] {
            let response =
                get_with(cluster_router(sync_tests::test_state()), uri, None, false).await;
            assert_eq!(response.status(), StatusCode::UNAUTHORIZED, "uri={uri}");
        }
    }

    #[tokio::test]
    async fn cluster_routes_reject_a_verified_non_operator_session() {
        // fiducia-auth verifies the token but reports no operator role.
        let auth = Router::new().route(
            "/v1/me",
            get(|| async {
                Json(json!({
                    "user": {
                        "user_id": "00000000-0000-0000-0000-000000000002",
                        "email": "customer@example.com",
                        "roles": ["customer"]
                    }
                }))
            }),
        );
        let (auth_url, auth_task) = spawn_mock(auth).await;
        let state = insight_state(
            auth_url,
            "http://localhost:8095".into(),
            None,
            None,
            None,
            Vec::new(),
        );

        let page = get_with(
            cluster_router(state.clone()),
            "/cluster",
            Some("verified.jwt"),
            false,
        )
        .await;
        assert_eq!(page.status(), StatusCode::FORBIDDEN);

        let api = get_with(
            cluster_router(state),
            "/api/admin/cluster/overview",
            Some("verified.jwt"),
            false,
        )
        .await;
        assert_eq!(api.status(), StatusCode::FORBIDDEN);
        assert_eq!(body_json(api).await["error"], "forbidden");

        auth_task.abort();
    }

    const TEST_INTERNAL_SECRET: &str = "test-internal-secret";

    /// Trusted-hop check for the node mocks: the fan-out must present the same
    /// `x-fiducia-internal-auth` secret the real node plane enforces.
    fn internal_auth_ok(headers: &HeaderMap) -> bool {
        headers
            .get("x-fiducia-internal-auth")
            .and_then(|value| value.to_str().ok())
            == Some(TEST_INTERNAL_SECRET)
    }

    async fn healthy_node_shards(headers: HeaderMap) -> Response {
        if !internal_auth_ok(&headers) {
            return (
                StatusCode::UNAUTHORIZED,
                Json(json!({ "error": "internal_auth" })),
            )
                .into_response();
        }
        Json(json!({
            "node_id": "node-ok",
            "shard_count": 2,
            "leader_count": 1,
            "follower_count": 1,
            "quorum": {
                "leaderless_shards": [],
                "at_risk_led_shards": [],
                "all_led_shards_have_quorum": true,
                "storage_faulted_shards": [],
                "unresponsive_shards": [],
                "status_complete": true,
                "all_shard_storage_healthy": true
            },
            "shards": [
                {
                    "shard_id": 0, "role": "leader", "term": 3, "leader_id": "node-ok",
                    "commit_index": 42, "last_applied": 42, "last_log_index": 42,
                    "snapshot_index": 0, "retained_log_entries": 42,
                    "storage_healthy": true, "healthy_replicas": 3, "has_quorum": true,
                    "replication": [
                        { "peer": "node-down", "match_index": 42, "lag": 0, "in_flight": false }
                    ],
                    "metrics": {
                        "append_rtt_ms_last": 2, "quorum_rtt_ms_last": 3,
                        "follower_lag_max": 0, "leader_transfer_count": 1
                    }
                },
                {
                    "shard_id": 1, "role": "follower", "term": 3, "leader_id": "node-down",
                    "commit_index": 10, "last_applied": 10, "last_log_index": 10,
                    "snapshot_index": 0, "retained_log_entries": 10,
                    "storage_healthy": true, "healthy_replicas": 0, "has_quorum": false,
                    "metrics": { "follower_lag_max": 0, "leader_transfer_count": 0 }
                }
            ]
        }))
        .into_response()
    }

    async fn healthy_node_metrics(headers: HeaderMap) -> Response {
        if !internal_auth_ok(&headers) {
            return (
                StatusCode::UNAUTHORIZED,
                Json(json!({ "error": "internal_auth" })),
            )
                .into_response();
        }
        Json(json!({
            "operations": [{
                "op": "kv.put", "count": 12, "errors": 1, "avg_ms": 2.5, "max_ms": 20.0,
                "buckets": [
                    { "le_ms": 1.0, "count": 4 }, { "le_ms": 5.0, "count": 10 },
                    { "le_ms": 25.0, "count": 12 }, { "le_ms": 100.0, "count": 12 },
                    { "le_ms": 500.0, "count": 12 }, { "le_ms": 2000.0, "count": 12 },
                    { "le_ms": null, "count": 12 }
                ]
            }]
        }))
        .into_response()
    }

    /// A captured fiducia-node JSON log line (tracing JSON layer, flattened
    /// event fields) as promtail ships it to Loki.
    const LOKI_TRANSFER_LINE: &str = r#"{"timestamp":"2025-07-13T09:58:01.123456Z","level":"INFO","message":"observed raft leadership transition","metric.name":"fiducia.raft.leader_transfer","shard":0,"from":"Follower","to":"Leader","reason":"became_leader","count":1,"target":"fiducia_node::consensus"}"#;

    /// The full read path: mocked fiducia-auth (verified operator), fiducia-brain
    /// (status + membership with dialable node addresses), one healthy node, one
    /// node answering 500, Loki, and Prometheus. The overview must merge what is
    /// reachable and carry the down node as a per-node error — never a 5xx.
    #[tokio::test]
    async fn overview_merges_all_planes_and_tolerates_a_down_node() {
        // The upstream client reads the trusted-hop secret once (OnceLock); the
        // node mocks below verify the fan-out actually presents it.
        std::env::set_var("FIDUCIA_INTERNAL_SECRET", TEST_INTERNAL_SECRET);

        let auth = Router::new().route(
            "/v1/me",
            get(|| async {
                // `dev-admin` exercises the debug-build registry shortcut, so this
                // test (db: None) covers the full handler path after auth.
                Json(json!({
                    "user": { "user_id": "dev-admin", "email": "op@example.com", "roles": ["admin"] }
                }))
            }),
        );
        let (auth_url, auth_task) = spawn_mock(auth).await;

        let node_ok = Router::new()
            .route("/v1/observe/shards", get(healthy_node_shards))
            .route("/v1/observe/metrics", get(healthy_node_metrics));
        let (node_ok_url, node_ok_task) = spawn_mock(node_ok).await;

        let node_down = Router::new()
            .route(
                "/v1/observe/shards",
                get(|| async { StatusCode::INTERNAL_SERVER_ERROR }),
            )
            .route(
                "/v1/observe/metrics",
                get(|| async { StatusCode::INTERNAL_SERVER_ERROR }),
            );
        let (node_down_url, node_down_task) = spawn_mock(node_down).await;

        // The brain reports both nodes with the mock servers' real addresses, so
        // discovery (no FIDUCIA_NODE_URLS) dials them.
        let ok_address = node_ok_url.trim_start_matches("http://").to_string();
        let down_address = node_down_url.trim_start_matches("http://").to_string();
        let brain = Router::new()
            .route(
                "/v1/config",
                get(|| async {
                    Json(json!({
                        "cluster_id": "fiducia-test", "shard_count": 2, "replication_factor": 3
                    }))
                }),
            )
            .route(
                "/v1/policies",
                get(|| async {
                    Json(json!({ "policies": [{ "namespace": "orders", "home_region": "eu" }] }))
                }),
            )
            .route(
                "/v1/status",
                get(|| async {
                    Json(json!({
                        "service": "fiducia-brain", "version": "0.1.0",
                        "cluster_id": "fiducia-test", "nodes": 2,
                        "shard_count": 2, "replication_factor": 3,
                        "ready": false,
                        "topology": { "nodes_by_health": { "healthy": 1, "suspect": 1 } },
                        "placement": {
                            "placed_shards": 2, "unplaced_shards": 0,
                            "under_replicated_shards": 0, "leaderless_shards": 0,
                            "shards_with_unhealthy_replicas": 1
                        },
                        "brain_cluster": {
                            "placement_generation": 7, "is_leader": true, "leader": null,
                            "available": true, "ha_configured": false
                        }
                    }))
                }),
            )
            .route(
                "/v1/nodes",
                get(move || {
                    let ok_address = ok_address.clone();
                    let down_address = down_address.clone();
                    async move {
                    Json(json!({
                        "nodes": [
                            {
                                "node_id": "node-ok", "address": ok_address, "health": "healthy",
                                "failure_domain": "gcp/europe-west1", "last_seen_ms": 1_752_400_000_000i64,
                                "hosted_shards": [0, 1], "leading_shards": [0]
                            },
                            {
                                "node_id": "node-down", "address": down_address, "health": "suspect",
                                "failure_domain": "aws/eu-central-1", "last_seen_ms": 1_752_399_000_000i64,
                                "hosted_shards": [0, 1], "leading_shards": [1]
                            }
                        ]
                    }))
                    }
                }),
            );
        let (brain_url, brain_task) = spawn_mock(brain).await;

        let loki = Router::new().route(
            "/loki/api/v1/query_range",
            get(|| async {
                Json(json!({
                    "status": "success",
                    "data": {
                        "resultType": "streams",
                        "result": [{
                            "stream": { "namespace": "fiducia", "pod": "fiducia-node-0" },
                            "values": [["1752400681123456789", LOKI_TRANSFER_LINE]]
                        }]
                    }
                }))
            }),
        );
        let (loki_url, loki_task) = spawn_mock(loki).await;

        let prometheus = Router::new()
            .route(
                "/api/v1/query",
                get(|| async {
                    Json(json!({
                        "status": "success",
                        "data": {
                            "resultType": "vector",
                            "result": [
                                { "metric": { "pod": "fiducia-node-0" }, "value": [1752400681.0, "1"] },
                                { "metric": { "pod": "fiducia-node-1" }, "value": [1752400681.0, "1"] },
                                { "metric": { "pod": "fiducia-brain-0" }, "value": [1752400681.0, "0"] }
                            ]
                        }
                    }))
                }),
            )
            .route(
                "/api/v1/query_range",
                get(|| async {
                    Json(json!({
                        "status": "success",
                        "data": {
                            "resultType": "matrix",
                            "result": [{
                                "metric": { "pod": "fiducia-node-0" },
                                "values": [[1752400621.0, "1"], [1752400681.0, "1"]]
                            }]
                        }
                    }))
                }),
            );
        let (prometheus_url, prometheus_task) = spawn_mock(prometheus).await;

        let state = insight_state(
            auth_url,
            brain_url,
            Some(prometheus_url),
            Some(loki_url),
            Some("/telemetry".into()),
            Vec::new(), // discovery path: node URLs come from brain /v1/nodes
        );

        // -- JSON overview: merged shards, per-node outcomes, quorum rollup ----
        let overview = get_with(
            cluster_router(state.clone()),
            "/api/admin/cluster/overview",
            Some("verified.jwt"),
            false,
        )
        .await;
        assert_eq!(overview.status(), StatusCode::OK);
        let overview = body_json(overview).await;
        assert_eq!(overview["cluster"]["cluster_id"], "fiducia-test");
        assert_eq!(overview["config"]["shard_count"], 2);
        assert_eq!(overview["policies"][0]["namespace"], "orders");
        let shards = overview["shards"].as_array().unwrap();
        assert_eq!(shards.len(), 2, "both shards merged from the healthy node");
        assert_eq!(shards[0]["shard_id"], 0);
        assert_eq!(shards[0]["reported_by"], "node-ok");
        assert_eq!(shards[0]["leader_view"], true);
        assert_eq!(shards[0]["replication"][0]["peer"], "node-down");
        assert_eq!(shards[1]["leader_view"], false, "leader is the down node");
        let observations = overview["node_observations"].as_array().unwrap();
        assert_eq!(observations.len(), 2);
        assert!(observations[0]["error"].is_null());
        assert!(
            observations[1]["error"].as_str().unwrap().contains("500"),
            "the down node is an error entry, not a page failure"
        );
        assert_eq!(overview["quorum"]["nodes_reporting"], 1);
        assert_eq!(overview["quorum"]["nodes_failed"], 1);
        // Shard 1's leader is the *down* node: its follower row still knows a
        // leader_id, so it is "leader unreached", never miscounted as leaderless
        // during a partial-visibility incident (M5).
        assert_eq!(overview["quorum"]["leaderless"], json!([]));
        assert_eq!(overview["quorum"]["leader_unreached"], json!([1]));
        assert_eq!(overview["prometheus"]["state"], "up");
        assert_eq!(
            overview["prometheus"]["targets"], 2,
            "only value==\"1\" counts"
        );

        // -- events API: clamped window + classified Loki lines ---------------
        let events = get_with(
            cluster_router(state.clone()),
            "/api/admin/cluster/events?since_minutes=999999",
            Some("verified.jwt"),
            false,
        )
        .await;
        assert_eq!(events.status(), StatusCode::OK);
        let events = body_json(events).await;
        assert_eq!(events["configured"], true);
        assert_eq!(events["since_minutes"], 1440, "clamped to the max window");
        assert_eq!(events["events"][0]["kind"], "leader_transfer");
        assert_eq!(events["events"][0]["shard"], 0);

        // -- metrics API: per-op fan-out with the down node carried as error ---
        let metrics = get_with(
            cluster_router(state.clone()),
            "/api/admin/cluster/metrics",
            Some("verified.jwt"),
            false,
        )
        .await;
        assert_eq!(metrics.status(), StatusCode::OK);
        let metrics = body_json(metrics).await;
        let nodes = metrics["nodes"].as_array().unwrap();
        assert_eq!(nodes.len(), 2);
        assert_eq!(nodes[0]["operations"][0]["op"], "kv.put");
        assert!(nodes[1]["error"].as_str().is_some());
        assert_eq!(
            metrics["prometheus_up_range"][0]["metric"]["pod"],
            "fiducia-node-0"
        );

        // -- full HTML page + htmx fragment ------------------------------------
        let page = get_with(
            cluster_router(state.clone()),
            "/cluster",
            Some("verified.jwt"),
            false,
        )
        .await;
        assert_eq!(page.status(), StatusCode::OK);
        let html = body_text(page).await;
        assert!(html.contains("Cluster insight"));
        assert!(html.contains("node-ok"));
        assert!(html.contains("unreachable"), "down node badge renders");
        assert!(html.contains("leader_transfer"), "Loki event renders");
        assert!(
            html.contains("/telemetry/explore?left="),
            "Grafana deep link"
        );

        let fragment = get_with(
            cluster_router(state),
            "/cluster/shards",
            Some("verified.jwt"),
            true,
        )
        .await;
        assert_eq!(fragment.status(), StatusCode::OK);
        let fragment = body_text(fragment).await;
        assert!(fragment.contains("shard-table"));
        assert!(!fragment.contains("<!DOCTYPE"), "fragment, not a full page");

        for task in [
            auth_task,
            brain_task,
            node_ok_task,
            node_down_task,
            loki_task,
            prometheus_task,
        ] {
            task.abort();
        }
    }

    /// Loki unset is a rendered state, not an error: the API says so and the
    /// panel explains which variable enables it.
    #[tokio::test]
    async fn unconfigured_observability_renders_as_not_configured() {
        std::env::set_var("FIDUCIA_INTERNAL_SECRET", TEST_INTERNAL_SECRET);
        let auth = Router::new().route(
            "/v1/me",
            get(|| async {
                Json(json!({
                    "user": { "user_id": "dev-admin", "email": "op@example.com", "roles": ["admin"] }
                }))
            }),
        );
        let (auth_url, auth_task) = spawn_mock(auth).await;
        let state = insight_state(
            auth_url,
            "http://localhost:8095".into(),
            None,
            None,
            None,
            Vec::new(),
        );

        let events = get_with(
            cluster_router(state.clone()),
            "/api/admin/cluster/events",
            Some("verified.jwt"),
            false,
        )
        .await;
        assert_eq!(events.status(), StatusCode::OK);
        let events = body_json(events).await;
        assert_eq!(events["configured"], false);
        assert_eq!(events["since_minutes"], 30);
        assert_eq!(events["events"], json!([]));

        let fragment = get_with(
            cluster_router(state),
            "/cluster/events",
            Some("verified.jwt"),
            true,
        )
        .await;
        assert_eq!(fragment.status(), StatusCode::OK);
        let html = body_text(fragment).await;
        assert!(html.contains("FIDUCIA_LOKI_URL"));

        auth_task.abort();
    }

    /// H1: the fan-out must (a) refuse a brain-supplied address that is not
    /// in-cluster — never dialing it with the cluster secret — and (b) never
    /// follow a redirect, so a trusted node that answers a cross-origin 302 can't
    /// bounce the secret to an attacker's `Location`.
    #[tokio::test]
    async fn node_fanout_refuses_untrusted_addresses_and_never_follows_redirects() {
        use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

        std::env::set_var("FIDUCIA_INTERNAL_SECRET", TEST_INTERNAL_SECRET);
        let auth = Router::new().route(
            "/v1/me",
            get(|| async {
                Json(json!({
                    "user": { "user_id": "dev-admin", "email": "op@example.com", "roles": ["admin"] }
                }))
            }),
        );
        let (auth_url, auth_task) = spawn_mock(auth).await;

        // A capture server standing in for the attacker's redirect target. It
        // records any hit and whether the cluster secret rode along.
        let hits = Arc::new(AtomicUsize::new(0));
        let leaked = Arc::new(AtomicBool::new(false));
        let hits_handler = hits.clone();
        let leaked_handler = leaked.clone();
        let capture = Router::new().route(
            "/leak",
            get(move |headers: HeaderMap| {
                let hits_handler = hits_handler.clone();
                let leaked_handler = leaked_handler.clone();
                async move {
                    hits_handler.fetch_add(1, Ordering::SeqCst);
                    if headers
                        .get("x-fiducia-internal-auth")
                        .and_then(|value| value.to_str().ok())
                        == Some(TEST_INTERNAL_SECRET)
                    {
                        leaked_handler.store(true, Ordering::SeqCst);
                    }
                    StatusCode::OK
                }
            }),
        );
        let (capture_url, capture_task) = spawn_mock(capture).await;

        // A trusted (loopback) node that answers observe with a cross-origin 302
        // pointing at the capture server.
        let leak_location = format!("{capture_url}/leak");
        let redirect_node = Router::new().route(
            "/v1/observe/shards",
            get(move || {
                let leak_location = leak_location.clone();
                async move { (StatusCode::FOUND, [(LOCATION, leak_location)]).into_response() }
            }),
        );
        let (redirect_url, redirect_task) = spawn_mock(redirect_node).await;
        let redirect_address = redirect_url.trim_start_matches("http://").to_string();

        let brain = Router::new()
            .route(
                "/v1/status",
                get(|| async {
                    Json(json!({
                        "service": "fiducia-brain", "version": "0.1.0",
                        "cluster_id": "fiducia-test", "shard_count": 0, "replication_factor": 3
                    }))
                }),
            )
            .route(
                "/v1/nodes",
                get(move || {
                    let redirect_address = redirect_address.clone();
                    async move {
                        Json(json!({
                            "nodes": [
                                // Not loopback, not in-cluster: must be refused pre-request.
                                { "node_id": "evil", "address": "attacker.example.com:8090", "health": "healthy" },
                                // Loopback (trusted) but answers with a redirect.
                                { "node_id": "redir", "address": redirect_address, "health": "healthy" }
                            ]
                        }))
                    }
                }),
            );
        let (brain_url, brain_task) = spawn_mock(brain).await;

        let state = insight_state(auth_url, brain_url, None, None, None, Vec::new());
        let response = get_with(
            cluster_router(state),
            "/api/admin/cluster/shards",
            Some("verified.jwt"),
            false,
        )
        .await;
        assert_eq!(response.status(), StatusCode::OK, "never a page failure");
        let body = body_json(response).await;
        let observations = body["node_observations"].as_array().unwrap();
        assert_eq!(observations.len(), 2);

        let evil = observations
            .iter()
            .find(|o| o["node_id"] == "evil")
            .unwrap();
        assert_eq!(
            evil["error"], "untrusted address",
            "the out-of-cluster address is a distinct refused state"
        );
        assert_eq!(evil["untrusted"], true);

        let redir = observations
            .iter()
            .find(|o| o["node_id"] == "redir")
            .unwrap();
        assert!(
            redir["error"].as_str().unwrap().contains("302"),
            "the 302 surfaces as an error, not followed: got {:?}",
            redir["error"]
        );

        assert_eq!(
            hits.load(Ordering::SeqCst),
            0,
            "the redirect was never followed"
        );
        assert!(
            !leaked.load(Ordering::SeqCst),
            "the cluster secret never reached the redirect target"
        );

        for task in [auth_task, brain_task, redirect_task, capture_task] {
            task.abort();
        }
    }

    /// M2: an upstream body past the cap is an error observation, not an OOM or a
    /// panic — the fan-out reads with a running byte counter and aborts.
    #[tokio::test]
    async fn oversized_upstream_body_is_an_error_not_an_oom() {
        std::env::set_var("FIDUCIA_INTERNAL_SECRET", TEST_INTERNAL_SECRET);
        // Larger than upstream::MAX_UPSTREAM_BODY_BYTES (16 MiB).
        let oversized = "x".repeat(17 * 1024 * 1024);
        let node = Router::new().route(
            "/v1/observe/shards",
            get(move || {
                let oversized = oversized.clone();
                async move { oversized }
            }),
        );
        let (node_url, node_task) = spawn_mock(node).await;

        let targets = vec![cluster_insight::NodeTarget {
            node_id: "big".into(),
            base_url: node_url,
            trusted: true,
        }];
        let observations = cluster_insight::observe_shards_fanout(&targets).await;
        assert_eq!(observations.len(), 1);
        assert!(observations[0].shards.is_none());
        assert_eq!(
            observations[0].error.as_deref(),
            Some("oversized response"),
            "the body cap is enforced as bytes arrive"
        );

        node_task.abort();
    }
}

#[cfg(test)]
mod csrf_tests {
    use super::*;
    use axum::body::Body;
    use axum::http::Request;
    use tower::ServiceExt;

    fn browser_headers(origin: &str) -> HeaderMap {
        let mut headers = HeaderMap::new();
        headers.insert("host", HeaderValue::from_static("admin.fiducia.cloud"));
        headers.insert("origin", HeaderValue::from_str(origin).unwrap());
        headers.insert("sec-fetch-site", HeaderValue::from_static("same-origin"));
        headers
    }

    #[test]
    fn form_security_requires_exact_origin_and_credential_bound_token() {
        let state = sync_tests::test_state();
        let session = Session::test_admin("dev-admin");
        let csrf = csrf_token(&state, &session);

        assert!(require_form_security(
            &browser_headers("https://admin.fiducia.cloud"),
            &state,
            &session,
            &csrf,
        )
        .is_ok());
        assert!(require_form_security(
            &browser_headers("https://app.fiducia.cloud"),
            &state,
            &session,
            &csrf,
        )
        .is_err());
        assert!(require_form_security(
            &browser_headers("https://admin.fiducia.cloud"),
            &state,
            &session,
            "tampered",
        )
        .is_err());
    }

    #[test]
    fn login_security_requires_exact_origin_host_cookie_and_bound_token() {
        let state = sync_tests::test_state();
        let nonce = "unit-test-login-nonce";
        let csrf = state
            .request_security
            .csrf_token(&format!("login\0{nonce}"));
        let mut exact = browser_headers("https://admin.fiducia.cloud");
        exact.insert(
            "cookie",
            format!("{LOGIN_CSRF_COOKIE}={nonce}").parse().unwrap(),
        );
        assert!(require_login_security(&exact, &state, &csrf).is_ok());

        let mut sibling = exact.clone();
        sibling.insert(
            "origin",
            HeaderValue::from_static("https://app.fiducia.cloud"),
        );
        assert!(require_login_security(&sibling, &state, &csrf).is_err());

        let mut missing_cookie = exact;
        missing_cookie.remove("cookie");
        assert!(require_login_security(&missing_cookie, &state, &csrf).is_err());
    }

    #[test]
    fn sync_security_distinguishes_cookie_and_bearer_provenance() {
        let state = sync_tests::test_state();
        let cookie_session = Session::test_admin_cookie("operator-a", "cookie.jwt");
        let csrf = csrf_token(&state, &cookie_session);
        let mut cookie_headers = browser_headers("https://admin.fiducia.cloud");
        cookie_headers.insert(CSRF_HEADER, HeaderValue::from_str(&csrf).unwrap());
        assert!(require_sync_write_security(&cookie_headers, &state, &cookie_session).is_ok());

        cookie_headers.remove(CSRF_HEADER);
        assert!(require_sync_write_security(&cookie_headers, &state, &cookie_session).is_err());

        let bearer_session = Session::test_admin_bearer("operator-a", "bearer.jwt");
        let mut bearer_headers = HeaderMap::new();
        bearer_headers.insert("host", HeaderValue::from_static("admin.fiducia.cloud"));
        assert!(require_sync_write_security(&bearer_headers, &state, &bearer_session).is_ok());

        bearer_headers.insert(
            "origin",
            HeaderValue::from_static("https://app.fiducia.cloud"),
        );
        assert!(require_sync_write_security(&bearer_headers, &state, &bearer_session).is_err());
    }

    #[tokio::test]
    async fn response_headers_deny_framing() {
        let app = Router::new()
            .route("/healthz", get(health))
            .layer(middleware::from_fn(security_headers));
        let response = app
            .oneshot(
                Request::builder()
                    .uri("/healthz")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(
            response
                .headers()
                .get("x-frame-options")
                .and_then(|value| value.to_str().ok()),
            Some("DENY")
        );
        assert!(response
            .headers()
            .get("content-security-policy")
            .and_then(|value| value.to_str().ok())
            .is_some_and(|value| value.contains("frame-ancestors 'none'")));
        // Health is deliberately cache-neutral; authenticated/dynamic routes
        // are covered separately by the middleware's path classification.
        assert!(response.headers().get("cache-control").is_none());
    }

    #[tokio::test]
    async fn dynamic_responses_are_never_cached() {
        let app = Router::new()
            .route("/login", get(|| async { StatusCode::OK }))
            .layer(middleware::from_fn(security_headers));
        let response = app
            .oneshot(
                Request::builder()
                    .uri("/login")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(
            response
                .headers()
                .get("cache-control")
                .and_then(|value| value.to_str().ok()),
            Some("no-store")
        );
    }
}

#[cfg(test)]
mod interface_contract_tests {
    use fiducia_interfaces::{LockAcquireManyRequest, ProposeErrorReason};

    #[test]
    fn generated_interfaces_are_importable() {
        let request = LockAcquireManyRequest {
            keys: vec!["orders/42".to_string(), "inventory/sku-7".to_string()],
            holder: Some("worker-a".to_string()),
            ttl_ms: Some(30_000),
            wait: Some(false),
        };

        assert_eq!(request.keys.len(), 2);
        assert!(matches!(
            ProposeErrorReason::NotLeader,
            ProposeErrorReason::NotLeader
        ));
    }
}

// DB-behavior tests for the sync durability layer (durable idempotency + global
// cursor/tombstones), gated on `TEST_DATABASE_URL` — unset → skip, so `cargo test` stays
// green with no DB. Run against a real Postgres with admin.sql applied.
#[cfg(test)]
mod db_tests {
    use super::*;
    use sea_orm::ConnectionTrait;

    const SCHEMA: &str = include_str!("../../fiducia-interfaces/sql/admin.sql");

    fn state_with(db: DatabaseConnection) -> AppState {
        AppState {
            auth_url: "x".into(),
            brain_url: "x".into(),
            supabase_url: "https://example.supabase.co".into(),
            supabase_publishable_key: "test-publishable-key".into(),
            db: Some(db),
            stream_tx: broadcast::channel(4).0,
            request_security: test_request_security(),
            prometheus_url: None,
            loki_url: None,
            grafana_public_url: None,
            node_urls: Vec::new(),
        }
    }

    // One test, one connection, one runtime: SeaORM's async connection pool is
    // runtime-bound, so the whole durability check deliberately shares one test.
    #[tokio::test]
    async fn sync_durability_against_real_postgres() {
        let Some(url) = std::env::var("TEST_DATABASE_URL")
            .ok()
            .filter(|v| !v.is_empty())
        else {
            eprintln!("skip sync_durability_against_real_postgres: TEST_DATABASE_URL unset");
            return;
        };
        let mut options = ConnectOptions::new(url);
        options.max_connections(4);
        let db = Database::connect(options)
            .await
            .expect("connect TEST_DATABASE_URL");
        // Raw SQL here applies the canonical gated-test schema; behavioral CRUD
        // below uses SeaORM, while production catch-up owns one reviewed UNION so
        // live rows and tombstones are read in a single database snapshot.
        db.execute_unprepared(SCHEMA)
            .await
            .expect("apply admin.sql");
        let st = state_with(db.clone());

        // --- Durable idempotency: rollback -> commit -> exact replay ------------
        let row_id = Uuid::new_v4();
        let key = format!("admin-sync-{}", Uuid::new_v4().simple());
        let request = SyncWriteRequest {
            id: row_id.to_string(),
            op: Some("upsert".into()),
            payload: Some(json!({ "status": "applied" })),
            base_version: Some(1),
            key: Some(key.clone()),
        };
        let operator =
            Session::test_admin_bearer("00000000-0000-0000-0000-000000000001", "verified.jwt");
        let fingerprint = sync_write_fingerprint(&operator, "infra_operations", &request);

        assert!(matches!(
            sync_write_infra_operations(&st, &request, &key, &fingerprint).await,
            Err(SyncWriteError::NotFound)
        ));
        assert!(
            sync_idempotency_keys::Entity::find_by_id(&key)
                .one(&db)
                .await
                .unwrap()
                .is_none(),
            "a failed row mutation rolls its key claim back"
        );

        infra_operations::ActiveModel {
            id: Set(row_id),
            action: Set("scale".to_string()),
            ..Default::default()
        }
        .insert(&db)
        .await
        .unwrap();
        let committed_version = match sync_write_infra_operations(&st, &request, &key, &fingerprint)
            .await
            .unwrap()
        {
            SyncWriteOutcome::Committed(row) => row.version,
            SyncWriteOutcome::Replay(_) => panic!("first successful write must commit"),
        };
        let ledger = sync_idempotency_keys::Entity::find_by_id(&key)
            .one(&db)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(ledger.request_fingerprint.as_deref(), Some(&*fingerprint));
        assert_eq!(ledger.committed_version, Some(committed_version));

        // Survives a restart and replays only the exact original request.
        let fresh = state_with(db.clone());
        assert!(matches!(
            sync_write_infra_operations(&fresh, &request, &key, &fingerprint).await,
            Ok(SyncWriteOutcome::Replay(version)) if version == committed_version
        ));
        let changed = SyncWriteRequest {
            id: request.id.clone(),
            op: request.op.clone(),
            payload: Some(json!({ "status": "failed" })),
            base_version: request.base_version,
            key: request.key.clone(),
        };
        let changed_fingerprint = sync_write_fingerprint(&operator, "infra_operations", &changed);
        assert!(matches!(
            sync_write_infra_operations(&fresh, &changed, &key, &changed_fingerprint).await,
            Err(SyncWriteError::IdempotencyMismatch)
        ));

        // A distinct stale write must lose the version CAS and roll its newly
        // claimed idempotency key back, while the exact old request above replays.
        let stale_key = format!("admin-sync-stale-{}", Uuid::new_v4().simple());
        let stale = SyncWriteRequest {
            key: Some(stale_key.clone()),
            ..SyncWriteRequest {
                id: request.id.clone(),
                op: request.op.clone(),
                payload: Some(json!({ "status": "failed" })),
                base_version: Some(1),
                key: None,
            }
        };
        let stale_fingerprint = sync_write_fingerprint(&operator, "infra_operations", &stale);
        assert!(matches!(
            sync_write_infra_operations(&fresh, &stale, &stale_key, &stale_fingerprint).await,
            Err(SyncWriteError::VersionConflict { expected: 1, actual })
                if actual == committed_version
        ));
        assert!(
            sync_idempotency_keys::Entity::find_by_id(&stale_key)
                .one(&db)
                .await
                .unwrap()
                .is_none(),
            "a failed CAS rolls its key claim back"
        );

        // --- Global cursor: stable pages include v1 inserts and delete tombstones.
        let clock = db
            .query_one(Statement::from_string(
                DbBackend::Postgres,
                "select last_sequence from public.sync_clock".to_string(),
            ))
            .await
            .unwrap()
            .unwrap();
        let start_cursor: i64 = clock.try_get("", "last_sequence").unwrap();
        let a = infra_operations::ActiveModel {
            action: Set("scale".to_string()),
            ..Default::default()
        }
        .insert(&db)
        .await
        .unwrap();
        let b = infra_operations::ActiveModel {
            action: Set("drain".to_string()),
            ..Default::default()
        }
        .insert(&db)
        .await
        .unwrap();
        let a_id = a.id;
        let b_id = b.id;
        let mut active: infra_operations::ActiveModel = a.into();
        active.status = Set("applied".to_string());
        active.update(&db).await.unwrap(); // bump `a` to version 2
        infra_operations::Entity::delete_by_id(b_id)
            .exec(&db)
            .await
            .unwrap();
        let c = infra_operations::ActiveModel {
            action: Set("snapshot".to_string()),
            ..Default::default()
        }
        .insert(&db)
        .await
        .unwrap();

        let mut cursor = start_cursor;
        let mut changes = Vec::new();
        loop {
            let page = catchup_infra_operations(&db, cursor, 1).await.unwrap();
            assert!(page.changes.iter().all(|change| change.sequence > cursor));
            changes.extend(page.changes);
            if !page.has_more {
                cursor = page.next_cursor;
                break;
            }
            assert!(page.next_cursor > cursor);
            cursor = page.next_cursor;
        }
        assert!(
            changes
                .windows(2)
                .all(|pair| pair[0].sequence < pair[1].sequence),
            "global sequences are unique and strictly ordered"
        );
        assert!(changes.iter().any(|change| {
            change.id == a_id.to_string() && change.op == "upsert" && change.version == 2
        }));
        assert!(changes.iter().any(|change| {
            change.id == b_id.to_string()
                && change.op == "delete"
                && change.version == 2
                && change.row.is_none()
        }));
        assert!(
            changes.iter().any(|change| {
                change.id == c.id.to_string() && change.op == "upsert" && change.version == 1
            }),
            "a later v1 insert is visible after higher per-row versions"
        );
        assert_eq!(
            cursor,
            changes
                .last()
                .map_or(start_cursor, |change| change.sequence)
        );
    }
}
