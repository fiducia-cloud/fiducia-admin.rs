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

use entity::{infra_operations, operators, sync_idempotency_keys};
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
    headers.insert(
        HeaderName::from_static("referrer-policy"),
        HeaderValue::from_static("no-referrer"),
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

/// Insert a `scale` row into infra_operations (status `requested`, operator
/// resolved from the verified Supabase subject) and broadcast
/// it as a `fiducia:sync` change.
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
    let row = infra_operations::ActiveModel {
        operator_id: Set(operator_id),
        action: Set("scale".to_string()),
        target_nodes: Set(Some(target_nodes as i32)),
        status: Set("requested".to_string()),
        params: Set(json!({ "target_nodes": target_nodes, "replication_factor": 3 })),
        ..Default::default()
    }
    .insert(db)
    .await?;
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

    async fn spawn_mock(app: Router) -> (String, tokio::task::JoinHandle<()>) {
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
    fn only_mutating_registry_roles_are_enabled() {
        for role in ["owner", "admin", "operator"] {
            assert!(operator_registry_role_allows_access(role), "role={role}");
        }
        for role in ["viewer", "authenticated", "customer", ""] {
            assert!(!operator_registry_role_allows_access(role), "role={role}");
        }
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
