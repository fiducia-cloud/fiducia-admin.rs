//! fiducia-admin — the server-rendered admin dashboard (MASH: Maud + Axum + SQLx
//! + HTMX).
//!
//! One web app, two role-gated areas:
//!   * **everyone signed in** — account/org + API keys (data from `fiducia-auth`);
//!   * **admins** — cluster & infra ops: scale, nodes, shard placement (via
//!     `fiducia-brain`).
//!
//! Auth is a Supabase session (verified through `fiducia-auth`). This is the
//! authenticated app — distinct from `fiducia-backend`, which serves the public
//! marketing site.
//!
//! ADMIN plane isolation: when `DATABASE_URL` is set it points at the admin app's
//! OWN Postgres (operators, infra_operations, admin_audit_log) — a separate
//! instance from the customer DB. That is a security boundary; this service never
//! connects to the customer database. With no `DATABASE_URL` the app still renders
//! fully (the infra audit list is simply empty), so it boots for local dev / E2E
//! with just the `FIDUCIA_ADMIN_DEV_SESSION` bypass and no DB.

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
        Form, Path, Query, State,
    },
    http::{
        header::{CONTENT_TYPE, LOCATION, SET_COOKIE},
        HeaderMap, StatusCode,
    },
    response::{IntoResponse, Response},
    routing::{get, post},
    Json, Router,
};
use fiducia_interfaces_db::admin::InfraOperationsRow;
use fiducia_sync_core::{ChangeEvent, ChangeOp, WriteAck};
use maud::Markup;
use serde::Deserialize;
use serde_json::{json, Value};
use sqlx::postgres::PgPoolOptions;
use sqlx::PgPool;
use tokio::sync::broadcast;
use tower_http::{
    catch_panic::CatchPanicLayer, limit::RequestBodyLimitLayer, timeout::TimeoutLayer,
    trace::TraceLayer,
};
use uuid::Uuid;

use session::Session;

const SERVICE: &str = "fiducia-admin";

/// Bound request handling time (slow-loris / hung-upstream protection).
const REQUEST_TIMEOUT_SECS: u64 = 30;
/// Cap request bodies (HTML form posts are tiny).
const MAX_BODY_BYTES: usize = 64 * 1024;

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
    /// Admin Postgres pool. `None` is only used by isolated failure-path tests.
    pool: Option<PgPool>,
    /// Fans `fiducia:sync` frames out to `/admin/ws` subscribers.
    stream_tx: broadcast::Sender<String>,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    fiducia_telemetry::init(SERVICE);

    let pool = connect_admin_db().await?;
    required_env("FIDUCIA_INTERNAL_SECRET")?;
    let (stream_tx, _) = broadcast::channel::<String>(256);

    let state = Arc::new(AppState {
        auth_url: required_env("FIDUCIA_AUTH_URL")?,
        brain_url: required_env("FIDUCIA_BRAIN_URL")?,
        pool: Some(pool),
        stream_tx,
    });

    let app = Router::new()
        .route("/healthz", get(health))
        .route("/assets/htmx.min.js", get(htmx_js))
        .route("/assets/fiducia-sync.js", get(sync_js))
        .route("/login", get(login).post(login_submit))
        .route("/", get(dashboard))
        .route("/account", get(account))
        .route("/keys", get(keys_page).post(create_key))
        .route("/keys/:key_id/revoke", post(revoke_key))
        .route("/infra", get(infra_page))
        .route("/infra/scale", post(scale))
        // Local-first sync write path (mirrors the customer plane): the sync
        // client POSTs a queued optimistic write; we persist via SQLx and return
        // the committed row version, then broadcast the change to WS subscribers.
        .route("/api/admin/sync/:table", post(sync_write).get(sync_catchup))
        .route("/admin/ws", get(admin_ws))
        .with_state(state)
        // Hardening stack (outermost last): catch handler panics → 500, bound
        // request time, and cap body size.
        .layer(TraceLayer::new_for_http())
        .layer(TimeoutLayer::new(Duration::from_secs(REQUEST_TIMEOUT_SECS)))
        .layer(RequestBodyLimitLayer::new(MAX_BODY_BYTES))
        .layer(CatchPanicLayer::new());

    let port: u16 = std::env::var("PORT")
        .ok()
        .and_then(|p| p.parse().ok())
        .unwrap_or(8096);
    let addr = SocketAddr::from(([0, 0, 0, 0], port));
    tracing::info!("{SERVICE} listening on http://{addr}");
    let listener = tokio::net::TcpListener::bind(addr).await?;
    axum::serve(listener, app).await?;
    Ok(())
}

/// Connect to the isolated admin Postgres plane; missing/unreachable storage is
/// fatal because an operator action without its audit trail is not acceptable.
async fn connect_admin_db() -> Result<PgPool, Box<dyn std::error::Error>> {
    let url = required_env("DATABASE_URL")?;
    let pool = PgPoolOptions::new()
        .max_connections(5)
        .connect(&url)
        .await?;
    pool.acquire().await?;
    tracing::info!("admin DB connected — infra_operations audit is live");
    Ok(pool)
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

/// Require any signed-in user, else redirect to /login.
async fn require(headers: &HeaderMap, st: &AppState) -> Result<Session, Response> {
    session::current(headers, &st.auth_url)
        .await
        .ok_or_else(|| redirect("/login"))
}

/// Require the admin role, else 403.
async fn require_admin(headers: &HeaderMap, st: &AppState) -> Result<Session, Response> {
    let s = require(headers, st).await?;
    if s.is_admin {
        Ok(s)
    } else {
        Err((StatusCode::FORBIDDEN, views::forbidden(&s)).into_response())
    }
}

async fn login() -> Markup {
    views::login()
}

#[derive(Debug, Deserialize)]
struct LoginForm {
    token: String,
}

async fn login_submit(Form(form): Form<LoginForm>) -> Response {
    let token = form.token.trim();
    if token.is_empty() {
        return redirect("/login");
    }
    // Security: the session cookie is HttpOnly + SameSite=Strict + Secure. `Secure`
    // means the cookie is only sent over HTTPS; gate it off with
    // FIDUCIA_INSECURE_COOKIES=1 for a plain-http local escape hatch. (Local dev
    // click-through uses the FIDUCIA_ADMIN_DEV_SESSION env bypass, not this cookie,
    // so the default-Secure cookie doesn't hinder local use.)
    let secure = if std::env::var("FIDUCIA_INSECURE_COOKIES").as_deref() == Ok("1") {
        ""
    } else {
        "; Secure"
    };
    let cookie = format!("fiducia_session={token}; Path=/; HttpOnly; SameSite=Strict{secure}");
    (
        StatusCode::SEE_OTHER,
        [(LOCATION, "/".to_string()), (SET_COOKIE, cookie)],
    )
        .into_response()
}

async fn dashboard(State(st): State<Arc<AppState>>, headers: HeaderMap) -> Response {
    match require(&headers, &st).await {
        Ok(s) => views::dashboard(&s).into_response(),
        Err(r) => r,
    }
}

async fn account(State(st): State<Arc<AppState>>, headers: HeaderMap) -> Response {
    match require(&headers, &st).await {
        Ok(s) => views::account(&s).into_response(),
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
    views::infra(&s, &nodes, &placement, &recent).into_response()
}

#[derive(Debug, Deserialize)]
struct ScaleForm {
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
async fn recent_ops(st: &AppState) -> Result<Vec<Value>, sqlx::Error> {
    let pool = st.pool.as_ref().ok_or(sqlx::Error::PoolClosed)?;
    let rows = sqlx::query_as::<_, InfraOperationsRow>(
        "select * from infra_operations order by created_at desc limit 10",
    )
    .fetch_all(pool)
    .await?;
    Ok(rows
        .iter()
        .filter_map(|row| serde_json::to_value(row).ok())
        .collect())
}

/// Insert a `scale` row into infra_operations (status `requested`, operator
/// resolved from the session email if a matching operator exists) and broadcast
/// it as a `fiducia:sync` change.
async fn record_scale(
    st: &AppState,
    s: &Session,
    target_nodes: u32,
) -> Result<InfraOperationsRow, sqlx::Error> {
    let pool = st.pool.as_ref().ok_or(sqlx::Error::PoolClosed)?;
    let operator_id: Option<Uuid> = match &s.email {
        Some(email) => {
            sqlx::query_scalar::<_, Uuid>("select id from operators where lower(email) = lower($1)")
                .bind(email)
                .fetch_optional(pool)
                .await?
        }
        None => None,
    };
    let row = sqlx::query_as::<_, InfraOperationsRow>(
        "insert into infra_operations (operator_id, action, target_nodes, status, params) \
         values ($1, 'scale', $2, 'requested', $3) returning *",
    )
    .bind(operator_id)
    .bind(target_nodes as i32)
    .bind(json!({ "target_nodes": target_nodes, "replication_factor": 3 }))
    .fetch_one(pool)
    .await?;
    broadcast_infra_change(st, &row);
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
    if let Err(response) = require_admin_api(&headers, &st).await {
        return response;
    }
    let idem_key = headers
        .get("idempotency-key")
        .and_then(|v| v.to_str().ok())
        .map(str::to_owned);
    if let Some(key) = &idem_key {
        match idempotency_begin(&st, key).await {
            Ok(Idem::Replay(v)) => return ack(&req.id, v),
            Ok(Idem::InFlight) => {
                return (
                    StatusCode::CONFLICT,
                    Json(json!({ "error": "idempotency_in_flight" })),
                )
                    .into_response()
            }
            Ok(Idem::Proceed) => {}
            Err(err) => return dependency_error("idempotency_claim_failed", err),
        }
    }

    let committed = match table.as_str() {
        "infra_operations" => sync_write_infra_operations_row(&st, &req).await,
        _ => {
            return (
                StatusCode::NOT_FOUND,
                Json(json!({ "error": "unsupported_sync_table", "table": table })),
            )
                .into_response()
        }
    };
    let version = match committed {
        Ok(version) => version,
        Err(SyncWriteError::InvalidId) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(json!({ "error": "invalid_row_id" })),
            )
                .into_response()
        }
        Err(SyncWriteError::NotFound) => {
            return (
                StatusCode::NOT_FOUND,
                Json(json!({ "error": "row_not_found" })),
            )
                .into_response()
        }
        Err(SyncWriteError::Database(err)) => return dependency_error("sync_write_failed", err),
    };

    if let Some(key) = &idem_key {
        if let Err(err) = idempotency_commit(&st, key, version).await {
            return dependency_error("idempotency_commit_failed", err);
        }
    }
    ack(&req.id, version)
}

/// Idempotency decision for a claimed/seen key.
enum Idem {
    Replay(i64),
    InFlight,
    Proceed,
}

/// Begin idempotent handling in the durable admin ledger.
async fn idempotency_begin(st: &AppState, key: &str) -> Result<Idem, sqlx::Error> {
    let pool = st.pool.as_ref().ok_or(sqlx::Error::PoolClosed)?;
    let claimed = sqlx::query_scalar::<_, i32>(
        "insert into sync_idempotency_keys (key) values ($1) \
         on conflict (key) do nothing returning 1",
    )
    .bind(key)
    .fetch_optional(pool)
    .await?;
    if claimed.is_some() {
        return Ok(Idem::Proceed);
    }
    Ok(
        match sqlx::query_scalar::<_, Option<i64>>(
            "select committed_version from sync_idempotency_keys where key = $1",
        )
        .bind(key)
        .fetch_optional(pool)
        .await?
        {
            Some(Some(version)) => Idem::Replay(version),
            _ => Idem::InFlight,
        },
    )
}

/// Record the committed version for `key` in the durable admin ledger.
async fn idempotency_commit(st: &AppState, key: &str, version: i64) -> Result<(), sqlx::Error> {
    let pool = st.pool.as_ref().ok_or(sqlx::Error::PoolClosed)?;
    sqlx::query("update sync_idempotency_keys set committed_version = $2 where key = $1")
        .bind(key)
        .bind(version)
        .execute(pool)
        .await?;
    Ok(())
}

#[derive(Debug, Deserialize)]
struct CatchupParams {
    #[serde(default)]
    since: i64,
}

/// Catch-up hydration: `GET /api/admin/sync/{table}?since=<version>` returns the
/// control-plane rows newer than the client's cursor, ordered by version
/// (index-backed by `infra_operations_version_idx`). Feeds the SDK's `hydrate()`.
async fn sync_catchup(
    State(st): State<Arc<AppState>>,
    Path(table): Path<String>,
    Query(params): Query<CatchupParams>,
    headers: HeaderMap,
) -> Response {
    if let Err(response) = require_admin_api(&headers, &st).await {
        return response;
    }
    let rows: Vec<serde_json::Value> = match table.as_str() {
        "infra_operations" => {
            let Some(pool) = &st.pool else {
                return dependency_error("database_unavailable", sqlx::Error::PoolClosed);
            };
            match sqlx::query_as::<_, InfraOperationsRow>(
                "select * from infra_operations where version > $1 order by version asc limit 500",
            )
            .bind(params.since)
            .fetch_all(pool)
            .await
            {
                Ok(rows) => rows
                    .iter()
                    .map(|r| serde_json::to_value(r).unwrap_or_default())
                    .collect(),
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
    Json(json!({ "table": table, "since": params.since, "rows": rows })).into_response()
}

/// Build the shared write-ack the @fiducia/sync client reconciles against.
fn ack(id: &str, committed_version: i64) -> Response {
    Json(WriteAck {
        id: id.to_string(),
        committed_version,
    })
    .into_response()
}

enum SyncWriteError {
    InvalidId,
    NotFound,
    Database(sqlx::Error),
}

/// Persist one queued optimistic write to `infra_operations`, broadcasting the
/// committed change. The BEFORE UPDATE trigger bumps `version`.
async fn sync_write_infra_operations_row(
    st: &AppState,
    req: &SyncWriteRequest,
) -> Result<i64, SyncWriteError> {
    let pool = st
        .pool
        .as_ref()
        .ok_or(SyncWriteError::Database(sqlx::Error::PoolClosed))?;
    let id = Uuid::parse_str(&req.id).map_err(|_| SyncWriteError::InvalidId)?;
    let op = req.op.as_deref().unwrap_or("upsert");

    let committed = if op == "delete" {
        // A control-plane op is an audit record, not a droppable row: a "delete"
        // marks it failed. Version still bumps via the trigger.
        sqlx::query_as::<_, InfraOperationsRow>(
            "update infra_operations set status = 'failed' where id = $1 returning *",
        )
        .bind(id)
        .fetch_optional(pool)
        .await
    } else {
        let payload = req.payload.clone().unwrap_or_else(|| json!({}));
        let status = payload.get("status").and_then(Value::as_str);
        let target_nodes = payload
            .get("target_nodes")
            .and_then(Value::as_i64)
            .map(|v| v as i32);
        let error = payload.get("error").and_then(Value::as_str);
        // COALESCE keeps existing values for any field the client omitted.
        sqlx::query_as::<_, InfraOperationsRow>(
            "update infra_operations set \
                status = coalesce($2, status), \
                target_nodes = coalesce($3, target_nodes), \
                error = coalesce($4, error) \
             where id = $1 returning *",
        )
        .bind(id)
        .bind(status)
        .bind(target_nodes)
        .bind(error)
        .fetch_optional(pool)
        .await
    };

    match committed {
        Ok(Some(row)) => {
            broadcast_infra_change(st, &row);
            Ok(row.version)
        }
        Ok(None) => Err(SyncWriteError::NotFound),
        Err(err) => Err(SyncWriteError::Database(err)),
    }
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
fn broadcast_infra_change(st: &AppState, row: &InfraOperationsRow) {
    let change = ChangeEvent {
        table: "infra_operations".to_string(),
        op: ChangeOp::Upsert,
        id: row.id.to_string(),
        version: row.version,
        row: serde_json::to_value(row).unwrap_or_default(),
        at_ms: unix_epoch_ms() as i64,
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
mod sync_tests {
    use super::*;
    use axum::body::Body;
    use axum::http::Request;
    use tower::ServiceExt;

    fn test_state() -> Arc<AppState> {
        Arc::new(AppState {
            auth_url: "http://localhost:8097".into(),
            brain_url: "http://localhost:8095".into(),
            pool: None,
            stream_tx: broadcast::channel(16).0,
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
    async fn sync_write_fails_closed_without_postgres() {
        let response = post_sync(test_state(), "infra_operations", None).await;
        assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);

        let unsupported = post_sync(test_state(), "operators", None).await;
        assert_eq!(unsupported.status(), StatusCode::NOT_FOUND);
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

    #[tokio::test]
    async fn idempotency_requires_the_durable_ledger() {
        let response = post_sync(
            test_state(),
            "infra_operations",
            Some("infra_operations:op1:upsert:7"),
        )
        .await;
        assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
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

// DB-behavior tests for the sync durability layer (durable idempotency + indexed
// catch-up), gated on `TEST_DATABASE_URL` — unset → skip, so `cargo test` stays
// green with no DB. Run against a real Postgres with admin.sql applied.
#[cfg(test)]
mod db_tests {
    use super::*;
    use sqlx::postgres::PgPoolOptions;

    const SCHEMA: &str = include_str!("../../fiducia-interfaces/sql/admin.sql");

    fn state_with(pool: PgPool) -> AppState {
        AppState {
            auth_url: "x".into(),
            brain_url: "x".into(),
            pool: Some(pool),
            stream_tx: broadcast::channel(4).0,
        }
    }

    // One test, one pool, one runtime: `#[tokio::test]` gives each test its own
    // runtime, and an sqlx pool is bound to the runtime that created it — so a
    // pool shared across tests dies with the first test's runtime. Keeping the
    // whole sync-durability check in a single test sidesteps that entirely.
    #[tokio::test]
    async fn sync_durability_against_real_postgres() {
        let Some(url) = std::env::var("TEST_DATABASE_URL")
            .ok()
            .filter(|v| !v.is_empty())
        else {
            eprintln!("skip sync_durability_against_real_postgres: TEST_DATABASE_URL unset");
            return;
        };
        let pool = PgPoolOptions::new()
            .max_connections(4)
            .connect(&url)
            .await
            .expect("connect TEST_DATABASE_URL");
        sqlx::raw_sql(SCHEMA)
            .execute(&pool)
            .await
            .expect("apply admin.sql");
        let st = state_with(pool.clone());

        // --- Durable idempotency: claim -> in-flight -> record -> replay ---------
        let key = format!("infra_operations:{}:upsert:7", Uuid::new_v4().simple());
        assert!(
            matches!(idempotency_begin(&st, &key).await, Ok(Idem::Proceed)),
            "first claim owns it"
        );
        assert!(
            matches!(idempotency_begin(&st, &key).await, Ok(Idem::InFlight)),
            "second sees in-flight"
        );
        idempotency_commit(&st, &key, 8).await.unwrap();
        assert!(
            matches!(idempotency_begin(&st, &key).await, Ok(Idem::Replay(8))),
            "replays committed"
        );
        // Survives a "restart": a fresh AppState (empty in-process cache) still replays.
        let fresh = state_with(pool.clone());
        assert!(
            matches!(idempotency_begin(&fresh, &key).await, Ok(Idem::Replay(8))),
            "durable across restart"
        );

        // --- Indexed catch-up: rows newer than the cursor, ordered by version ----
        let a: Uuid = sqlx::query_scalar(
            "insert into infra_operations (action) values ('scale') returning id",
        )
        .fetch_one(&pool)
        .await
        .unwrap();
        let _b: Uuid = sqlx::query_scalar(
            "insert into infra_operations (action) values ('drain') returning id",
        )
        .fetch_one(&pool)
        .await
        .unwrap();
        sqlx::query("update infra_operations set status = 'applied' where id = $1")
            .bind(a)
            .execute(&pool)
            .await
            .unwrap(); // bump `a` to version 2

        let newer: Vec<InfraOperationsRow> = sqlx::query_as(
            "select * from infra_operations where version > $1 order by version asc limit 500",
        )
        .bind(1_i64)
        .fetch_all(&pool)
        .await
        .unwrap();
        assert!(
            newer.iter().any(|r| r.id == a && r.version > 1),
            "bumped row present"
        );
        assert!(
            newer.iter().all(|r| r.version > 1),
            "cursor excludes v1 rows"
        );
        assert!(
            newer.windows(2).all(|w| w[0].version <= w[1].version),
            "ordered by version"
        );
    }
}
