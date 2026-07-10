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

use axum::{
    extract::{
        ws::{Message, WebSocket, WebSocketUpgrade},
        Form, Path, State,
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
use std::collections::HashMap;
use std::sync::Mutex;
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

struct AppState {
    auth_url: String,
    brain_url: String,
    /// Admin Postgres pool. `None` keeps the no-DB behavior (infra audit empty).
    pool: Option<PgPool>,
    /// Fans `fiducia:sync` frames out to `/admin/ws` subscribers.
    stream_tx: broadcast::Sender<String>,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    fiducia_telemetry::init(SERVICE);

    let pool = connect_admin_db().await;
    let (stream_tx, _) = broadcast::channel::<String>(256);

    let state = Arc::new(AppState {
        auth_url: std::env::var("FIDUCIA_AUTH_URL")
            .unwrap_or_else(|_| "http://localhost:8097".into()),
        brain_url: std::env::var("FIDUCIA_BRAIN_URL")
            .unwrap_or_else(|_| "http://localhost:8095".into()),
        pool,
        stream_tx,
    });

    let app = Router::new()
        .route("/healthz", get(health))
        .route("/assets/htmx.min.js", get(htmx_js))
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
        .route("/api/admin/sync/infra_operations", post(sync_write_infra_operations))
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

/// Open a pool to the ADMIN Postgres plane when `DATABASE_URL` is set. Returns
/// `None` (no-DB path) if the var is unset/empty, or if the connection fails —
/// the dashboard must boot without a DB, so a bad/missing DB is degraded, never
/// fatal. This is the admin DB only; never the customer database.
async fn connect_admin_db() -> Option<PgPool> {
    let url = std::env::var("DATABASE_URL").ok().filter(|v| !v.is_empty())?;
    match PgPoolOptions::new().max_connections(5).connect(&url).await {
        Ok(pool) => {
            tracing::info!("admin DB connected — infra_operations audit is live");
            Some(pool)
        }
        Err(err) => {
            tracing::error!("admin DB connect failed ({err}); running without the audit trail");
            None
        }
    }
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

async fn keys_page(State(st): State<Arc<AppState>>, headers: HeaderMap) -> Response {
    let s = match require(&headers, &st).await {
        Ok(s) => s,
        Err(r) => return r,
    };
    let keys = upstream::list_keys(&st.auth_url, &s).await;
    views::keys(&s, &keys).into_response()
}

#[derive(Debug, Deserialize)]
struct CreateKeyForm {
    name: String,
    #[serde(default)]
    scope: Option<String>,
    #[serde(default)]
    env: Option<String>,
}

async fn create_key(
    State(st): State<Arc<AppState>>,
    headers: HeaderMap,
    Form(form): Form<CreateKeyForm>,
) -> Response {
    let s = match require(&headers, &st).await {
        Ok(s) => s,
        Err(r) => return r,
    };
    let scopes = vec![form.scope.unwrap_or_else(|| "requests:write".to_string())];
    let env = form.env.as_deref().unwrap_or("live");
    let created = upstream::create_key_with_scopes(&st.auth_url, &s, &form.name, &scopes, env).await;
    if is_htmx(&headers) {
        let keys = upstream::list_keys(&st.auth_url, &s).await;
        views::keys_after_create(&form.name, &created, &keys).into_response()
    } else {
        redirect("/keys")
    }
}

async fn revoke_key(
    State(st): State<Arc<AppState>>,
    headers: HeaderMap,
    Path(key_id): Path<String>,
) -> Response {
    let s = match require(&headers, &st).await {
        Ok(s) => s,
        Err(r) => return r,
    };
    let revoked = upstream::revoke_key(&st.auth_url, &s, &key_id).await;
    if is_htmx(&headers) {
        let keys = upstream::list_keys(&st.auth_url, &s).await;
        views::keys_after_revoke(revoked, &keys).into_response()
    } else {
        redirect("/keys")
    }
}

async fn infra_page(State(st): State<Arc<AppState>>, headers: HeaderMap) -> Response {
    let s = match require_admin(&headers, &st).await {
        Ok(s) => s,
        Err(r) => return r,
    };
    let nodes = upstream::nodes(&st.brain_url).await;
    let placement = upstream::placement(&st.brain_url).await;
    let recent = recent_ops(&st).await;
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
    // Drive the real brain (best-effort), and — when the admin DB is wired —
    // record the control-plane action in the infra_operations audit trail.
    let _ = upstream::set_scale(&st.brain_url, form.target_nodes).await;
    let _ = record_scale(&st, &s, form.target_nodes).await;
    if is_htmx(&headers) {
        let nodes = upstream::nodes(&st.brain_url).await;
        let placement = upstream::placement(&st.brain_url).await;
        let recent = recent_ops(&st).await;
        views::infra_panel(&nodes, &placement, &recent, Some(form.target_nodes)).into_response()
    } else {
        redirect("/infra")
    }
}

// ---- Admin DB vertical (P2): infra_operations audit + sync broadcast ---------

/// Recent control-plane operations, newest first, as display JSON. Empty when no
/// admin DB is configured (or the query fails) so the page always renders.
async fn recent_ops(st: &AppState) -> Vec<Value> {
    let Some(pool) = &st.pool else {
        return vec![];
    };
    match sqlx::query_as::<_, InfraOperationsRow>(
        "select * from infra_operations order by created_at desc limit 10",
    )
    .fetch_all(pool)
    .await
    {
        Ok(rows) => rows
            .iter()
            .filter_map(|row| serde_json::to_value(row).ok())
            .collect(),
        Err(err) => {
            tracing::error!("recent infra_operations query failed: {err}");
            vec![]
        }
    }
}

/// Insert a `scale` row into infra_operations (status `requested`, operator
/// resolved from the session email if a matching operator exists) and broadcast
/// it as a `fiducia:sync` change. No-op without an admin DB.
async fn record_scale(st: &AppState, s: &Session, target_nodes: u32) -> Option<InfraOperationsRow> {
    let pool = st.pool.as_ref()?;
    let operator_id: Option<Uuid> = match &s.email {
        Some(email) => sqlx::query_scalar::<_, Uuid>(
            "select id from operators where lower(email) = lower($1)",
        )
        .bind(email)
        .fetch_optional(pool)
        .await
        .ok()
        .flatten(),
        None => None,
    };
    match sqlx::query_as::<_, InfraOperationsRow>(
        "insert into infra_operations (operator_id, action, target_nodes, status, params) \
         values ($1, 'scale', $2, 'requested', $3) returning *",
    )
    .bind(operator_id)
    .bind(target_nodes as i32)
    .bind(json!({ "target_nodes": target_nodes, "replication_factor": 3 }))
    .fetch_one(pool)
    .await
    {
        Ok(row) => {
            broadcast_infra_change(st, &row);
            Some(row)
        }
        Err(err) => {
            tracing::error!("infra_operations insert failed: {err}");
            None
        }
    }
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
}

/// Persist a queued infra_operations write and return the committed row version
/// so the client can adopt it and clear its `dirty` flag; broadcast the change so
/// every WS subscriber reconciles too. The BEFORE UPDATE trigger bumps `version`.
async fn sync_write_infra_operations(
    State(st): State<Arc<AppState>>,
    Json(req): Json<SyncWriteRequest>,
) -> Response {
    let op = req.op.as_deref().unwrap_or("upsert");

    if let Some(pool) = &st.pool {
        if let Ok(id) = Uuid::parse_str(&req.id) {
            let committed = if op == "delete" {
                // A control-plane op is an audit record, not a droppable row: a
                // "delete" marks it failed. Version still bumps via the trigger.
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
                    broadcast_infra_change(&st, &row);
                    return Json(json!({
                        "id": row.id.to_string(),
                        "committed_version": row.version,
                    }))
                    .into_response();
                }
                Ok(None) => {}
                Err(err) => tracing::error!("infra_operations sync write failed: {err}"),
            }
        }
    }

    // Fallback ack (no pool, unparseable id, or no matching row): a monotonic
    // version so the client's queue drains cleanly instead of retrying.
    Json(json!({
        "id": req.id,
        "committed_version": req.base_version.unwrap_or(0) + 1,
    }))
    .into_response()
}

/// Broadcast a single infra_operations upsert as a `fiducia:sync` frame.
fn broadcast_infra_change(st: &AppState, row: &InfraOperationsRow) {
    let frame = json!({
        "event": "fiducia:sync",
        "changes": [{
            "table": "infra_operations",
            "op": "upsert",
            "id": row.id.to_string(),
            "version": row.version,
            "row": serde_json::to_value(row).unwrap_or_default(),
            "at_ms": unix_epoch_ms(),
        }],
    });
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
async fn admin_ws(State(st): State<Arc<AppState>>, ws: WebSocketUpgrade) -> Response {
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
