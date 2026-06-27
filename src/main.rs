//! fiducia-admin — the server-rendered admin dashboard.
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
//! Skeleton: routing + HTML are real; session verification and the upstream
//! calls are stubbed (`FIDUCIA_ADMIN_DEV_SESSION=admin|user` lets you click
//! through the UI). See `session.rs` / `upstream.rs`.

mod session;
mod upstream;
mod views;

use std::net::SocketAddr;
use std::sync::Arc;

use axum::{
    extract::{Form, Path, State},
    http::{header::LOCATION, HeaderMap, StatusCode},
    response::{Html, IntoResponse, Response},
    routing::{get, post},
    Json, Router,
};
use serde::Deserialize;
use serde_json::{json, Value};
use tower_http::trace::TraceLayer;

use session::Session;

const SERVICE: &str = "fiducia-admin";

struct AppState {
    auth_url: String,
    brain_url: String,
}

#[tokio::main]
async fn main() {
    fiducia_telemetry::init(SERVICE);

    let state = Arc::new(AppState {
        auth_url: std::env::var("FIDUCIA_AUTH_URL").unwrap_or_else(|_| "http://localhost:8097".into()),
        brain_url: std::env::var("FIDUCIA_BRAIN_URL").unwrap_or_else(|_| "http://localhost:8095".into()),
    });

    let app = Router::new()
        .route("/healthz", get(health))
        .route("/login", get(login))
        .route("/", get(dashboard))
        .route("/account", get(account))
        .route("/keys", get(keys_page).post(create_key))
        .route("/keys/:key_id/revoke", post(revoke_key))
        .route("/infra", get(infra_page))
        .route("/infra/scale", post(scale))
        .with_state(state)
        .layer(TraceLayer::new_for_http());

    let port: u16 = std::env::var("PORT").ok().and_then(|p| p.parse().ok()).unwrap_or(8096);
    let addr = SocketAddr::from(([0, 0, 0, 0], port));
    tracing::info!("{SERVICE} listening on http://{addr}");
    let listener = tokio::net::TcpListener::bind(addr).await.unwrap();
    axum::serve(listener, app).await.unwrap();
}

async fn health() -> Json<Value> {
    Json(json!({ "status": "ok", "service": SERVICE }))
}

fn redirect(to: &str) -> Response {
    (StatusCode::SEE_OTHER, [(LOCATION, to)]).into_response()
}

/// Require any signed-in user, else redirect to /login.
async fn require(headers: &HeaderMap, st: &AppState) -> Result<Session, Response> {
    session::current(headers, &st.auth_url).await.ok_or_else(|| redirect("/login"))
}

/// Require the admin role, else 403.
async fn require_admin(headers: &HeaderMap, st: &AppState) -> Result<Session, Response> {
    let s = require(headers, st).await?;
    if s.is_admin {
        Ok(s)
    } else {
        Err((StatusCode::FORBIDDEN, Html(views::page("Forbidden", Some(&s), "<h1>403</h1><p class=\"muted\">Admin role required.</p>"))).into_response())
    }
}

async fn login() -> Html<String> {
    Html(views::login())
}

async fn dashboard(State(st): State<Arc<AppState>>, headers: HeaderMap) -> Response {
    match require(&headers, &st).await {
        Ok(s) => Html(views::dashboard(&s)).into_response(),
        Err(r) => r,
    }
}

async fn account(State(st): State<Arc<AppState>>, headers: HeaderMap) -> Response {
    match require(&headers, &st).await {
        Ok(s) => Html(views::account(&s)).into_response(),
        Err(r) => r,
    }
}

async fn keys_page(State(st): State<Arc<AppState>>, headers: HeaderMap) -> Response {
    let s = match require(&headers, &st).await { Ok(s) => s, Err(r) => return r };
    let org = s.orgs.first().cloned().unwrap_or_default();
    let keys = upstream::list_keys(&st.auth_url, &org).await;
    Html(views::keys(&s, &keys)).into_response()
}

#[derive(Debug, Deserialize)]
struct CreateKeyForm {
    name: String,
}

async fn create_key(
    State(st): State<Arc<AppState>>,
    headers: HeaderMap,
    Form(form): Form<CreateKeyForm>,
) -> Response {
    let s = match require(&headers, &st).await { Ok(s) => s, Err(r) => return r };
    let org = s.orgs.first().cloned().unwrap_or_default();
    let _ = upstream::create_key(&st.auth_url, &org, &form.name).await;
    // TODO: surface the raw key once on a confirmation page.
    redirect("/keys")
}

async fn revoke_key(
    State(st): State<Arc<AppState>>,
    headers: HeaderMap,
    Path(key_id): Path<String>,
) -> Response {
    let s = match require(&headers, &st).await { Ok(s) => s, Err(r) => return r };
    let org = s.orgs.first().cloned().unwrap_or_default();
    let _ = upstream::revoke_key(&st.auth_url, &org, &key_id).await;
    redirect("/keys")
}

async fn infra_page(State(st): State<Arc<AppState>>, headers: HeaderMap) -> Response {
    let s = match require_admin(&headers, &st).await { Ok(s) => s, Err(r) => return r };
    let nodes = upstream::nodes(&st.brain_url).await;
    let placement = upstream::placement(&st.brain_url).await;
    Html(views::infra(&s, &nodes, &placement)).into_response()
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
    if let Err(r) = require_admin(&headers, &st).await {
        return r;
    }
    let _ = upstream::set_scale(&st.brain_url, form.target_nodes).await;
    redirect("/infra")
}
