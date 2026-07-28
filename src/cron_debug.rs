//! Operator-only cron debugging surface.
//!
//! This module deliberately keeps the browser outside the service trust boundary:
//! a verified operator selects a canonical organization, and the admin BFF builds
//! a new request containing only trusted-hop authentication, the tenant header,
//! and W3C trace context. Browser cookies and bearer tokens are never forwarded.
//! Function source and invocation payloads are removed before rendering or JSON
//! serialization; the default debugger is metadata-only.

use super::*;
use axum::http::header::{AUTHORIZATION, CACHE_CONTROL, COOKIE, PRAGMA};
use maud::{html, Markup};
use reqwest::{Client, Method, Url};
use serde_json::{Map, Value};
use std::sync::LazyLock;
use std::time::Duration;

const CRON_ADMIN_TIMEOUT: Duration = Duration::from_secs(5);
const MAX_UPSTREAM_BYTES: usize = 2 * 1024 * 1024;
const MAX_ORG_BYTES: usize = 128;
const MAX_SCHEDULE_BYTES: usize = 128;
const MAX_SEARCH_BYTES: usize = 128;
const MAX_RESULTS: usize = 100;
const MAX_WINDOW_MS: u64 = 31 * 24 * 60 * 60 * 1000;
const ORG_HEADER: &str = "x-fiducia-org-id";

#[derive(Clone)]
pub(crate) struct CronAdminServices {
    client: Client,
    node: Option<TrustedCronService>,
    functions: Option<TrustedCronService>,
}

#[derive(Clone)]
struct TrustedCronService {
    base: Url,
    auth_header: HeaderName,
    secret: HeaderValue,
}

static CRON_ADMIN_SERVICES: LazyLock<CronAdminServices> =
    LazyLock::new(CronAdminServices::from_env);

#[derive(Clone, Copy)]
enum CronServiceKind {
    Node,
    Functions,
}

impl CronAdminServices {
    pub(crate) fn from_env() -> Self {
        let client = Client::builder()
            .timeout(CRON_ADMIN_TIMEOUT)
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .expect("cron admin HTTP client configuration is static");
        let node_url = optional_env("FIDUCIA_CRON_NODE_URL")
            .or_else(|| csv_env("FIDUCIA_NODE_URLS").into_iter().next());
        Self {
            client,
            node: trusted_service(
                node_url,
                optional_env("FIDUCIA_INTERNAL_SECRET"),
                HeaderName::from_static("x-fiducia-internal-auth"),
            ),
            functions: trusted_service(
                optional_env("FIDUCIA_LAMBDA_SERVICE_URL"),
                optional_env("FIDUCIA_LAMBDA_SERVER_AUTH_SECRET"),
                HeaderName::from_static("x-server-auth"),
            ),
        }
    }

    #[cfg(test)]
    fn disabled() -> Self {
        Self {
            client: Client::builder()
                .timeout(CRON_ADMIN_TIMEOUT)
                .redirect(reqwest::redirect::Policy::none())
                .build()
                .unwrap(),
            node: None,
            functions: None,
        }
    }
}

fn trusted_service(
    raw_url: Option<String>,
    raw_secret: Option<String>,
    auth_header: HeaderName,
) -> Option<TrustedCronService> {
    let mut base = Url::parse(raw_url?.trim()).ok()?;
    if !matches!(base.scheme(), "http" | "https")
        || base.host_str().is_none()
        || !base.username().is_empty()
        || base.password().is_some()
    {
        tracing::error!(header = %auth_header, "invalid cron admin upstream URL; integration disabled");
        return None;
    }
    base.set_query(None);
    base.set_fragment(None);
    base.set_path(&format!("{}/", base.path().trim_end_matches('/')));
    let secret = HeaderValue::from_str(raw_secret?.trim()).ok()?;
    Some(TrustedCronService {
        base,
        auth_header,
        secret,
    })
}

pub(crate) fn cron_admin_routes(router: Router<Arc<AppState>>) -> Router<Arc<AppState>> {
    router
        .route("/crons", get(cron_debug_page))
        .route("/api/admin/crons", get(cron_debug_api))
        .route("/crons/:org_id/:schedule/:action", post(cron_action_form))
        .route(
            "/api/admin/crons/:org_id/:schedule/:action",
            post(cron_action_api),
        )
}

#[derive(Clone, Debug, Default, Deserialize)]
struct CronDebugQuery {
    org_id: Option<String>,
    schedule: Option<String>,
    run_id: Option<String>,
    trace_id: Option<String>,
    function_id: Option<String>,
    from_ms: Option<u64>,
    to_ms: Option<u64>,
    limit: Option<usize>,
}

#[derive(Clone, Debug, Serialize)]
struct CronDebugSnapshot {
    org_id: String,
    schedules: Vec<Value>,
    schedule: Option<Value>,
    runs: Vec<Value>,
    function: Option<Value>,
    generated_at_ms: u64,
}

async fn cron_debug_page(
    State(st): State<Arc<AppState>>,
    headers: HeaderMap,
    Query(query): Query<CronDebugQuery>,
) -> Response {
    let session = match require_admin(&headers, &st).await {
        Ok(session) => session,
        Err(response) => return response,
    };
    let csrf = csrf_token(&st, &session);
    if query.org_id.as_deref().is_none_or(str::is_empty) {
        return cron_page_markup(
            &session,
            &csrf,
            &query,
            None,
            None,
            st.grafana_public_url.as_deref(),
        )
        .into_response();
    }
    let span = tracing::info_span!(
        "admin.cron.search",
        search.has_schedule = query.schedule.is_some(),
        search.has_run_id = query.run_id.is_some(),
        search.has_trace_id = query.trace_id.is_some(),
        search.has_function_id = query.function_id.is_some(),
    );
    let _entered = span.enter();
    match load_snapshot(&st, &headers, &query).await {
        Ok(snapshot) => cron_page_markup(
            &session,
            &csrf,
            &query,
            Some(&snapshot),
            None,
            st.grafana_public_url.as_deref(),
        )
        .into_response(),
        Err(error) => cron_page_markup(
            &session,
            &csrf,
            &query,
            None,
            Some(error.code()),
            st.grafana_public_url.as_deref(),
        )
        .into_response(),
    }
}

async fn cron_debug_api(
    State(st): State<Arc<AppState>>,
    headers: HeaderMap,
    Query(query): Query<CronDebugQuery>,
) -> Response {
    if let Err(response) = require_admin_api(&headers, &st).await {
        return response;
    }
    match load_snapshot(&st, &headers, &query).await {
        Ok(snapshot) => {
            no_store_admin_json(StatusCode::OK, json!({ "ok": true, "snapshot": snapshot }))
        }
        Err(error) => no_store_admin_json(
            error.status(),
            json!({ "ok": false, "error": error.code() }),
        ),
    }
}

#[derive(Debug)]
enum CronDebugError {
    BadRequest(&'static str),
    NotConfigured(&'static str),
    Upstream(&'static str),
}

impl CronDebugError {
    fn code(&self) -> &'static str {
        match self {
            Self::BadRequest(code) | Self::NotConfigured(code) | Self::Upstream(code) => code,
        }
    }

    fn status(&self) -> StatusCode {
        match self {
            Self::BadRequest(_) => StatusCode::BAD_REQUEST,
            Self::NotConfigured(_) => StatusCode::SERVICE_UNAVAILABLE,
            Self::Upstream(_) => StatusCode::BAD_GATEWAY,
        }
    }
}

async fn load_snapshot(
    st: &AppState,
    incoming: &HeaderMap,
    query: &CronDebugQuery,
) -> Result<CronDebugSnapshot, CronDebugError> {
    validate_query(query)?;
    let org_id = query
        .org_id
        .as_deref()
        .ok_or(CronDebugError::BadRequest("org_id_required"))?;
    let limit = query.limit.unwrap_or(50).clamp(1, MAX_RESULTS);
    let schedules_body = upstream_json(
        st,
        incoming,
        org_id,
        CronServiceKind::Node,
        Method::GET,
        &["v1", "cron", "schedules"],
        &[("limit", "200".to_string())],
        None,
    )
    .await?;
    let mut schedules = schedules_body
        .get("schedules")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default();
    if let Some(function_id) = query.function_id.as_deref() {
        schedules.retain(|schedule| schedule_function_id(schedule) == Some(function_id));
    }
    schedules.truncate(limit);

    let mut selected_schedule = None;
    let mut runs = Vec::new();
    if let Some(schedule_name) = query.schedule.as_deref() {
        let body = upstream_json(
            st,
            incoming,
            org_id,
            CronServiceKind::Node,
            Method::GET,
            &["v1", "cron", "schedules", schedule_name],
            &[],
            None,
        )
        .await?;
        selected_schedule = body.get("schedule").cloned();
        let history = upstream_json(
            st,
            incoming,
            org_id,
            CronServiceKind::Node,
            Method::GET,
            &["v1", "cron", "schedules", schedule_name, "history"],
            &[("limit", limit.to_string())],
            None,
        )
        .await?;
        runs = history
            .get("history")
            .and_then(Value::as_array)
            .cloned()
            .unwrap_or_default();
        runs.retain(|run| run_matches(run, query));
        runs.truncate(limit);
    }

    let function = match query.function_id.as_deref() {
        Some(function_id) => {
            let value = upstream_json(
                st,
                incoming,
                org_id,
                CronServiceKind::Functions,
                Method::GET,
                &["v1", "functions", function_id],
                &[],
                None,
            )
            .await?;
            Some(redact_function_value(value))
        }
        None => None,
    };

    Ok(CronDebugSnapshot {
        org_id: org_id.to_string(),
        schedules,
        schedule: selected_schedule,
        runs,
        function,
        generated_at_ms: cron_now_ms(),
    })
}

fn validate_query(query: &CronDebugQuery) -> Result<(), CronDebugError> {
    let org_id = query
        .org_id
        .as_deref()
        .ok_or(CronDebugError::BadRequest("org_id_required"))?;
    if !valid_bounded_token(org_id, MAX_ORG_BYTES, true) {
        return Err(CronDebugError::BadRequest("invalid_org_id"));
    }
    if let Some(schedule) = query.schedule.as_deref() {
        if !valid_bounded_token(schedule, MAX_SCHEDULE_BYTES, true) {
            return Err(CronDebugError::BadRequest("invalid_schedule"));
        }
    }
    for value in [query.run_id.as_deref(), query.trace_id.as_deref()] {
        if value.is_some_and(|value| !valid_bounded_token(value, MAX_SEARCH_BYTES, true)) {
            return Err(CronDebugError::BadRequest("invalid_search_value"));
        }
    }
    if query
        .function_id
        .as_deref()
        .is_some_and(|value| Uuid::parse_str(value).is_err())
    {
        return Err(CronDebugError::BadRequest("invalid_function_id"));
    }
    if (query.run_id.is_some()
        || query.trace_id.is_some()
        || query.from_ms.is_some()
        || query.to_ms.is_some())
        && query.schedule.is_none()
    {
        return Err(CronDebugError::BadRequest(
            "schedule_required_for_run_search",
        ));
    }
    if let (Some(from), Some(to)) = (query.from_ms, query.to_ms) {
        if from > to || to.saturating_sub(from) > MAX_WINDOW_MS {
            return Err(CronDebugError::BadRequest("invalid_time_range"));
        }
    }
    Ok(())
}

fn valid_bounded_token(value: &str, max: usize, allow_punctuation: bool) -> bool {
    !value.is_empty()
        && value.len() <= max
        && value.bytes().all(|byte| {
            byte.is_ascii_alphanumeric()
                || (allow_punctuation && matches!(byte, b'-' | b'_' | b'.' | b':'))
        })
}

fn schedule_function_id(schedule: &Value) -> Option<&str> {
    schedule
        .get("target")
        .and_then(|target| target.get("function_id"))
        .and_then(Value::as_str)
}

fn run_matches(run: &Value, query: &CronDebugQuery) -> bool {
    if let Some(expected) = query.run_id.as_deref() {
        let matches = ["run_id", "fire_id", "fire_id_ms", "idempotency_key"]
            .into_iter()
            .any(|field| value_as_string(run.get(field)).as_deref() == Some(expected));
        if !matches {
            return false;
        }
    }
    if let Some(expected) = query.trace_id.as_deref() {
        if run.get("trace_id").and_then(Value::as_str) != Some(expected) {
            return false;
        }
    }
    let at_ms = [
        "started_at_ms",
        "started_ms",
        "completed_at_ms",
        "fire_id_ms",
    ]
    .into_iter()
    .find_map(|field| run.get(field).and_then(Value::as_u64));
    if query
        .from_ms
        .is_some_and(|from| at_ms.is_none_or(|at| at < from))
    {
        return false;
    }
    if query.to_ms.is_some_and(|to| at_ms.is_none_or(|at| at > to)) {
        return false;
    }
    true
}

fn value_as_string(value: Option<&Value>) -> Option<String> {
    match value? {
        Value::String(value) => Some(value.clone()),
        Value::Number(value) => Some(value.to_string()),
        _ => None,
    }
}

fn redact_function_value(mut value: Value) -> Value {
    fn redact_object(object: &mut Map<String, Value>) {
        for key in [
            "functionBody",
            "function_body",
            "source",
            "environment",
            "entryCommand",
            "entry_command",
            "container",
            "request",
            "payload",
        ] {
            object.remove(key);
        }
        object.insert("source_redacted".to_string(), Value::Bool(true));
    }
    if let Some(object) = value.as_object_mut() {
        redact_object(object);
        if let Some(function) = object.get_mut("function").and_then(Value::as_object_mut) {
            redact_object(function);
        }
    }
    value
}

async fn upstream_json(
    _st: &AppState,
    incoming: &HeaderMap,
    org_id: &str,
    kind: CronServiceKind,
    method: Method,
    path: &[&str],
    query: &[(&str, String)],
    body: Option<Value>,
) -> Result<Value, CronDebugError> {
    let service = match kind {
        CronServiceKind::Node => CRON_ADMIN_SERVICES.node.as_ref(),
        CronServiceKind::Functions => CRON_ADMIN_SERVICES.functions.as_ref(),
    }
    .ok_or(CronDebugError::NotConfigured("cron_service_not_configured"))?;
    let url = service_url(service, path, query)?;
    let headers = outbound_headers(service, org_id, incoming)?;
    let mut request = CRON_ADMIN_SERVICES
        .client
        .request(method, url)
        .headers(headers);
    if let Some(body) = body {
        request = request.json(&body);
    }
    let mut response = request.send().await.map_err(|error| {
        tracing::warn!(
            dependency = match kind {
                CronServiceKind::Node => "fiducia-node",
                CronServiceKind::Functions => "fiducia-lambda-service",
            },
            error.class = if error.is_timeout() {
                "timeout"
            } else {
                "transport"
            },
            "admin cron upstream failed"
        );
        CronDebugError::Upstream("cron_upstream_unavailable")
    })?;
    if !response.status().is_success() {
        return Err(CronDebugError::Upstream("cron_upstream_rejected_request"));
    }
    if response
        .content_length()
        .is_some_and(|length| length > MAX_UPSTREAM_BYTES as u64)
    {
        return Err(CronDebugError::Upstream("cron_upstream_response_too_large"));
    }
    let mut bytes = Vec::new();
    while let Some(chunk) = response
        .chunk()
        .await
        .map_err(|_| CronDebugError::Upstream("cron_upstream_response_invalid"))?
    {
        if bytes.len().saturating_add(chunk.len()) > MAX_UPSTREAM_BYTES {
            return Err(CronDebugError::Upstream("cron_upstream_response_too_large"));
        }
        bytes.extend_from_slice(&chunk);
    }
    serde_json::from_slice(&bytes)
        .map_err(|_| CronDebugError::Upstream("cron_upstream_response_invalid"))
}

fn service_url(
    service: &TrustedCronService,
    path: &[&str],
    query: &[(&str, String)],
) -> Result<Url, CronDebugError> {
    let mut url = service.base.clone();
    {
        let mut segments = url
            .path_segments_mut()
            .map_err(|_| CronDebugError::Upstream("cron_upstream_url_invalid"))?;
        segments.pop_if_empty();
        for segment in path {
            segments.push(segment);
        }
    }
    if !query.is_empty() {
        let mut pairs = url.query_pairs_mut();
        for (key, value) in query {
            pairs.append_pair(key, value);
        }
    }
    Ok(url)
}

fn outbound_headers(
    service: &TrustedCronService,
    org_id: &str,
    incoming: &HeaderMap,
) -> Result<HeaderMap, CronDebugError> {
    let mut headers = HeaderMap::new();
    headers.insert(service.auth_header.clone(), service.secret.clone());
    headers.insert(
        HeaderName::from_static(ORG_HEADER),
        HeaderValue::from_str(org_id).map_err(|_| CronDebugError::BadRequest("invalid_org_id"))?,
    );
    for name in ["traceparent", "tracestate"] {
        let header = HeaderName::from_static(name);
        if let Some(value) = incoming.get(&header) {
            headers.insert(header, value.clone());
        }
    }
    debug_assert!(headers.get(COOKIE).is_none());
    debug_assert!(headers.get(AUTHORIZATION).is_none());
    Ok(headers)
}

#[derive(Debug, Deserialize)]
struct CronActionForm {
    csrf_token: String,
    #[serde(default)]
    request_id: Option<String>,
}

async fn cron_action_form(
    State(st): State<Arc<AppState>>,
    Path((org_id, schedule, action)): Path<(String, String, String)>,
    headers: HeaderMap,
    Form(form): Form<CronActionForm>,
) -> Response {
    let session = match require_admin(&headers, &st).await {
        Ok(session) => session,
        Err(response) => return response,
    };
    if let Err(error) = require_form_security(&headers, &st, &session, &form.csrf_token) {
        return request_security_error(error);
    }
    let response = mutate_schedule(
        &st,
        &session,
        &headers,
        &org_id,
        &schedule,
        &action,
        form.request_id.as_deref(),
    )
    .await;
    if response.status().is_success() && !is_htmx(&headers) {
        let location = format!(
            "/crons?org_id={}&schedule={}",
            encode_query(&org_id),
            encode_query(&schedule)
        );
        redirect(&location)
    } else {
        response
    }
}

async fn cron_action_api(
    State(st): State<Arc<AppState>>,
    Path((org_id, schedule, action)): Path<(String, String, String)>,
    headers: HeaderMap,
) -> Response {
    let session = match require_admin(&headers, &st).await {
        Ok(session) => session,
        Err(response) => return response,
    };
    if session.is_browser_session() {
        return no_store_admin_json(
            StatusCode::FORBIDDEN,
            json!({ "ok": false, "error": "browser_admin_mutation_requires_csrf_form" }),
        );
    }
    mutate_schedule(
        &st,
        &session,
        &headers,
        &org_id,
        &schedule,
        &action,
        headers
            .get("x-request-id")
            .and_then(|value| value.to_str().ok()),
    )
    .await
}

async fn mutate_schedule(
    st: &AppState,
    session: &Session,
    incoming: &HeaderMap,
    org_id: &str,
    schedule: &str,
    action: &str,
    request_id: Option<&str>,
) -> Response {
    if !valid_bounded_token(org_id, MAX_ORG_BYTES, true)
        || !valid_bounded_token(schedule, MAX_SCHEDULE_BYTES, true)
        || !matches!(action, "pause" | "resume" | "trigger")
    {
        return no_store_admin_json(
            StatusCode::BAD_REQUEST,
            json!({ "ok": false, "error": "invalid_cron_action" }),
        );
    }
    let request_id = sanitize_request_id(request_id);
    if let Err(error) = record_cron_audit(
        st,
        session,
        &format!("cron.{action}.requested"),
        org_id,
        schedule,
        request_id.clone(),
        json!({ "org_id": org_id, "schedule": schedule, "action": action }),
    )
    .await
    {
        return dependency_error("cron_audit_write_failed", error);
    }
    let query = if action == "trigger" {
        vec![("fire_id_ms", cron_now_ms().to_string())]
    } else if action == "resume" {
        vec![("catch_up", "false".to_string())]
    } else {
        Vec::new()
    };
    let result = upstream_json(
        st,
        incoming,
        org_id,
        CronServiceKind::Node,
        Method::POST,
        &["v1", "cron", "schedules", schedule, action],
        &query,
        None,
    )
    .await;
    let (status, body, outcome) = match result {
        Ok(value) => (
            StatusCode::OK,
            json!({ "ok": true, "result": value }),
            "completed",
        ),
        Err(error) => (
            error.status(),
            json!({ "ok": false, "error": error.code() }),
            "failed",
        ),
    };
    if let Err(error) = record_cron_audit(
        st,
        session,
        &format!("cron.{action}.{outcome}"),
        org_id,
        schedule,
        request_id,
        json!({ "org_id": org_id, "schedule": schedule, "action": action, "outcome": outcome }),
    )
    .await
    {
        tracing::error!(%error, "failed to append cron action outcome audit");
    }
    no_store_admin_json(status, body)
}

fn sanitize_request_id(value: Option<&str>) -> Option<String> {
    value
        .filter(|value| valid_bounded_token(value, 200, true))
        .map(str::to_string)
}

async fn record_cron_audit(
    st: &AppState,
    session: &Session,
    action: &str,
    org_id: &str,
    schedule: &str,
    request_id: Option<String>,
    meta: Value,
) -> Result<(), DbErr> {
    let db = st.db.as_ref().ok_or_else(database_unavailable)?;
    let operator_id = match enabled_operator(st, session).await? {
        Some(operator) => Some(operator.id),
        None if cfg!(debug_assertions) && session.user_id == "dev-admin" => None,
        None => {
            return Err(DbErr::Custom(
                "operator registry authorization changed before cron audit write".to_string(),
            ));
        }
    };
    admin_audit_log::ActiveModel {
        actor_operator_id: Set(operator_id),
        actor: Set(session.email.clone()),
        action: Set(action.to_string()),
        target: Set(Some(format!("{org_id}/{schedule}"))),
        request_id: Set(request_id),
        meta: Set(meta),
        ..Default::default()
    }
    .insert(db)
    .await?;
    Ok(())
}

fn no_store_admin_json(status: StatusCode, body: Value) -> Response {
    (
        status,
        [(CACHE_CONTROL, "no-store"), (PRAGMA, "no-cache")],
        Json(body),
    )
        .into_response()
}

fn cron_page_markup(
    session: &Session,
    csrf: &str,
    query: &CronDebugQuery,
    snapshot: Option<&CronDebugSnapshot>,
    error: Option<&str>,
    grafana_base: Option<&str>,
) -> Markup {
    let org = query.org_id.as_deref().unwrap_or_default();
    let schedule = query.schedule.as_deref().unwrap_or_default();
    let run_id = query.run_id.as_deref().unwrap_or_default();
    let trace_id = query.trace_id.as_deref().unwrap_or_default();
    let function_id = query.function_id.as_deref().unwrap_or_default();
    views::page(
        "Cron debugger",
        Some(session),
        Some(csrf),
        html! {
            h1 { "Cron debugger" }
            div class="card" {
                p class="muted" {
                    "Operator-only metadata and run-trail view. Function source, invocation payloads, browser credentials, and raw dependency errors are never displayed."
                }
                form method="get" action="/crons" class="form-grid" {
                    label for="cron-org" { "Organization" }
                    input id="cron-org" name="org_id" value=(org) maxlength="128" required;
                    label for="cron-schedule" { "Schedule" }
                    input id="cron-schedule" name="schedule" value=(schedule) maxlength="128";
                    label for="cron-run" { "Run / fire id" }
                    input id="cron-run" name="run_id" value=(run_id) maxlength="128";
                    label for="cron-trace" { "Trace id" }
                    input id="cron-trace" name="trace_id" value=(trace_id) maxlength="128";
                    label for="cron-function" { "Function UUID" }
                    input id="cron-function" name="function_id" value=(function_id) maxlength="36";
                    label for="cron-from" { "From epoch ms" }
                    input id="cron-from" name="from_ms" type="number" value=(query.from_ms.map(|value| value.to_string()).unwrap_or_default());
                    label for="cron-to" { "To epoch ms" }
                    input id="cron-to" name="to_ms" type="number" value=(query.to_ms.map(|value| value.to_string()).unwrap_or_default());
                    label for="cron-limit" { "Limit" }
                    input id="cron-limit" name="limit" type="number" min="1" max="100" value=(query.limit.unwrap_or(50));
                    button class="btn" type="submit" { "Search" }
                }
                @if let Some(error) = error {
                    p class="inline-message" role="alert" { "Search failed: " code { (error) } }
                }
            }
            @if let Some(snapshot) = snapshot {
                (schedule_inventory_markup(snapshot, csrf))
                (run_trail_markup(snapshot, grafana_base))
                (function_metadata_markup(snapshot))
            }
        },
    )
}

fn schedule_inventory_markup(snapshot: &CronDebugSnapshot, csrf: &str) -> Markup {
    html! {
        div class="card" {
            h2 { "Schedules" }
            p class="muted" { "Tenant: " code { (&snapshot.org_id) } }
            table {
                thead { tr { th { "Name" } th { "Schedule" } th { "Target" } th { "State" } th { "Actions" } } }
                tbody {
                    @if snapshot.schedules.is_empty() {
                        tr { td colspan="5" class="muted" { "No matching schedules." } }
                    }
                    @for schedule in &snapshot.schedules {
                        @let name = display(schedule, "name");
                        @let enabled = schedule.get("enabled").and_then(Value::as_bool).unwrap_or(false);
                        tr {
                            td { code { (&name) } }
                            td { (schedule_expression(schedule)) }
                            td { (target_summary(schedule.get("target"))) }
                            td { @if enabled { "enabled" } @else { "paused" } }
                            td {
                                @if !name.is_empty() {
                                    (cron_action_button(&snapshot.org_id, &name, if enabled { "pause" } else { "resume" }, if enabled { "Pause" } else { "Resume" }, csrf))
                                    (cron_action_button(&snapshot.org_id, &name, "trigger", "Run now", csrf))
                                }
                            }
                        }
                    }
                }
            }
        }
    }
}

fn cron_action_button(
    org_id: &str,
    schedule: &str,
    action: &str,
    label: &str,
    csrf: &str,
) -> Markup {
    html! {
        form method="post" action=(format!("/crons/{}/{}/{}", encode_query(org_id), encode_query(schedule), action)) class="form-row" {
            input type="hidden" name="csrf_token" value=(csrf);
            input type="hidden" name="request_id" value=(Uuid::new_v4().to_string());
            button class="btn btn--ghost" type="submit" { (label) }
        }
    }
}

fn run_trail_markup(snapshot: &CronDebugSnapshot, grafana_base: Option<&str>) -> Markup {
    html! {
        div class="card" {
            h2 { "Run trail" }
            table {
                thead { tr { th { "Fire / run" } th { "Status" } th { "Trigger" } th { "Attempts" } th { "Duration" } th { "HTTP" } th { "Error" } th { "Trace" } } }
                tbody {
                    @if snapshot.runs.is_empty() {
                        tr { td colspan="8" class="muted" { "Select a schedule to load its bounded run trail." } }
                    }
                    @for run in &snapshot.runs {
                        @let trace_id = display(run, "trace_id");
                        tr {
                            td { code { (display_fallback(run, &["run_id", "fire_id", "fire_id_ms"])) } }
                            td { (display(run, "status")) }
                            td { (display(run, "trigger")) }
                            td { (display(run, "attempts")) }
                            td { (display(run, "duration_ms")) " ms" }
                            td { (display(run, "http_status")) }
                            td { code { (display(run, "error_class")) } }
                            td {
                                code { (&trace_id) }
                                @if let Some(base) = grafana_base {
                                    @if !trace_id.is_empty() {
                                        " " a href=(grafana_trace_url(base, &trace_id)) rel="noreferrer" { "Tempo" }
                                        " " a href=(cluster_insight::grafana_explore_loki_url(base, &trace_logql(&trace_id), 60)) rel="noreferrer" { "Logs" }
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
    }
}

fn function_metadata_markup(snapshot: &CronDebugSnapshot) -> Markup {
    html! {
        @if let Some(function) = &snapshot.function {
            div class="card" {
                h2 { "Function metadata" }
                p class="muted" { "Source and invocation payloads are redacted by policy." }
                table { tbody {
                    tr { th { "ID" } td { code { (display_fallback(function, &["functionId", "function_id", "id"])) } } }
                    tr { th { "Name" } td { (display_fallback(function, &["displayName", "display_name", "slug"])) } }
                    tr { th { "Runtime" } td { (display(function, "runtime")) } }
                    tr { th { "Status" } td { (display_fallback(function, &["status", "state"])) } }
                    tr { th { "Source" } td { "[redacted]" } }
                } }
            }
        }
    }
}

fn schedule_expression(value: &Value) -> String {
    value
        .get("cron")
        .and_then(Value::as_str)
        .map(str::to_string)
        .or_else(|| {
            value
                .get("one_shot_at_ms")
                .map(|value| format!("one-shot {value}"))
        })
        .unwrap_or_else(|| "—".to_string())
}

fn target_summary(target: Option<&Value>) -> String {
    let Some(target) = target else {
        return "—".to_string();
    };
    match target
        .get("kind")
        .and_then(Value::as_str)
        .unwrap_or("unknown")
    {
        "function" => format!("function:{}", display(target, "function_id")),
        "queue" => format!("queue:{}", display(target, "name")),
        "webhook" => target
            .get("url")
            .and_then(Value::as_str)
            .and_then(|raw| Url::parse(raw).ok())
            .and_then(|url| url.host_str().map(|host| format!("webhook:{host}")))
            .unwrap_or_else(|| "webhook:[redacted]".to_string()),
        "grpc" => "grpc:[redacted]".to_string(),
        other => other.to_string(),
    }
}

fn display(value: &Value, key: &str) -> String {
    match value.get(key) {
        None | Some(Value::Null) => "—".to_string(),
        Some(Value::String(value)) => value.clone(),
        Some(Value::Number(value)) => value.to_string(),
        Some(Value::Bool(value)) => value.to_string(),
        Some(_) => "[structured]".to_string(),
    }
}

fn display_fallback(value: &Value, keys: &[&str]) -> String {
    keys.iter()
        .map(|key| display(value, key))
        .find(|value| value != "—")
        .unwrap_or_else(|| "—".to_string())
}

fn trace_logql(trace_id: &str) -> String {
    format!(
        "{{service_name=~\"fiducia-node|fiducia-lambda-service\"}} | json | trace_id=\"{}\"",
        trace_id
    )
}

fn grafana_trace_url(base: &str, trace_id: &str) -> String {
    let left = json!({
        "datasource": "tempo",
        "queries": [{ "refId": "A", "queryType": "traceql", "query": trace_id }],
        "range": { "from": "now-1h", "to": "now" },
    });
    format!(
        "{}/explore?left={}",
        base.trim_end_matches('/'),
        encode_query(&left.to_string())
    )
}

fn encode_query(raw: &str) -> String {
    let mut output = String::with_capacity(raw.len() * 3);
    for byte in raw.bytes() {
        match byte {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                output.push(byte as char)
            }
            _ => output.push_str(&format!("%{byte:02X}")),
        }
    }
    output
}

fn cron_now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_millis() as u64)
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn service() -> TrustedCronService {
        TrustedCronService {
            base: Url::parse("https://node.example/internal/").unwrap(),
            auth_header: HeaderName::from_static("x-fiducia-internal-auth"),
            secret: HeaderValue::from_static("secret"),
        }
    }

    #[test]
    fn outbound_headers_strip_browser_credentials() {
        let mut incoming = HeaderMap::new();
        incoming.insert(COOKIE, HeaderValue::from_static("session=secret"));
        incoming.insert(AUTHORIZATION, HeaderValue::from_static("Bearer browser"));
        incoming.insert(
            "traceparent",
            HeaderValue::from_static("00-0123456789abcdef0123456789abcdef-0123456789abcdef-01"),
        );
        let headers = outbound_headers(&service(), "acme", &incoming).unwrap();
        assert!(headers.get(COOKIE).is_none());
        assert!(headers.get(AUTHORIZATION).is_none());
        assert_eq!(headers.get(ORG_HEADER).unwrap(), "acme");
        assert_eq!(headers.get("x-fiducia-internal-auth").unwrap(), "secret");
        assert!(headers.get("traceparent").is_some());
    }

    #[test]
    fn function_source_and_payloads_are_removed() {
        let redacted = redact_function_value(json!({
            "id": Uuid::nil(),
            "runtime": "nodejs",
            "functionBody": "return process.env.SECRET",
            "environment": { "SECRET": "nope" },
            "request": { "token": "nope" }
        }));
        assert!(redacted.get("functionBody").is_none());
        assert!(redacted.get("environment").is_none());
        assert!(redacted.get("request").is_none());
        assert_eq!(redacted.get("source_redacted"), Some(&Value::Bool(true)));
    }

    #[test]
    fn run_filters_match_trace_id_and_time_window() {
        let run = json!({
            "fire_id_ms": 42,
            "trace_id": "0123456789abcdef0123456789abcdef",
            "started_at_ms": 1_000,
        });
        let query = CronDebugQuery {
            org_id: Some("acme".to_string()),
            schedule: Some("daily".to_string()),
            run_id: Some("42".to_string()),
            trace_id: Some("0123456789abcdef0123456789abcdef".to_string()),
            from_ms: Some(999),
            to_ms: Some(1_001),
            ..Default::default()
        };
        assert!(run_matches(&run, &query));
    }

    #[test]
    fn browser_mutation_client_is_disabled_in_tests_without_configuration() {
        let services = CronAdminServices::disabled();
        assert!(services.node.is_none());
        assert!(services.functions.is_none());
    }
}
