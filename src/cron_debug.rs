//! Operator-only cron diagnostics.
//!
//! This module deliberately exposes schedule metadata and run outcomes only. It
//! never asks the lambda service for function source or invocation payloads.

use std::sync::Arc;
use std::time::Duration;

use axum::extract::{Path, Query, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::Json;
use maud::{html, Markup};
use reqwest::{Client, Url};
use serde::Deserialize;
use serde_json::{json, Value};

use crate::{csrf_token, require_admin, require_admin_api, views, AppState};

const MAX_ORG_BYTES: usize = 128;
const MAX_SCHEDULE_BYTES: usize = 128;
const DEFAULT_HISTORY_LIMIT: usize = 50;
const MAX_HISTORY_LIMIT: usize = 100;
const MAX_UPSTREAM_BYTES: usize = 2 * 1024 * 1024;
const UPSTREAM_TIMEOUT_SECS: u64 = 5;

#[derive(Debug, Default, Deserialize)]
pub(crate) struct CronPageQuery {
    org: Option<String>,
    schedule: Option<String>,
    limit: Option<usize>,
}

#[derive(Debug, Deserialize)]
pub(crate) struct CronListQuery {
    org: String,
}

#[derive(Debug, Deserialize)]
pub(crate) struct CronHistoryQuery {
    org: String,
    limit: Option<usize>,
}

#[derive(Debug)]
enum CronDebugError {
    NotConfigured,
    InvalidConfiguration,
    InvalidOrganization,
    InvalidSchedule,
    UpstreamUnavailable,
    UpstreamStatus(u16),
    OversizedResponse,
    InvalidResponse,
}

impl CronDebugError {
    fn code(&self) -> &'static str {
        match self {
            Self::NotConfigured => "cron_node_not_configured",
            Self::InvalidConfiguration => "cron_node_configuration_invalid",
            Self::InvalidOrganization => "invalid_organization",
            Self::InvalidSchedule => "invalid_schedule",
            Self::UpstreamUnavailable => "cron_node_unavailable",
            Self::UpstreamStatus(_) => "cron_node_rejected_request",
            Self::OversizedResponse => "cron_node_response_too_large",
            Self::InvalidResponse => "cron_node_response_invalid",
        }
    }

    fn status(&self) -> StatusCode {
        match self {
            Self::InvalidOrganization | Self::InvalidSchedule => StatusCode::BAD_REQUEST,
            Self::NotConfigured | Self::InvalidConfiguration => StatusCode::SERVICE_UNAVAILABLE,
            Self::UpstreamStatus(code) => StatusCode::from_u16(*code)
                .ok()
                .filter(|status| status.is_client_error())
                .unwrap_or(StatusCode::BAD_GATEWAY),
            Self::UpstreamUnavailable | Self::OversizedResponse | Self::InvalidResponse => {
                StatusCode::BAD_GATEWAY
            }
        }
    }
}

pub(crate) async fn page(
    State(st): State<Arc<AppState>>,
    headers: HeaderMap,
    Query(query): Query<CronPageQuery>,
) -> Response {
    let session = match require_admin(&headers, &st).await {
        Ok(session) => session,
        Err(response) => return response,
    };
    let csrf = csrf_token(&st, &session);

    let org = query
        .org
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(str::to_string);
    let schedule = query
        .schedule
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(str::to_string);
    let limit = query
        .limit
        .unwrap_or(DEFAULT_HISTORY_LIMIT)
        .clamp(1, MAX_HISTORY_LIMIT);

    let mut error: Option<&'static str> = None;
    let mut schedules = None;
    let mut history = None;

    if let Some(org_id) = org.as_deref() {
        if !valid_org(org_id) {
            error = Some(CronDebugError::InvalidOrganization.code());
        } else {
            match fetch_schedules(&st, org_id).await {
                Ok(value) => schedules = Some(value),
                Err(cause) => {
                    tracing::warn!(error = cause.code(), "admin cron schedule lookup failed");
                    error = Some(cause.code());
                }
            }
        }
    }

    if error.is_none() {
        if let (Some(org_id), Some(schedule_name)) = (org.as_deref(), schedule.as_deref()) {
            if !valid_schedule(schedule_name) {
                error = Some(CronDebugError::InvalidSchedule.code());
            } else {
                match fetch_history(&st, org_id, schedule_name, limit).await {
                    Ok(value) => history = Some(value),
                    Err(cause) => {
                        tracing::warn!(error = cause.code(), "admin cron history lookup failed");
                        error = Some(cause.code());
                    }
                }
            }
        }
    }

    let body = cron_page_body(
        org.as_deref(),
        schedule.as_deref(),
        limit,
        schedules.as_ref(),
        history.as_ref(),
        error,
    );
    (StatusCode::OK, views::page("Cron debugger", Some(&session), Some(&csrf), body))
        .into_response()
}

pub(crate) async fn list_api(
    State(st): State<Arc<AppState>>,
    headers: HeaderMap,
    Query(query): Query<CronListQuery>,
) -> Response {
    if let Err(response) = require_admin_api(&headers, &st).await {
        return response;
    }
    let org = query.org.trim();
    if !valid_org(org) {
        return error_response(CronDebugError::InvalidOrganization);
    }
    match fetch_schedules(&st, org).await {
        Ok(value) => Json(value).into_response(),
        Err(error) => error_response(error),
    }
}

pub(crate) async fn history_api(
    State(st): State<Arc<AppState>>,
    Path(schedule): Path<String>,
    headers: HeaderMap,
    Query(query): Query<CronHistoryQuery>,
) -> Response {
    if let Err(response) = require_admin_api(&headers, &st).await {
        return response;
    }
    let org = query.org.trim();
    if !valid_org(org) {
        return error_response(CronDebugError::InvalidOrganization);
    }
    if !valid_schedule(&schedule) {
        return error_response(CronDebugError::InvalidSchedule);
    }
    let limit = query
        .limit
        .unwrap_or(DEFAULT_HISTORY_LIMIT)
        .clamp(1, MAX_HISTORY_LIMIT);
    match fetch_history(&st, org, &schedule, limit).await {
        Ok(value) => Json(value).into_response(),
        Err(error) => error_response(error),
    }
}

fn error_response(error: CronDebugError) -> Response {
    let status = error.status();
    let code = error.code();
    (status, Json(json!({ "error": code }))).into_response()
}

async fn fetch_schedules(st: &AppState, org: &str) -> Result<Value, CronDebugError> {
    let mut url = cron_url(st, &["v1", "cron", "schedules"])?;
    url.query_pairs_mut().append_pair("limit", "200");
    fetch_json(st, org, url).await
}

async fn fetch_history(
    st: &AppState,
    org: &str,
    schedule: &str,
    limit: usize,
) -> Result<Value, CronDebugError> {
    let mut url = cron_url(st, &["v1", "cron", "schedules", schedule, "history"])?;
    url.query_pairs_mut()
        .append_pair("limit", &limit.clamp(1, MAX_HISTORY_LIMIT).to_string());
    fetch_json(st, org, url).await
}

fn cron_url(st: &AppState, segments: &[&str]) -> Result<Url, CronDebugError> {
    let raw = st
        .cron_node_url
        .as_deref()
        .or_else(|| st.node_urls.first().map(String::as_str))
        .ok_or(CronDebugError::NotConfigured)?;
    build_url(raw, segments)
}

fn build_url(raw: &str, segments: &[&str]) -> Result<Url, CronDebugError> {
    let mut url = Url::parse(raw.trim()).map_err(|_| CronDebugError::InvalidConfiguration)?;
    if !matches!(url.scheme(), "http" | "https")
        || !url.username().is_empty()
        || url.password().is_some()
        || url.host_str().is_none()
    {
        return Err(CronDebugError::InvalidConfiguration);
    }
    url.set_query(None);
    url.set_fragment(None);
    {
        let mut path = url
            .path_segments_mut()
            .map_err(|_| CronDebugError::InvalidConfiguration)?;
        path.pop_if_empty();
        for segment in segments {
            path.push(segment);
        }
    }
    Ok(url)
}

async fn fetch_json(st: &AppState, org: &str, url: Url) -> Result<Value, CronDebugError> {
    let client = Client::builder()
        .timeout(Duration::from_secs(UPSTREAM_TIMEOUT_SECS))
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .map_err(|_| CronDebugError::InvalidConfiguration)?;
    let response = client
        .get(url)
        .header("x-fiducia-internal-auth", &st.internal_secret)
        .header("x-fiducia-org-id", org)
        .send()
        .await
        .map_err(|_| CronDebugError::UpstreamUnavailable)?;
    let status = response.status();
    if response
        .content_length()
        .is_some_and(|length| length > MAX_UPSTREAM_BYTES as u64)
    {
        return Err(CronDebugError::OversizedResponse);
    }
    let bytes = response
        .bytes()
        .await
        .map_err(|_| CronDebugError::UpstreamUnavailable)?;
    if bytes.len() > MAX_UPSTREAM_BYTES {
        return Err(CronDebugError::OversizedResponse);
    }
    if !status.is_success() {
        return Err(CronDebugError::UpstreamStatus(status.as_u16()));
    }
    serde_json::from_slice(&bytes).map_err(|_| CronDebugError::InvalidResponse)
}

fn valid_org(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= MAX_ORG_BYTES
        && !value.chars().any(|ch| ch.is_control() || ch.is_whitespace())
}

fn valid_schedule(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= MAX_SCHEDULE_BYTES
        && !value.chars().any(char::is_control)
}

fn cron_page_body(
    org: Option<&str>,
    schedule: Option<&str>,
    limit: usize,
    schedules: Option<&Value>,
    history: Option<&Value>,
    error: Option<&str>,
) -> Markup {
    html! {
        h1 { "Cron debugger" }
        div class="card" {
            p class="muted" {
                "Read-only operator diagnostics. Enter the canonical tenant id; the server adds the trusted-hop secret and tenant header. Function source and invocation payloads are never fetched."
            }
            form method="get" action="/crons" {
                label for="org" { "Organization id" }
                input id="org" name="org" value=(org.unwrap_or_default()) maxlength=(MAX_ORG_BYTES) required;
                label for="schedule" { "Schedule name (optional)" }
                input id="schedule" name="schedule" value=(schedule.unwrap_or_default()) maxlength=(MAX_SCHEDULE_BYTES);
                label for="limit" { "Run history limit" }
                input id="limit" name="limit" type="number" min="1" max=(MAX_HISTORY_LIMIT) value=(limit);
                button class="btn" type="submit" { "Inspect" }
            }
            @if let Some(code) = error {
                p class="muted" role="alert" { "Lookup failed: " code { (code) } }
            }
        }
        @if let Some(value) = schedules {
            (schedule_table(value, org.unwrap_or_default()))
        }
        @if let Some(value) = history {
            (history_table(value))
        }
    }
}

fn schedule_table(value: &Value, org: &str) -> Markup {
    let rows = value
        .get("schedules")
        .and_then(Value::as_array)
        .map(Vec::as_slice)
        .unwrap_or_default();
    html! {
        div class="card" {
            h2 { "Tenant schedules" }
            p class="muted" { (rows.len()) " schedule(s) returned." }
            table {
                thead { tr { th { "Name" } th { "Schedule" } th { "Enabled" } th { "Target" } th { "Inspect" } } }
                tbody {
                    @for row in rows {
                        @let name = string_field(row, "name");
                        tr {
                            td { code { (name) } }
                            td { (schedule_mode(row)) }
                            td { (display_field(row, "enabled")) }
                            td { code { (target_summary(row.get("target"))) } }
                            td {
                                a href=(format!("/crons?org={}&schedule={}", query_escape(org), query_escape(&name))) { "Runs" }
                            }
                        }
                    }
                }
            }
        }
    }
}

fn history_table(value: &Value) -> Markup {
    let rows = value
        .get("history")
        .and_then(Value::as_array)
        .map(Vec::as_slice)
        .unwrap_or_default();
    html! {
        div class="card" {
            h2 { "Run trail" }
            p class="muted" { (rows.len()) " run(s), newest first. Trace ids can be copied into Grafana/Tempo and correlated with Loki logs." }
            table {
                thead { tr { th { "Fire id" } th { "Status" } th { "Trigger" } th { "Attempts" } th { "Duration ms" } th { "HTTP" } th { "Error class" } th { "Trace" } } }
                tbody {
                    @for row in rows {
                        tr {
                            td { code { (display_field(row, "fire_id")) } }
                            td { (display_field(row, "status")) }
                            td { (display_field(row, "trigger")) }
                            td { (display_field(row, "attempts")) }
                            td { (display_field(row, "duration_ms")) }
                            td { (display_field(row, "http_status")) }
                            td { (display_field(row, "error_class")) }
                            td { code { (display_field(row, "trace_id")) } }
                        }
                    }
                }
            }
        }
    }
}

fn schedule_mode(value: &Value) -> String {
    if let Some(cron) = value.get("cron").and_then(Value::as_str) {
        return cron.to_string();
    }
    value
        .get("one_shot_at_ms")
        .map(|value| format!("one-shot {}", scalar(value)))
        .unwrap_or_else(|| "—".to_string())
}

fn target_summary(value: Option<&Value>) -> String {
    let Some(value) = value else {
        return "—".to_string();
    };
    let kind = value.get("kind").and_then(Value::as_str).unwrap_or("unknown");
    match kind {
        "function" => format!("function:{}", display_field(value, "function_id")),
        "webhook" => "webhook:[redacted]".to_string(),
        "grpc" => "grpc:[redacted]".to_string(),
        "queue" => format!("queue:{}", display_field(value, "name")),
        other => other.to_string(),
    }
}

fn string_field(value: &Value, key: &str) -> String {
    value
        .get(key)
        .and_then(Value::as_str)
        .unwrap_or_default()
        .to_string()
}

fn display_field(value: &Value, key: &str) -> String {
    value.get(key).map(scalar).unwrap_or_else(|| "—".to_string())
}

fn scalar(value: &Value) -> String {
    match value {
        Value::Null => "—".to_string(),
        Value::String(value) => value.clone(),
        Value::Bool(value) => value.to_string(),
        Value::Number(value) => value.to_string(),
        _ => "[structured]".to_string(),
    }
}

fn query_escape(value: &str) -> String {
    let mut out = String::with_capacity(value.len());
    for byte in value.bytes() {
        if byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b'~') {
            out.push(char::from(byte));
        } else {
            use std::fmt::Write as _;
            let _ = write!(&mut out, "%{byte:02X}");
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn validates_org_like_the_node_scope_guard() {
        assert!(valid_org("acme-prod"));
        assert!(!valid_org(""));
        assert!(!valid_org("acme corp"));
        assert!(!valid_org("acme\ncorp"));
        assert!(!valid_org(&"a".repeat(MAX_ORG_BYTES + 1)));
    }

    #[test]
    fn schedule_path_is_encoded_as_one_segment() {
        let url = build_url("http://fiducia-node:8080", &["v1", "cron", "schedules", "billing/daily", "history"]).unwrap();
        assert_eq!(url.path(), "/v1/cron/schedules/billing%2Fdaily/history");
    }

    #[test]
    fn target_summary_never_displays_webhook_or_grpc_addresses() {
        let webhook = json!({"kind":"webhook","url":"https://secret.example/hook"});
        let grpc = json!({"kind":"grpc","endpoint":"https://secret.example/grpc"});
        assert_eq!(target_summary(Some(&webhook)), "webhook:[redacted]");
        assert_eq!(target_summary(Some(&grpc)), "grpc:[redacted]");
    }

    #[test]
    fn query_escape_encodes_tenant_and_schedule_delimiters() {
        assert_eq!(query_escape("acme/a b"), "acme%2Fa%20b");
    }
}
