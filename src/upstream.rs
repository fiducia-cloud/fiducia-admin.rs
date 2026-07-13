//! Calls to the other fiducia services.
//!
//! The admin app is a thin web tier: it renders HTML but the data and actions
//! live elsewhere — **accounts/API keys** in `fiducia-auth`, **infra** in
//! `fiducia-brain`. Each call returns a typed success or an error to the handler;
//! dependency failures are never presented as empty, successful data.

use std::io;
use std::time::Duration;

use serde_json::{json, Value};

use crate::session::Session;

/// Shared HTTP client (connection pooling + a sane timeout) so a slow upstream
/// can't hang a dashboard request.
type UpstreamResult<T> = Result<T, Box<dyn std::error::Error + Send + Sync>>;

fn client() -> UpstreamResult<reqwest::Client> {
    Ok(reqwest::Client::builder()
        .timeout(Duration::from_secs(10))
        .build()?)
}

/// The cluster trusted-hop secret, read once. The brain's `/v1` enforces it when
/// configured, so admin's brain calls (membership / placement / scale) must
/// present it. (Auth calls use the caller's bearer token instead.)
fn internal_secret() -> UpstreamResult<&'static str> {
    static SECRET: std::sync::OnceLock<Option<String>> = std::sync::OnceLock::new();
    SECRET
        .get_or_init(|| {
            std::env::var("FIDUCIA_INTERNAL_SECRET")
                .ok()
                .map(|s| s.trim().to_string())
                .filter(|s| !s.is_empty())
        })
        .as_deref()
        .ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                "FIDUCIA_INTERNAL_SECRET must be set",
            )
            .into()
        })
}

/// Attach the required trusted-hop header to an outbound brain request.
fn attach_internal(builder: reqwest::RequestBuilder) -> UpstreamResult<reqwest::RequestBuilder> {
    Ok(builder.header("x-fiducia-internal-auth", internal_secret()?))
}

/// `fiducia-auth`: list the caller's org API keys (masked). Forwards the caller's
/// session bearer so auth resolves the same identity the dashboard authenticated.
pub async fn list_keys(auth_url: &str, session: &Session) -> UpstreamResult<Vec<Value>> {
    let token = session
        .bearer_token
        .as_deref()
        .ok_or_else(|| io::Error::new(io::ErrorKind::PermissionDenied, "missing bearer session"))?;
    let url = format!("{}/v1/keys", auth_url.trim_end_matches('/'));
    let value = get_json(client()?.get(url).bearer_auth(token)).await?;
    json_array(&value, "keys")
}

/// `fiducia-auth`: create a scoped key. Returns the raw key (shown once) + meta.
pub async fn create_key_with_scopes(
    auth_url: &str,
    session: &Session,
    name: &str,
    scopes: &[String],
    env: &str,
) -> UpstreamResult<Value> {
    let token = session
        .bearer_token
        .as_deref()
        .ok_or_else(|| io::Error::new(io::ErrorKind::PermissionDenied, "missing bearer session"))?;
    let scopes = normalized_scopes(scopes);
    let env = match env.trim() {
        "" => "live",
        value => value,
    };
    let url = format!("{}/v1/keys", auth_url.trim_end_matches('/'));
    post_json(
        url,
        Some(token),
        json!({ "name": name, "org_id": session.orgs.first(), "scopes": scopes, "env": env }),
    )
    .await
}

fn normalized_scopes(scopes: &[String]) -> Vec<String> {
    let mut out = scopes
        .iter()
        .map(|scope| scope.trim())
        .filter(|scope| !scope.is_empty())
        .map(ToString::to_string)
        .collect::<Vec<_>>();
    if out.is_empty() {
        out.push("requests:write".to_string());
    }
    out.sort();
    out.dedup();
    out
}

/// `fiducia-auth`: revoke a key. Returns whether auth reported it revoked.
pub async fn revoke_key(auth_url: &str, session: &Session, key_id: &str) -> UpstreamResult<bool> {
    let token = session
        .bearer_token
        .as_deref()
        .ok_or_else(|| io::Error::new(io::ErrorKind::PermissionDenied, "missing bearer session"))?;
    let url = format!(
        "{}/v1/keys/{}",
        auth_url.trim_end_matches('/'),
        urlencode(key_id)
    );
    let value = get_json(client()?.delete(url).bearer_auth(token)).await?;
    value
        .get("revoked")
        .and_then(Value::as_bool)
        .ok_or_else(|| {
            io::Error::new(io::ErrorKind::InvalidData, "auth response omitted revoked").into()
        })
}

/// `fiducia-brain`: cluster membership.
pub async fn nodes(brain_url: &str) -> UpstreamResult<Vec<Value>> {
    get_array(brain_url, "/v1/nodes", "nodes").await
}

/// `fiducia-brain`: shard placement map.
pub async fn placement(brain_url: &str) -> UpstreamResult<Vec<Value>> {
    get_array(brain_url, "/v1/placement", "shards").await
}

/// `fiducia-brain`: set the desired scale plan. The replication factor is fixed
/// at the multi-cloud baseline (the brain clamps it server-side anyway), so the
/// admin form only changes the node count.
pub async fn set_scale(brain_url: &str, target_nodes: u32) -> UpstreamResult<bool> {
    let url = format!("{}/v1/scale", brain_url.trim_end_matches('/'));
    let value =
        get_json(attach_internal(client()?.post(url).json(
            &json!({ "target_nodes": target_nodes, "replication_factor": 3 }),
        ))?)
        .await?;
    value.get("ok").and_then(Value::as_bool).ok_or_else(|| {
        io::Error::new(io::ErrorKind::InvalidData, "brain response omitted ok").into()
    })
}

async fn get_array(base_url: &str, path: &str, field: &str) -> UpstreamResult<Vec<Value>> {
    let url = format!("{}{}", base_url.trim_end_matches('/'), path);
    // get_array only fetches from the brain (nodes / placement), so always present
    // the trusted-hop secret.
    let value = get_json(attach_internal(client()?.get(url))?).await?;
    json_array(&value, field)
}

fn json_array(value: &Value, field: &str) -> UpstreamResult<Vec<Value>> {
    value
        .get(field)
        .and_then(Value::as_array)
        .cloned()
        .ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                format!("upstream response omitted {field} array"),
            )
            .into()
        })
}

/// Percent-encode a single path segment (key ids are opaque but kept URL-safe).
fn urlencode(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for b in s.bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                out.push(b as char)
            }
            _ => out.push_str(&format!("%{b:02X}")),
        }
    }
    out
}

async fn get_json(
    request: reqwest::RequestBuilder,
) -> Result<Value, Box<dyn std::error::Error + Send + Sync>> {
    Ok(request.send().await?.error_for_status()?.json().await?)
}

async fn post_json(
    url: String,
    bearer: Option<&str>,
    body: Value,
) -> Result<Value, Box<dyn std::error::Error + Send + Sync>> {
    let mut request = client()?.post(url).json(&body);
    if let Some(token) = bearer {
        request = request.bearer_auth(token);
    }
    let value = request.send().await?.error_for_status()?.json().await?;
    Ok(value)
}
