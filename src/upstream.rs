//! Calls to the other fiducia services.
//!
//! The admin app is a thin web tier: it renders HTML but the data and actions
//! live elsewhere — **accounts/API keys** in `fiducia-auth`, **infra** in
<<<<<<< HEAD
//! `fiducia-brain`. Each call here is a small HTTP round-trip; failures degrade
//! gracefully (empty list / `false`) so a transient upstream blip renders an
//! empty page rather than a 500.

use std::time::Duration;

use serde_json::{json, Value};

/// Shared HTTP client (connection pooling + a sane timeout).
fn client() -> reqwest::Client {
    reqwest::Client::builder()
        .timeout(Duration::from_secs(10))
        .build()
        .unwrap_or_else(|_| reqwest::Client::new())
}

/// `fiducia-auth`: list an org's API keys (masked). Forwards the caller's session
/// bearer so auth resolves the same identity the dashboard authenticated.
pub async fn list_keys(auth_url: &str, token: Option<&str>, _org: &str) -> Vec<Value> {
    let url = format!("{}/v1/keys", auth_url.trim_end_matches('/'));
    let mut req = client().get(url);
    if let Some(token) = token {
        req = req.bearer_auth(token);
    }
    match req.send().await {
        Ok(resp) => resp
            .json::<Value>()
            .await
            .ok()
            .and_then(|v| v.get("keys").and_then(|k| k.as_array()).cloned())
            .unwrap_or_default(),
        Err(e) => {
            tracing::warn!(error = %e, "list_keys: fiducia-auth unreachable");
            vec![]
        }
    }
}

/// `fiducia-auth`: create a key. Returns the response (raw key shown once + meta).
pub async fn create_key(auth_url: &str, token: Option<&str>, org: &str, name: &str) -> Value {
    let url = format!("{}/v1/keys", auth_url.trim_end_matches('/'));
    let mut req = client().post(url).json(&json!({ "name": name, "org": org }));
    if let Some(token) = token {
        req = req.bearer_auth(token);
    }
    match req.send().await {
        Ok(resp) => resp
            .json::<Value>()
            .await
            .unwrap_or_else(|_| json!({ "error": "bad_response" })),
        Err(e) => {
            tracing::warn!(error = %e, "create_key: fiducia-auth unreachable");
            json!({ "error": "auth_unreachable" })
        }
    }
}

/// `fiducia-auth`: revoke a key. Returns whether auth reported it revoked.
pub async fn revoke_key(auth_url: &str, token: Option<&str>, _org: &str, key_id: &str) -> bool {
    let url = format!(
        "{}/v1/keys/{}",
        auth_url.trim_end_matches('/'),
        urlencode(key_id)
    );
    let mut req = client().delete(url);
    if let Some(token) = token {
        req = req.bearer_auth(token);
    }
    match req.send().await {
        Ok(resp) => resp
            .json::<Value>()
            .await
            .ok()
            .and_then(|v| v.get("revoked").and_then(|r| r.as_bool()))
            .unwrap_or(false),
        Err(e) => {
            tracing::warn!(error = %e, "revoke_key: fiducia-auth unreachable");
=======
//! `fiducia-brain`.

use serde_json::{json, Value};

use crate::session::Session;

/// `fiducia-auth`: list the caller's org API keys (masked).
pub async fn list_keys(auth_url: &str, session: &Session) -> Vec<Value> {
    let Some(token) = session.bearer_token.as_deref() else {
        return vec![];
    };
    let url = format!("{}/v1/keys", auth_url.trim_end_matches('/'));
    match get_json(reqwest::Client::new().get(url).bearer_auth(token)).await {
        Ok(value) => value
            .get("keys")
            .and_then(Value::as_array)
            .cloned()
            .unwrap_or_default(),
        Err(err) => {
            tracing::warn!(error = %err, "failed to list API keys via fiducia-auth");
            vec![]
        }
    }
}

/// `fiducia-auth`: create a scoped key. Returns the raw key (shown once) + meta.
pub async fn create_key_with_scopes(
    auth_url: &str,
    session: &Session,
    name: &str,
    scopes: &[String],
    env: &str,
) -> Value {
    let Some(token) = session.bearer_token.as_deref() else {
        return json!({ "error": "missing_bearer_session" });
    };
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
    .unwrap_or_else(|err| json!({ "error": "upstream_failed", "detail": err.to_string() }))
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

/// `fiducia-auth`: revoke a key.
pub async fn revoke_key(auth_url: &str, session: &Session, key_id: &str) -> bool {
    let Some(token) = session.bearer_token.as_deref() else {
        return false;
    };
    let url = format!("{}/v1/keys/{}", auth_url.trim_end_matches('/'), key_id);
    match get_json(reqwest::Client::new().delete(url).bearer_auth(token)).await {
        Ok(value) => value
            .get("revoked")
            .and_then(Value::as_bool)
            .unwrap_or(false),
        Err(err) => {
            tracing::warn!(error = %err, key_id, "failed to revoke API key via fiducia-auth");
>>>>>>> origin/main
            false
        }
    }
}

/// `fiducia-brain`: cluster membership.
pub async fn nodes(brain_url: &str) -> Vec<Value> {
<<<<<<< HEAD
    brain_list(brain_url, "/v1/nodes", "nodes").await
=======
    get_array(brain_url, "/v1/nodes", "nodes").await
>>>>>>> origin/main
}

/// `fiducia-brain`: shard placement map.
pub async fn placement(brain_url: &str) -> Vec<Value> {
<<<<<<< HEAD
    brain_list(brain_url, "/v1/placement", "shards").await
}

/// Shared GET for the brain's `{ "<field>": [...] }` list endpoints.
async fn brain_list(brain_url: &str, path: &str, field: &str) -> Vec<Value> {
    let url = format!("{}{}", brain_url.trim_end_matches('/'), path);
    match client().get(&url).send().await {
        Ok(resp) => resp
            .json::<Value>()
            .await
            .ok()
            .and_then(|v| v.get(field).and_then(|a| a.as_array()).cloned())
            .unwrap_or_default(),
        Err(e) => {
            tracing::warn!(error = %e, url, "brain list: fiducia-brain unreachable");
=======
    get_array(brain_url, "/v1/placement", "shards").await
}

/// `fiducia-brain`: set the desired scale plan.
pub async fn set_scale(brain_url: &str, target_nodes: u32) -> bool {
    let url = format!("{}/v1/scale", brain_url.trim_end_matches('/'));
    post_json(
        url,
        None,
        json!({ "target_nodes": target_nodes, "replication_factor": 3 }),
    )
    .await
    .map(|value| value.get("ok").and_then(Value::as_bool).unwrap_or(false))
    .unwrap_or(false)
}

async fn get_array(base_url: &str, path: &str, field: &str) -> Vec<Value> {
    let url = format!("{}{}", base_url.trim_end_matches('/'), path);
    match get_json(reqwest::Client::new().get(url)).await {
        Ok(value) => value
            .get(field)
            .and_then(Value::as_array)
            .cloned()
            .unwrap_or_default(),
        Err(err) => {
            tracing::warn!(error = %err, path, "failed to fetch admin upstream data");
>>>>>>> origin/main
            vec![]
        }
    }
}

<<<<<<< HEAD
/// `fiducia-brain`: set the desired scale plan. The brain's `ScalePlan` needs a
/// replication factor too, so we read the current one from `/v1/config` and keep
/// it (the admin form only changes node count).
pub async fn set_scale(brain_url: &str, target_nodes: u32) -> bool {
    let base = brain_url.trim_end_matches('/');
    let rf = current_replication_factor(base).await.unwrap_or(3);
    let url = format!("{base}/v1/scale");
    match client()
        .post(&url)
        .json(&json!({ "target_nodes": target_nodes, "replication_factor": rf }))
        .send()
        .await
    {
        Ok(resp) => resp
            .json::<Value>()
            .await
            .ok()
            .and_then(|v| v.get("ok").and_then(|o| o.as_bool()))
            .unwrap_or(false),
        Err(e) => {
            tracing::warn!(error = %e, "set_scale: fiducia-brain unreachable");
            false
        }
    }
}

/// Read the cluster's current replication factor so a scale change preserves it.
async fn current_replication_factor(brain_base: &str) -> Option<u32> {
    let url = format!("{brain_base}/v1/config");
    let v: Value = client().get(&url).send().await.ok()?.json().await.ok()?;
    v.get("replication_factor")
        .and_then(|r| r.as_u64())
        .map(|r| r as u32)
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
=======
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
    let client = reqwest::Client::new();
    let mut request = client.post(url).json(&body);
    if let Some(token) = bearer {
        request = request.bearer_auth(token);
    }
    let value = request.send().await?.error_for_status()?.json().await?;
    Ok(value)
>>>>>>> origin/main
}
