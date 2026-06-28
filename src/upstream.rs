//! Calls to the other fiducia services.
//!
//! The admin app is a thin web tier: it renders HTML but the data and actions
//! live elsewhere — **accounts/API keys** in `fiducia-auth`, **infra** in
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
            false
        }
    }
}

/// `fiducia-brain`: cluster membership.
pub async fn nodes(brain_url: &str) -> Vec<Value> {
    brain_list(brain_url, "/v1/nodes", "nodes").await
}

/// `fiducia-brain`: shard placement map.
pub async fn placement(brain_url: &str) -> Vec<Value> {
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
            vec![]
        }
    }
}

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
}
