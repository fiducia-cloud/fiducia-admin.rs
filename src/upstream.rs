//! Calls to the other fiducia services.
//!
//! The admin app is a thin web tier: it renders HTML but the data and actions
//! live elsewhere — **accounts/API keys** in `fiducia-auth`, **infra** in
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
            false
        }
    }
}

/// `fiducia-brain`: cluster membership.
pub async fn nodes(brain_url: &str) -> Vec<Value> {
    get_array(brain_url, "/v1/nodes", "nodes").await
}

/// `fiducia-brain`: shard placement map.
pub async fn placement(brain_url: &str) -> Vec<Value> {
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
            vec![]
        }
    }
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
    let client = reqwest::Client::new();
    let mut request = client.post(url).json(&body);
    if let Some(token) = bearer {
        request = request.bearer_auth(token);
    }
    let value = request.send().await?.error_for_status()?.json().await?;
    Ok(value)
}
