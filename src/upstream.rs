//! Calls to the other fiducia services.
//!
//! The admin app is a thin web tier: it renders HTML but the data and actions
//! live in `fiducia-brain`. Customer account and API-key traffic is deliberately
//! absent from this operator-only application. Each call returns a typed success
//! or an error to the handler; dependency failures are never presented as empty,
//! successful data.

use std::io;
use std::time::Duration;

use serde_json::{json, Value};

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

/// Attach the required trusted-hop header to an outbound brain request. Also
/// used by `cluster_insight` for the node observe fan-out — the node's `/v1`
/// enforces the same `x-fiducia-internal-auth` trusted-hop secret.
pub(crate) fn attach_internal(
    builder: reqwest::RequestBuilder,
) -> UpstreamResult<reqwest::RequestBuilder> {
    Ok(builder.header("x-fiducia-internal-auth", internal_secret()?))
}

/// `fiducia-brain`: cluster membership.
pub async fn nodes(brain_url: &str) -> UpstreamResult<Vec<Value>> {
    get_array(brain_url, "/v1/nodes", "nodes").await
}

/// `fiducia-brain`: control-plane rollup (node health counts, placement gaps,
/// brain HA/leader state). One call feeds the Cluster Insight summary cards.
pub async fn status(brain_url: &str) -> UpstreamResult<Value> {
    get_object(brain_url, "/v1/status").await
}

/// `fiducia-brain`: authoritative cluster configuration (`shard_count`,
/// `replication_factor`, `cluster_id`).
pub async fn config(brain_url: &str) -> UpstreamResult<Value> {
    get_object(brain_url, "/v1/config").await
}

/// `fiducia-brain`: namespace placement policies.
pub async fn policies(brain_url: &str) -> UpstreamResult<Value> {
    get_object(brain_url, "/v1/policies").await
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
    let value = get_object(base_url, path).await?;
    json_array(&value, field)
}

async fn get_object(base_url: &str, path: &str) -> UpstreamResult<Value> {
    let url = format!("{}{}", base_url.trim_end_matches('/'), path);
    // These helpers only fetch from the brain, so always present the trusted-hop
    // secret.
    get_json(attach_internal(client()?.get(url))?).await
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

async fn get_json(
    request: reqwest::RequestBuilder,
) -> Result<Value, Box<dyn std::error::Error + Send + Sync>> {
    Ok(request.send().await?.error_for_status()?.json().await?)
}
