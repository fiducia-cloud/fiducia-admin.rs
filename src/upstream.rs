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

/// Hard cap on any single upstream response body admin buffers (M2). Every
/// upstream JSON payload (brain status/config/policies, node observe, Prometheus
/// / Loki queries) is kilobytes in the steady state; a body past this cap is a
/// bug or a hostile/compromised upstream trying to exhaust admin's memory — the
/// concurrent node fan-out amplifies it — so the read is aborted, not allocated.
pub(crate) const MAX_UPSTREAM_BODY_BYTES: usize = 16 * 1024 * 1024;

/// An upstream failure reduced to a short, URL-free class (L7). reqwest's own
/// `Display` embeds the target URL, which must never reach
/// `node_observations[].error` or a view tooltip.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum UpstreamError {
    /// The target host is not in-cluster / not operator-trusted, so admin refused
    /// to dial it with the cluster secret (H1). Never becomes a request.
    UntrustedAddress,
    /// The body exceeded [`MAX_UPSTREAM_BODY_BYTES`] and the read was aborted (M2).
    OversizedResponse,
    /// A non-2xx status. A 3xx is included: in-cluster hops are single calls and
    /// the clients never follow redirects (H1), so a 3xx surfaces here as an error.
    BadStatus(u16),
}

impl std::fmt::Display for UpstreamError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            UpstreamError::UntrustedAddress => f.write_str("untrusted address"),
            UpstreamError::OversizedResponse => f.write_str("oversized response"),
            UpstreamError::BadStatus(code) => write!(f, "bad status: {code}"),
        }
    }
}

impl std::error::Error for UpstreamError {}

fn client() -> UpstreamResult<reqwest::Client> {
    Ok(reqwest::Client::builder()
        .timeout(Duration::from_secs(10))
        // In-cluster hops are single calls; a redirect is never legitimate and
        // must not carry the trusted-hop secret to an upstream-chosen `Location`
        // (reqwest resends custom headers across redirects) — surface 3xx as an
        // error instead of following it (H1).
        .redirect(reqwest::redirect::Policy::none())
        .build()?)
}

/// Collapse any upstream error to a short, URL-free class for
/// `node_observations[].error`, Prometheus/Loki tooltips, and metric-fan-out rows
/// (L7). Recognizes our own [`UpstreamError`] sentinels and walks the source chain
/// for a reqwest cause; anything else is a generic class, never a raw URL.
pub(crate) fn error_class(error: &(dyn std::error::Error + Send + Sync + 'static)) -> String {
    if let Some(upstream) = error.downcast_ref::<UpstreamError>() {
        return upstream.to_string();
    }
    if let Some(request) = error.downcast_ref::<reqwest::Error>() {
        return reqwest_class(request);
    }
    let mut source = error.source();
    while let Some(cause) = source {
        if let Some(request) = cause.downcast_ref::<reqwest::Error>() {
            return reqwest_class(request);
        }
        source = cause.source();
    }
    "upstream error".to_string()
}

fn reqwest_class(error: &reqwest::Error) -> String {
    if error.is_timeout() {
        "timeout".to_string()
    } else if let Some(status) = error.status() {
        format!("bad status: {}", status.as_u16())
    } else {
        // Connect refused/reset, DNS failure, mid-body transport error: all
        // "we could not get an answer" — one class, and crucially URL-free.
        "unreachable".to_string()
    }
}

/// Send a request, reject any non-2xx (a 3xx included — the clients never follow
/// redirects, H1), and read the body under a running byte cap (M2). Returns the
/// bounded buffer for the caller to deserialize.
pub(crate) async fn send_capped(request: reqwest::RequestBuilder) -> UpstreamResult<Vec<u8>> {
    let response = request.send().await?;
    let status = response.status();
    if !status.is_success() {
        return Err(UpstreamError::BadStatus(status.as_u16()).into());
    }
    read_capped_body(response).await
}

/// Buffer a response body, aborting past [`MAX_UPSTREAM_BODY_BYTES`] (M2). Reads
/// via `chunk()` so the cap is enforced as bytes arrive — the advertised
/// `Content-Length` is untrusted (it can be absent or a lie).
async fn read_capped_body(mut response: reqwest::Response) -> UpstreamResult<Vec<u8>> {
    let mut buffer = Vec::new();
    while let Some(chunk) = response.chunk().await? {
        if buffer.len().saturating_add(chunk.len()) > MAX_UPSTREAM_BODY_BYTES {
            return Err(UpstreamError::OversizedResponse.into());
        }
        buffer.extend_from_slice(&chunk);
    }
    Ok(buffer)
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
