//! Cluster Insight — the read-only observability layer behind `/cluster`.
//!
//! Three planes feed the page, and every one is fetched fresh per request (this
//! service holds no cluster state):
//!
//!   * **fiducia-brain** (`/v1/status`, `/v1/nodes`, …, via [`crate::upstream`])
//!     — the authority view: membership, health counts, placement gaps.
//!   * **fiducia-node** client-plane observe endpoints (`/v1/observe/shards`,
//!     `/v1/observe/metrics`) — the Raft-eye view, fanned out to every node
//!     concurrently. These paths are exempt from the node's org-scope middleware
//!     (fiducia-node `org_scope::is_exempt`: node introspection carries no tenant
//!     state), so a call needs only the `x-fiducia-internal-auth` trusted-hop
//!     secret — no `x-fiducia-org-id` header. A down node must never break the
//!     page: each node's fetch result is carried per-node ([`NodeObservation`]),
//!     success or error.
//!   * **Observability plane** (Prometheus + Loki, both unauthenticated
//!     in-cluster) — optional. Unset URLs render as "not configured", never as
//!     an error.
//!
//! Node discovery: explicit `FIDUCIA_NODE_URLS` wins when set; otherwise node
//! base URLs come from the brain's `/v1/nodes` (each `NodeInfo.address` is the
//! `host:port` the node heartbeats in).

use std::time::{Duration, SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};
use serde_json::Value;
use tokio::task::JoinSet;

use crate::upstream;

/// Per-node budget for the observe fan-out. One slow node delays the panel by at
/// most this long (the fetches run concurrently), and then reports as an error.
const NODE_OBSERVE_TIMEOUT_SECS: u64 = 3;
/// Budget for a Prometheus / Loki query (in-cluster hops).
const OBSERVABILITY_TIMEOUT_SECS: u64 = 5;
/// Loki line cap per events query; events are further capped after parsing.
const LOKI_QUERY_LIMIT: u32 = 500;
/// Hard cap on parsed events returned to views/API (newest first).
const MAX_EVENTS: usize = 100;

/// Default / maximum lookback for the events panel and API.
pub const EVENTS_DEFAULT_MINUTES: i64 = 30;
pub const EVENTS_MAX_MINUTES: i64 = 1440;

type InsightResult<T> = Result<T, Box<dyn std::error::Error + Send + Sync>>;

fn client(timeout_secs: u64) -> InsightResult<reqwest::Client> {
    Ok(reqwest::Client::builder()
        .timeout(Duration::from_secs(timeout_secs))
        .build()?)
}

pub fn now_ms() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as i64)
        .unwrap_or(0)
}

// ---- Node discovery -----------------------------------------------------------

/// One fiducia-node client-plane base URL to observe.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NodeTarget {
    /// Stable node id when known (brain discovery); otherwise derived from the
    /// URL's host so explicit targets still label their table rows.
    pub node_id: String,
    pub base_url: String,
}

/// Targets from the explicit `FIDUCIA_NODE_URLS` override (comma-separated base
/// URLs). Explicit config wins over brain discovery so an operator can point the
/// dashboard at nodes the brain has not registered (or a local stack).
pub fn explicit_node_targets(urls: &[String]) -> Vec<NodeTarget> {
    urls.iter()
        .map(|url| {
            let base_url = normalize_base_url(url);
            NodeTarget {
                node_id: host_label(&base_url),
                base_url,
            }
        })
        .collect()
}

/// Targets discovered from the brain's `/v1/nodes` membership snapshot: each
/// `NodeInfo` carries the `address` (`host:port`) the node heartbeats in.
/// Entries without an address are skipped (a node that never heartbeated an
/// address has nothing to dial).
pub fn targets_from_brain_nodes(nodes: &[Value]) -> Vec<NodeTarget> {
    nodes
        .iter()
        .filter_map(|node| {
            let address = node.get("address")?.as_str()?.trim();
            if address.is_empty() {
                return None;
            }
            let node_id = node
                .get("node_id")
                .and_then(Value::as_str)
                .unwrap_or(address)
                .to_string();
            Some(NodeTarget {
                node_id,
                base_url: normalize_base_url(address),
            })
        })
        .collect()
}

/// Node addresses arrive as `host:port` from heartbeats or full URLs from env;
/// normalize both to a scheme-qualified base URL without a trailing slash.
fn normalize_base_url(address: &str) -> String {
    let address = address.trim().trim_end_matches('/');
    if address.starts_with("http://") || address.starts_with("https://") {
        address.to_string()
    } else {
        format!("http://{address}")
    }
}

/// A short host-derived label for explicitly configured targets
/// (`http://fiducia-node-0.fiducia-node…:8090` → `fiducia-node-0`).
fn host_label(base_url: &str) -> String {
    let host = base_url
        .trim_start_matches("http://")
        .trim_start_matches("https://");
    let host = host.split([':', '/']).next().unwrap_or(host);
    host.split('.').next().unwrap_or(host).to_string()
}

// ---- Node observe fan-out -------------------------------------------------------

fn default_true() -> bool {
    true
}

/// Node-level quorum rollup from `/v1/observe/shards` (fiducia-node `observe.rs`).
#[derive(Debug, Clone, Default, Deserialize, Serialize)]
pub struct QuorumRollup {
    #[serde(default)]
    pub leaderless_shards: Vec<u32>,
    #[serde(default)]
    pub at_risk_led_shards: Vec<u32>,
    #[serde(default)]
    pub all_led_shards_have_quorum: bool,
    #[serde(default)]
    pub storage_faulted_shards: Vec<u32>,
    #[serde(default)]
    pub unresponsive_shards: Vec<u32>,
    #[serde(default)]
    pub status_complete: bool,
}

/// One follower's replication progress as reported by a shard leader.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct PeerReplication {
    pub peer: String,
    #[serde(default)]
    pub match_index: u64,
    #[serde(default)]
    pub lag: u64,
    #[serde(default)]
    pub in_flight: bool,
}

/// Per-shard latency/lag counters (fiducia-node `ShardMetrics`).
#[derive(Debug, Clone, Default, Deserialize, Serialize)]
pub struct ShardLatency {
    #[serde(default)]
    pub append_rtt_ms_last: Option<u64>,
    #[serde(default)]
    pub quorum_rtt_ms_last: Option<u64>,
    #[serde(default)]
    pub follower_lag_max: u64,
    #[serde(default)]
    pub leader_transfer_count: u64,
}

/// One shard's Raft status as one node sees it (fiducia-node `ShardStatus`).
/// Fields are individually defaulted so a newer/older node payload still renders.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct ShardView {
    pub shard_id: u32,
    #[serde(default)]
    pub role: String,
    #[serde(default)]
    pub term: u64,
    #[serde(default)]
    pub leader_id: Option<String>,
    #[serde(default)]
    pub commit_index: u64,
    #[serde(default)]
    pub last_applied: u64,
    #[serde(default)]
    pub last_log_index: u64,
    #[serde(default = "default_true")]
    pub storage_healthy: bool,
    #[serde(default)]
    pub storage_error: Option<String>,
    #[serde(default)]
    pub healthy_replicas: usize,
    #[serde(default)]
    pub has_quorum: bool,
    #[serde(default)]
    pub replication: Vec<PeerReplication>,
    #[serde(default)]
    pub metrics: ShardLatency,
}

/// The full `/v1/observe/shards` payload from one node.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct NodeShards {
    pub node_id: String,
    #[serde(default)]
    pub shard_count: u32,
    #[serde(default)]
    pub leader_count: usize,
    #[serde(default)]
    pub follower_count: usize,
    #[serde(default)]
    pub quorum: QuorumRollup,
    #[serde(default)]
    pub shards: Vec<ShardView>,
}

/// One node's fan-out outcome. `error` is set (and `shards` is `None`) when the
/// node was unreachable, timed out, or answered non-2xx/garbage — the page and
/// the API surface that per node instead of failing the whole view.
#[derive(Debug, Clone, Serialize)]
pub struct NodeObservation {
    pub node_id: String,
    pub base_url: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub shards: Option<NodeShards>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

/// One node's `/v1/observe/metrics` fan-out outcome (per-op counters).
#[derive(Debug, Clone, Serialize)]
pub struct NodeMetrics {
    pub node_id: String,
    pub base_url: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub operations: Option<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

async fn observe_get(base_url: &str, path: &str) -> InsightResult<Value> {
    let url = format!("{}{}", base_url.trim_end_matches('/'), path);
    let request = upstream::attach_internal(client(NODE_OBSERVE_TIMEOUT_SECS)?.get(url))?;
    Ok(request.send().await?.error_for_status()?.json().await?)
}

/// Fetch `/v1/observe/shards` from every target concurrently. Partial failure is
/// the expected steady state during an incident — exactly when this page matters
/// — so per-node errors become data, not a page error. Results come back in the
/// caller's target order.
pub async fn observe_shards_fanout(targets: &[NodeTarget]) -> Vec<NodeObservation> {
    let mut set = JoinSet::new();
    for (index, target) in targets.iter().cloned().enumerate() {
        set.spawn(async move {
            let outcome = observe_get(&target.base_url, "/v1/observe/shards").await;
            (index, target, outcome)
        });
    }
    let mut observations: Vec<Option<NodeObservation>> = vec![None; targets.len()];
    while let Some(joined) = set.join_next().await {
        let Ok((index, target, outcome)) = joined else {
            continue; // a panicked fetch task reports as a missing slot below
        };
        observations[index] = Some(match outcome {
            Ok(value) => match serde_json::from_value::<NodeShards>(value) {
                Ok(shards) => NodeObservation {
                    node_id: target.node_id,
                    base_url: target.base_url,
                    shards: Some(shards),
                    error: None,
                },
                Err(err) => observation_error(target, format!("unexpected payload: {err}")),
            },
            Err(err) => observation_error(target, err.to_string()),
        });
    }
    observations
        .into_iter()
        .zip(targets)
        .map(|(observation, target)| {
            observation
                .unwrap_or_else(|| observation_error(target.clone(), "fetch task failed".into()))
        })
        .collect()
}

fn observation_error(target: NodeTarget, error: String) -> NodeObservation {
    NodeObservation {
        node_id: target.node_id,
        base_url: target.base_url,
        shards: None,
        error: Some(error),
    }
}

/// Fetch `/v1/observe/metrics` from every target concurrently (same partial-
/// failure contract as [`observe_shards_fanout`]).
pub async fn observe_metrics_fanout(targets: &[NodeTarget]) -> Vec<NodeMetrics> {
    let mut set = JoinSet::new();
    for (index, target) in targets.iter().cloned().enumerate() {
        set.spawn(async move {
            let outcome = observe_get(&target.base_url, "/v1/observe/metrics").await;
            (index, target, outcome)
        });
    }
    let mut results: Vec<Option<NodeMetrics>> = vec![None; targets.len()];
    while let Some(joined) = set.join_next().await {
        let Ok((index, target, outcome)) = joined else {
            continue;
        };
        results[index] = Some(match outcome {
            Ok(value) => NodeMetrics {
                node_id: target.node_id,
                base_url: target.base_url,
                operations: Some(value.get("operations").cloned().unwrap_or(Value::Null)),
                error: None,
            },
            Err(err) => NodeMetrics {
                node_id: target.node_id,
                base_url: target.base_url,
                operations: None,
                error: Some(err.to_string()),
            },
        });
    }
    results
        .into_iter()
        .zip(targets)
        .map(|(result, target)| {
            result.unwrap_or_else(|| NodeMetrics {
                node_id: target.node_id.clone(),
                base_url: target.base_url.clone(),
                operations: None,
                error: Some("fetch task failed".into()),
            })
        })
        .collect()
}

// ---- Shard merge ----------------------------------------------------------------

/// One shard's cluster-wide row, merged across every node's report.
#[derive(Debug, Clone, Serialize)]
pub struct MergedShard {
    pub shard_id: u32,
    /// Which node's view this row adopted.
    pub reported_by: String,
    /// True when `reported_by` leads the shard — the leader's view carries the
    /// authoritative quorum/replication columns.
    pub leader_view: bool,
    #[serde(flatten)]
    pub view: ShardView,
}

/// Merge every node's `/v1/observe/shards` into one row per shard. The leader's
/// view wins (only the leader knows per-peer replication lag and quorum); when
/// no reporting node leads a shard, keep the first follower/candidate view so a
/// leaderless shard still renders with its last-known indices.
pub fn merge_shards(observations: &[NodeObservation]) -> Vec<MergedShard> {
    let mut merged: std::collections::BTreeMap<u32, MergedShard> =
        std::collections::BTreeMap::new();
    for observation in observations {
        let Some(shards) = &observation.shards else {
            continue;
        };
        for view in &shards.shards {
            let leader_view = view.role == "leader";
            let row = || MergedShard {
                shard_id: view.shard_id,
                reported_by: observation.node_id.clone(),
                leader_view,
                view: view.clone(),
            };
            match merged.get(&view.shard_id) {
                Some(existing) if existing.leader_view => {} // leader view already won
                Some(_) if leader_view => {
                    merged.insert(view.shard_id, row());
                }
                Some(_) => {}
                None => {
                    merged.insert(view.shard_id, row());
                }
            }
        }
    }
    merged.into_values().collect()
}

/// Cluster-wide quorum rollup, folded from every node's own rollup plus the
/// merged shard rows. Feeds the summary cards and the overview API.
#[derive(Debug, Clone, Default, Serialize)]
pub struct ClusterQuorum {
    /// Shards for which no reporting node claims leadership.
    pub leaderless: Vec<u32>,
    /// Union of every leader's `at_risk_led_shards` (led, but a majority is not
    /// caught up — one more failure stalls the shard).
    pub at_risk: Vec<u32>,
    /// Union of every node's `storage_faulted_shards`.
    pub storage_faulted: Vec<u32>,
    /// Union of every node's `unresponsive_shards` (wedged local actors).
    pub unresponsive: Vec<u32>,
    pub nodes_reporting: usize,
    pub nodes_failed: usize,
}

pub fn cluster_quorum(observations: &[NodeObservation], merged: &[MergedShard]) -> ClusterQuorum {
    let mut rollup = ClusterQuorum::default();
    let mut at_risk = std::collections::BTreeSet::new();
    let mut storage_faulted = std::collections::BTreeSet::new();
    let mut unresponsive = std::collections::BTreeSet::new();
    for observation in observations {
        match &observation.shards {
            Some(shards) => {
                rollup.nodes_reporting += 1;
                at_risk.extend(shards.quorum.at_risk_led_shards.iter().copied());
                storage_faulted.extend(shards.quorum.storage_faulted_shards.iter().copied());
                unresponsive.extend(shards.quorum.unresponsive_shards.iter().copied());
            }
            None => rollup.nodes_failed += 1,
        }
    }
    rollup.leaderless = merged
        .iter()
        .filter(|shard| !shard.leader_view)
        .map(|shard| shard.shard_id)
        .collect();
    rollup.at_risk = at_risk.into_iter().collect();
    rollup.storage_faulted = storage_faulted.into_iter().collect();
    rollup.unresponsive = unresponsive.into_iter().collect();
    rollup
}

// ---- Prometheus -------------------------------------------------------------------

/// The summary card's Prometheus state: unset URL, query failure, or the number
/// of up scrape targets in the `fiducia` namespace ([`PROM_FIDUCIA_UP_QUERY`]).
#[derive(Debug, Clone, Serialize)]
#[serde(tag = "state", rename_all = "snake_case")]
pub enum PromScrape {
    NotConfigured,
    Error { error: String },
    Up { targets: usize },
}

/// Instant-query URL: `GET /api/v1/query?query=…`.
pub fn prom_instant_query_url(base_url: &str, query: &str) -> String {
    format!(
        "{}/api/v1/query?query={}",
        base_url.trim_end_matches('/'),
        urlencode(query)
    )
}

/// Range-query URL: `GET /api/v1/query_range?query=…&start=…&end=…&step=…`.
/// `start`/`end` are unix seconds, `step` is seconds per point.
pub fn prom_range_query_url(
    base_url: &str,
    query: &str,
    start: i64,
    end: i64,
    step: u32,
) -> String {
    format!(
        "{}/api/v1/query_range?query={}&start={start}&end={end}&step={step}",
        base_url.trim_end_matches('/'),
        urlencode(query)
    )
}

/// The instant query the summary card runs: how many scrape targets Prometheus
/// currently sees up in the `fiducia` namespace. An empty vector renders as
/// "no series" — not an error — since scrape config is deployment-specific.
pub const PROM_FIDUCIA_UP_QUERY: &str = "up{namespace=\"fiducia\"}";

/// Run an instant query and return the `data.result` vector.
pub async fn prom_instant_query(base_url: &str, query: &str) -> InsightResult<Vec<Value>> {
    let value: Value = client(OBSERVABILITY_TIMEOUT_SECS)?
        .get(prom_instant_query_url(base_url, query))
        .send()
        .await?
        .error_for_status()?
        .json()
        .await?;
    prom_result_vector(&value)
}

/// Run a range query and return the `data.result` matrix.
pub async fn prom_range_query(
    base_url: &str,
    query: &str,
    start: i64,
    end: i64,
    step: u32,
) -> InsightResult<Vec<Value>> {
    let value: Value = client(OBSERVABILITY_TIMEOUT_SECS)?
        .get(prom_range_query_url(base_url, query, start, end, step))
        .send()
        .await?
        .error_for_status()?
        .json()
        .await?;
    prom_result_vector(&value)
}

fn prom_result_vector(value: &Value) -> InsightResult<Vec<Value>> {
    value
        .get("data")
        .and_then(|data| data.get("result"))
        .and_then(Value::as_array)
        .cloned()
        .ok_or_else(|| "prometheus response omitted data.result".into())
}

// ---- Loki events -------------------------------------------------------------------

/// The LogQL the events panel runs. Label selector first (`namespace="fiducia"`
/// is how promtail labels the fiducia pods' JSON stdout), then cheap line
/// filters for the raft / brain event families we classify below; the JSON
/// itself is parsed here in Rust (per line), not with LogQL `| json`, so field
/// names with dots (`metric.name`) need no label-mangling games.
pub fn loki_events_logql() -> String {
    "{namespace=\"fiducia\"} |~ \"raft: |membership: |scheduler: |leader_transfer\"".to_string()
}

/// `GET /loki/api/v1/query_range?query=…&start=…&end=…&limit=…` (ns timestamps).
pub fn loki_query_range_url(
    base_url: &str,
    query: &str,
    start_ns: i64,
    end_ns: i64,
    limit: u32,
) -> String {
    format!(
        "{}/loki/api/v1/query_range?query={}&start={start_ns}&end={end_ns}&limit={limit}",
        base_url.trim_end_matches('/'),
        urlencode(query)
    )
}

/// Clamp the caller's `since_minutes` into `[1, EVENTS_MAX_MINUTES]`, defaulting
/// to [`EVENTS_DEFAULT_MINUTES`].
pub fn clamp_since_minutes(requested: Option<i64>) -> i64 {
    requested
        .unwrap_or(EVENTS_DEFAULT_MINUTES)
        .clamp(1, EVENTS_MAX_MINUTES)
}

/// One classified cluster event, extracted from a fiducia pod's JSON log line.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct ClusterEvent {
    /// Event time (ms since epoch, from the Loki entry timestamp).
    pub at_ms: i64,
    /// Stable machine kind (`leader_transfer`, `election_won`, `node_dead`, …).
    pub kind: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub shard: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub node: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub from: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub to: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
    pub message: String,
}

/// Query Loki for recent cluster events and classify them, newest first.
pub async fn recent_cluster_events(
    loki_url: &str,
    since_minutes: i64,
) -> InsightResult<Vec<ClusterEvent>> {
    let end_ns = now_ms().saturating_mul(1_000_000);
    let start_ns = end_ns.saturating_sub(since_minutes.saturating_mul(60_000_000_000));
    let url = loki_query_range_url(
        loki_url,
        &loki_events_logql(),
        start_ns,
        end_ns,
        LOKI_QUERY_LIMIT,
    );
    let body: Value = client(OBSERVABILITY_TIMEOUT_SECS)?
        .get(url)
        .send()
        .await?
        .error_for_status()?
        .json()
        .await?;
    Ok(parse_loki_events(&body))
}

/// Extract + classify events from a Loki `query_range` response body
/// (`data.result[].values[] = [ns_timestamp, log_line]`). Unclassifiable lines
/// are dropped; the result is newest-first and capped at [`MAX_EVENTS`].
pub fn parse_loki_events(body: &Value) -> Vec<ClusterEvent> {
    let mut events = Vec::new();
    let streams = body
        .get("data")
        .and_then(|data| data.get("result"))
        .and_then(Value::as_array);
    for stream in streams.into_iter().flatten() {
        for entry in stream
            .get("values")
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
        {
            let Some(pair) = entry.as_array() else {
                continue;
            };
            let (Some(ts), Some(line)) = (
                pair.first().and_then(Value::as_str),
                pair.get(1).and_then(Value::as_str),
            ) else {
                continue;
            };
            let at_ms = ts.parse::<i64>().map(|ns| ns / 1_000_000).unwrap_or(0);
            if let Some(event) = classify_log_line(at_ms, line) {
                events.push(event);
            }
        }
    }
    events.sort_by_key(|event| std::cmp::Reverse(event.at_ms));
    events.truncate(MAX_EVENTS);
    events
}

/// Classify one JSON log line (fiducia-telemetry's `tracing-subscriber` JSON
/// layer with `flatten_event(true)`: the event's fields — `message`,
/// `metric.name`, `shard`, `node`, `from`, `to`, `reason` — sit at the top
/// level of the object). Recognizes the raft leadership events fiducia-node
/// emits (`consensus.rs`) and the brain's membership/scheduler events.
pub fn classify_log_line(at_ms: i64, line: &str) -> Option<ClusterEvent> {
    let value: Value = serde_json::from_str(line).ok()?;
    let message = value.get("message").and_then(Value::as_str)?.to_string();

    let metric = value.get("metric.name").and_then(Value::as_str);
    let kind = match metric {
        Some("fiducia.raft.leader_transfer") => "leader_transfer",
        Some("fiducia.brain.leader_transfer_intent") => "leader_transfer_intent",
        _ => {
            if message.starts_with("raft: election timeout") {
                "election_started"
            } else if message.starts_with("raft: won election") {
                "election_won"
            } else if message.starts_with("raft: stepped down") {
                "step_down"
            } else if message.starts_with("raft: leader lease lapsed") {
                "check_quorum_step_down"
            } else if message.starts_with("membership: new node registered") {
                "node_registered"
            } else if message.starts_with("membership: node marked Draining") {
                "node_draining"
            } else if message.starts_with("membership: node declared DEAD") {
                "node_dead"
            } else if message.starts_with("scheduler: (re)assigning shard placement") {
                "placement_assigned"
            } else if message.starts_with("scheduler: reconcile applied placement changes") {
                "placement_reconciled"
            } else {
                return None;
            }
        }
    };

    Some(ClusterEvent {
        at_ms,
        kind,
        shard: field_u64(&value, "shard"),
        node: field_string(&value, "node"),
        from: field_string(&value, "from"),
        to: field_string(&value, "to"),
        reason: field_string(&value, "reason"),
        message,
    })
}

/// A field recorded with `?debug` formatting serializes as a string ("3",
/// "\"node-a\""); recorded by value it is a JSON number. Accept both.
fn field_u64(value: &Value, field: &str) -> Option<u64> {
    match value.get(field)? {
        Value::Number(number) => number.as_u64(),
        Value::String(text) => text.trim_matches('"').parse().ok(),
        _ => None,
    }
}

fn field_string(value: &Value, field: &str) -> Option<String> {
    let text = match value.get(field)? {
        Value::String(text) => text.trim_matches('"').to_string(),
        Value::Number(number) => number.to_string(),
        _ => return None,
    };
    if text.is_empty() {
        None
    } else {
        Some(text)
    }
}

// ---- Grafana deep links --------------------------------------------------------------

/// Best-effort Grafana Explore deep link for a Loki query over the same window
/// the panel shows. `datasource: "loki"` is a name hint — Grafana falls back to
/// its default datasource when the name doesn't match.
pub fn grafana_explore_loki_url(grafana_base: &str, logql: &str, since_minutes: i64) -> String {
    let left = serde_json::json!({
        "datasource": "loki",
        "queries": [{ "refId": "A", "expr": logql }],
        "range": { "from": format!("now-{since_minutes}m"), "to": "now" },
    });
    format!(
        "{}/explore?left={}",
        grafana_base.trim_end_matches('/'),
        urlencode(&left.to_string())
    )
}

/// Best-effort Grafana Explore deep link for a PromQL query.
pub fn grafana_explore_prom_url(grafana_base: &str, promql: &str) -> String {
    let left = serde_json::json!({
        "datasource": "prometheus",
        "queries": [{ "refId": "A", "expr": promql }],
        "range": { "from": "now-1h", "to": "now" },
    });
    format!(
        "{}/explore?left={}",
        grafana_base.trim_end_matches('/'),
        urlencode(&left.to_string())
    )
}

/// Minimal percent-encoding for a query-string value (RFC 3986 unreserved set
/// passes through). Local so the crate stays free of a URL-encoding dependency.
fn urlencode(raw: &str) -> String {
    let mut out = String::with_capacity(raw.len() * 3);
    for byte in raw.bytes() {
        match byte {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                out.push(byte as char)
            }
            _ => out.push_str(&format!("%{byte:02X}")),
        }
    }
    out
}

// ---- Timestamps ------------------------------------------------------------------------

/// Human relative age ("2m ago") for the events/nodes tables. The absolute
/// timestamp goes in the `title` attribute via [`utc_timestamp`].
pub fn relative_age(at_ms: i64, now_ms: i64) -> String {
    let delta_s = (now_ms.saturating_sub(at_ms)) / 1000;
    if delta_s < 5 {
        "just now".to_string()
    } else if delta_s < 120 {
        format!("{delta_s}s ago")
    } else if delta_s < 7200 {
        format!("{}m ago", delta_s / 60)
    } else if delta_s < 172_800 {
        format!("{}h ago", delta_s / 3600)
    } else {
        format!("{}d ago", delta_s / 86_400)
    }
}

/// Epoch ms → `YYYY-MM-DD HH:MM:SSZ` (UTC), without pulling in chrono. Uses the
/// standard days-to-civil conversion (Howard Hinnant's `civil_from_days`).
pub fn utc_timestamp(at_ms: i64) -> String {
    let secs = at_ms.div_euclid(1000);
    let days = secs.div_euclid(86_400);
    let tod = secs.rem_euclid(86_400);
    let (hh, mm, ss) = (tod / 3600, (tod % 3600) / 60, tod % 60);

    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let year = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = doy - (153 * mp + 2) / 5 + 1;
    let month = if mp < 10 { mp + 3 } else { mp - 9 };
    let year = if month <= 2 { year + 1 } else { year };

    format!("{year:04}-{month:02}-{day:02} {hh:02}:{mm:02}:{ss:02}Z")
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    // ---- discovery ----

    #[test]
    fn explicit_node_urls_override_and_label_by_host() {
        let targets = explicit_node_targets(&[
            "http://fiducia-node-0.fiducia-node.fiducia.svc.cluster.local:8090/".to_string(),
            "10.2.0.7:8090".to_string(),
        ]);
        assert_eq!(
            targets[0].base_url,
            "http://fiducia-node-0.fiducia-node.fiducia.svc.cluster.local:8090"
        );
        assert_eq!(targets[0].node_id, "fiducia-node-0");
        assert_eq!(targets[1].base_url, "http://10.2.0.7:8090");
    }

    #[test]
    fn brain_nodes_discovery_uses_heartbeat_addresses_and_skips_addressless() {
        let nodes = vec![
            json!({ "node_id": "node-a", "address": "10.0.0.1:8090", "health": "healthy" }),
            json!({ "node_id": "node-b", "address": "", "health": "dead" }),
            json!({ "node_id": "node-c", "address": "https://node-c:8090" }),
        ];
        let targets = targets_from_brain_nodes(&nodes);
        assert_eq!(targets.len(), 2);
        assert_eq!(targets[0].node_id, "node-a");
        assert_eq!(targets[0].base_url, "http://10.0.0.1:8090");
        assert_eq!(targets[1].base_url, "https://node-c:8090");
    }

    // ---- merge ----

    fn shard_view(shard_id: u32, role: &str, term: u64) -> ShardView {
        serde_json::from_value(json!({ "shard_id": shard_id, "role": role, "term": term })).unwrap()
    }

    fn observation(node_id: &str, shards: Vec<ShardView>) -> NodeObservation {
        NodeObservation {
            node_id: node_id.to_string(),
            base_url: format!("http://{node_id}:8090"),
            shards: Some(NodeShards {
                node_id: node_id.to_string(),
                shard_count: 4,
                leader_count: 0,
                follower_count: 0,
                quorum: QuorumRollup::default(),
                shards,
            }),
            error: None,
        }
    }

    #[test]
    fn merge_prefers_the_leaders_view_per_shard_and_tolerates_down_nodes() {
        let follower_first = observation(
            "node-a",
            vec![shard_view(0, "follower", 6), shard_view(1, "leader", 4)],
        );
        let leader_second = observation(
            "node-b",
            vec![shard_view(0, "leader", 7), shard_view(1, "follower", 4)],
        );
        let down = NodeObservation {
            node_id: "node-c".into(),
            base_url: "http://node-c:8090".into(),
            shards: None,
            error: Some("connection refused".into()),
        };

        let merged = merge_shards(&[follower_first, leader_second, down]);
        assert_eq!(merged.len(), 2);
        assert_eq!(merged[0].shard_id, 0);
        assert_eq!(merged[0].reported_by, "node-b", "leader view wins");
        assert!(merged[0].leader_view);
        assert_eq!(merged[0].view.term, 7);
        assert_eq!(merged[1].reported_by, "node-a", "first leader kept");
        assert!(merged[1].leader_view);
    }

    #[test]
    fn merge_keeps_a_follower_view_for_a_leaderless_shard() {
        let merged = merge_shards(&[observation("node-a", vec![shard_view(2, "follower", 9)])]);
        assert_eq!(merged.len(), 1);
        assert!(!merged[0].leader_view);
        assert_eq!(merged[0].reported_by, "node-a");
    }

    #[test]
    fn cluster_quorum_folds_per_node_rollups_and_counts_failures() {
        let mut healthy = observation("node-a", vec![shard_view(0, "leader", 3)]);
        if let Some(shards) = &mut healthy.shards {
            shards.quorum.at_risk_led_shards = vec![0];
            shards.quorum.storage_faulted_shards = vec![2];
            shards.quorum.unresponsive_shards = vec![1];
        }
        let follower_only = observation("node-b", vec![shard_view(1, "follower", 3)]);
        let down = NodeObservation {
            node_id: "node-c".into(),
            base_url: "http://node-c:8090".into(),
            shards: None,
            error: Some("timeout".into()),
        };
        let merged = merge_shards(&[healthy.clone(), follower_only.clone(), down.clone()]);
        let quorum = cluster_quorum(&[healthy, follower_only, down], &merged);
        assert_eq!(quorum.nodes_reporting, 2);
        assert_eq!(quorum.nodes_failed, 1);
        assert_eq!(quorum.leaderless, vec![1], "no node leads shard 1");
        assert_eq!(quorum.at_risk, vec![0]);
        assert_eq!(quorum.storage_faulted, vec![2]);
        assert_eq!(quorum.unresponsive, vec![1]);
    }

    // ---- query construction ----

    #[test]
    fn prometheus_query_urls_are_escaped() {
        let url = prom_instant_query_url("http://prom:9090/", PROM_FIDUCIA_UP_QUERY);
        assert_eq!(
            url,
            "http://prom:9090/api/v1/query?query=up%7Bnamespace%3D%22fiducia%22%7D"
        );
        let range = prom_range_query_url("http://prom:9090", "rate(x[5m])", 100, 200, 15);
        assert!(range.starts_with("http://prom:9090/api/v1/query_range?query=rate%28x%5B5m%5D%29"));
        assert!(range.ends_with("&start=100&end=200&step=15"));
    }

    #[test]
    fn loki_query_range_url_carries_window_and_escaped_logql() {
        let url = loki_query_range_url("http://loki:3100", &loki_events_logql(), 1, 2, 500);
        assert!(url.starts_with(
            "http://loki:3100/loki/api/v1/query_range?query=%7Bnamespace%3D%22fiducia%22%7D"
        ));
        assert!(url.contains("&start=1&end=2&limit=500"));
        // The selector + line-filter families the classifier depends on.
        let logql = loki_events_logql();
        for family in ["raft: ", "membership: ", "scheduler: ", "leader_transfer"] {
            assert!(logql.contains(family), "logql must filter for {family:?}");
        }
    }

    #[test]
    fn since_minutes_is_clamped_with_a_default() {
        assert_eq!(clamp_since_minutes(None), EVENTS_DEFAULT_MINUTES);
        assert_eq!(clamp_since_minutes(Some(0)), 1);
        assert_eq!(clamp_since_minutes(Some(-5)), 1);
        assert_eq!(clamp_since_minutes(Some(90)), 90);
        assert_eq!(clamp_since_minutes(Some(1_000_000)), EVENTS_MAX_MINUTES);
    }

    #[test]
    fn grafana_deep_links_embed_the_query() {
        let loki = grafana_explore_loki_url("/telemetry", "{namespace=\"fiducia\"}", 30);
        assert!(loki.starts_with("/telemetry/explore?left="));
        assert!(loki.contains("now-30m"));
        let prom = grafana_explore_prom_url("https://g.example", PROM_FIDUCIA_UP_QUERY);
        assert!(prom.starts_with("https://g.example/explore?left="));
        assert!(prom.contains("fiducia"));
    }

    // ---- event parsing (captured samples matching fiducia-telemetry's JSON
    // layer: .json().flatten_event(true) puts event fields at the top level) ----

    /// consensus.rs `record_leader_transfer` (fields recorded by value / `?Debug`).
    const LEADER_TRANSFER_LINE: &str = r#"{"timestamp":"2026-07-13T09:58:01.123456Z","level":"INFO","message":"observed raft leadership transition","metric.name":"fiducia.raft.leader_transfer","shard":3,"from":"Follower","to":"Leader","reason":"became_leader","count":2,"target":"fiducia_node::consensus","threadId":"ThreadId(4)","filename":"src/consensus.rs","line_number":1788}"#;
    /// consensus.rs `become_leader` (`shard = ?self.shard_id` → Debug → string).
    const ELECTION_WON_LINE: &str = r#"{"timestamp":"2026-07-13T09:58:01.100000Z","level":"INFO","message":"raft: won election — now leader for shard","shard":"3","node":"node-b","term":7,"votes":2,"members":3,"target":"fiducia_node::consensus","threadId":"ThreadId(4)","filename":"src/consensus.rs","line_number":1105}"#;
    const CHECK_QUORUM_LINE: &str = r#"{"timestamp":"2026-07-13T09:57:40.000000Z","level":"WARN","message":"raft: leader lease lapsed (no majority contact within an election timeout) — stepping down to avoid split-brain / stale reads (check-quorum)","shard":"3","node":"node-a","term":6,"target":"fiducia_node::consensus"}"#;
    /// brain membership.rs sweep.
    const NODE_DEAD_LINE: &str = r#"{"timestamp":"2026-07-13T09:57:00.000000Z","level":"WARN","message":"membership: node declared DEAD (missed heartbeats) — its shards will be re-placed","node":"node-a","domain":"gcp/europe-west1","silent_for_ms":31000,"hosted_shards":5,"leading_shards":2,"target":"fiducia_brain::membership"}"#;
    /// brain scheduler.rs reassignment (`replicas = ?…` Debug strings).
    const PLACEMENT_LINE: &str = r#"{"timestamp":"2026-07-13T09:57:05.000000Z","level":"INFO","message":"scheduler: (re)assigning shard placement","shard":3,"replicas":"[\"node-b\", \"node-c\", \"node-d\"]","preferred_leader":"Some(\"node-b\")","target":"fiducia_brain::scheduler"}"#;
    const UNRELATED_LINE: &str = r#"{"timestamp":"2026-07-13T09:57:06.000000Z","level":"INFO","message":"fiducia-node listening on http://0.0.0.0:8090","target":"fiducia_node"}"#;

    #[test]
    fn classifies_raft_and_brain_events_from_captured_json_lines() {
        let transfer = classify_log_line(1_000, LEADER_TRANSFER_LINE).unwrap();
        assert_eq!(transfer.kind, "leader_transfer");
        assert_eq!(transfer.shard, Some(3));
        assert_eq!(transfer.from.as_deref(), Some("Follower"));
        assert_eq!(transfer.to.as_deref(), Some("Leader"));
        assert_eq!(transfer.reason.as_deref(), Some("became_leader"));

        let won = classify_log_line(1_000, ELECTION_WON_LINE).unwrap();
        assert_eq!(won.kind, "election_won");
        assert_eq!(won.shard, Some(3), "debug-formatted shard string parses");
        assert_eq!(won.node.as_deref(), Some("node-b"));

        let lease = classify_log_line(1_000, CHECK_QUORUM_LINE).unwrap();
        assert_eq!(lease.kind, "check_quorum_step_down");

        let dead = classify_log_line(1_000, NODE_DEAD_LINE).unwrap();
        assert_eq!(dead.kind, "node_dead");
        assert_eq!(dead.node.as_deref(), Some("node-a"));

        let placed = classify_log_line(1_000, PLACEMENT_LINE).unwrap();
        assert_eq!(placed.kind, "placement_assigned");
        assert_eq!(placed.shard, Some(3));

        assert!(classify_log_line(1_000, UNRELATED_LINE).is_none());
        assert!(classify_log_line(1_000, "not json at all").is_none());
    }

    #[test]
    fn parses_a_loki_query_range_body_newest_first() {
        let body = json!({
            "status": "success",
            "data": {
                "resultType": "streams",
                "result": [
                    {
                        "stream": { "namespace": "fiducia", "pod": "fiducia-node-1" },
                        "values": [
                            ["1752400681123456789", LEADER_TRANSFER_LINE],
                            ["1752400660000000000", CHECK_QUORUM_LINE],
                            ["1752400666000000000", UNRELATED_LINE]
                        ]
                    },
                    {
                        "stream": { "namespace": "fiducia", "pod": "fiducia-brain-0" },
                        "values": [["1752400620000000000", NODE_DEAD_LINE]]
                    }
                ]
            }
        });
        let events = parse_loki_events(&body);
        assert_eq!(events.len(), 3, "unrelated lines are dropped");
        assert_eq!(events[0].kind, "leader_transfer");
        assert_eq!(events[0].at_ms, 1_752_400_681_123);
        assert_eq!(events[1].kind, "check_quorum_step_down");
        assert_eq!(events[2].kind, "node_dead");
        assert!(events.windows(2).all(|w| w[0].at_ms >= w[1].at_ms));
    }

    // ---- timestamps ----

    #[test]
    fn relative_and_absolute_timestamps() {
        let now = 1_752_400_681_123; // 2025-07-13T09:58:01.123Z
        assert_eq!(relative_age(now - 2_000, now), "just now");
        assert_eq!(relative_age(now - 45_000, now), "45s ago");
        assert_eq!(relative_age(now - 150_000, now), "2m ago");
        assert_eq!(relative_age(now - 3 * 3_600_000, now), "3h ago");
        assert_eq!(relative_age(now - 3 * 86_400_000, now), "3d ago");
        assert_eq!(utc_timestamp(now), "2025-07-13 09:58:01Z");
        assert_eq!(utc_timestamp(0), "1970-01-01 00:00:00Z");
        assert_eq!(utc_timestamp(951_868_800_000), "2000-03-01 00:00:00Z");
    }
}
