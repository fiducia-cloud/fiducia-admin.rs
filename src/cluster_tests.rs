//! Cluster-insight view and upstream aggregation tests. Extracted verbatim from main.rs;
//! `use super::*` resolves to the crate root exactly as when inline.

use super::auth_flow_tests::spawn_mock;
use super::*;
use axum::body::Body;
use axum::http::Request;
use tower::ServiceExt;

fn cluster_router(state: Arc<AppState>) -> Router {
    Router::new()
        .route("/cluster", get(cluster_page))
        .route("/cluster/shards", get(cluster_shards_fragment))
        .route("/cluster/nodes", get(cluster_nodes_fragment))
        .route("/cluster/events", get(cluster_events_fragment))
        .route("/api/admin/cluster/overview", get(cluster_overview_api))
        .route("/api/admin/cluster/shards", get(cluster_shards_api))
        .route("/api/admin/cluster/events", get(cluster_events_api))
        .route("/api/admin/cluster/metrics", get(cluster_metrics_api))
        .with_state(state)
}

async fn get_with(router: Router, uri: &str, bearer: Option<&str>, htmx: bool) -> Response {
    let mut builder = Request::builder()
        .uri(uri)
        .header("host", "admin.fiducia.cloud");
    if let Some(token) = bearer {
        builder = builder.header("authorization", format!("Bearer {token}"));
    }
    if htmx {
        builder = builder.header("hx-request", "true");
    }
    router
        .oneshot(builder.body(Body::empty()).unwrap())
        .await
        .unwrap()
}

async fn body_json(response: Response) -> Value {
    let bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();
    serde_json::from_slice(&bytes).unwrap()
}

async fn body_text(response: Response) -> String {
    let bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();
    String::from_utf8_lossy(&bytes).into_owned()
}

/// A test AppState with the Cluster Insight upstreams under test control.
fn insight_state(
    auth_url: String,
    brain_url: String,
    prometheus_url: Option<String>,
    loki_url: Option<String>,
    grafana_public_url: Option<String>,
    node_urls: Vec<String>,
) -> Arc<AppState> {
    Arc::new(AppState {
        auth_url,
        brain_url,
        supabase_url: "https://example.supabase.co".into(),
        supabase_publishable_key: "test-publishable-key".into(),
        db: None,
        stream_tx: broadcast::channel(16).0,
        request_security: test_request_security(),
        prometheus_url,
        loki_url,
        grafana_public_url,
        node_urls,
    })
}

#[tokio::test]
async fn audit_routes_require_an_operator_session_before_database_access() {
    let app = Router::new()
        .route("/audit", get(audit_page))
        .route("/api/admin/audit", get(audit_api))
        .with_state(sync_tests::test_state());

    let page = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/audit")
                .header("host", "admin.fiducia.cloud")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(page.status(), StatusCode::SEE_OTHER);

    let api = app
        .oneshot(
            Request::builder()
                .uri("/api/admin/audit")
                .header("host", "admin.fiducia.cloud")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(api.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn every_cluster_route_requires_a_session() {
    // Anonymous HTML routes redirect to the login page…
    for uri in [
        "/cluster",
        "/cluster/shards",
        "/cluster/nodes",
        "/cluster/events",
    ] {
        let response = get_with(cluster_router(sync_tests::test_state()), uri, None, false).await;
        assert_eq!(response.status(), StatusCode::SEE_OTHER, "uri={uri}");
        assert_eq!(
            response
                .headers()
                .get(LOCATION)
                .and_then(|v| v.to_str().ok()),
            Some("/login"),
            "uri={uri}"
        );
    }
    // …and anonymous API routes get a machine-readable 401.
    for uri in [
        "/api/admin/cluster/overview",
        "/api/admin/cluster/shards",
        "/api/admin/cluster/events",
        "/api/admin/cluster/metrics",
    ] {
        let response = get_with(cluster_router(sync_tests::test_state()), uri, None, false).await;
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED, "uri={uri}");
    }
}

#[tokio::test]
async fn cluster_routes_reject_a_verified_non_operator_session() {
    // fiducia-auth verifies the token but reports no operator role.
    let auth = Router::new().route(
        "/v1/me",
        get(|| async {
            Json(json!({
                "user": {
                    "user_id": "00000000-0000-0000-0000-000000000002",
                    "email": "customer@example.com",
                    "roles": ["customer"]
                }
            }))
        }),
    );
    let (auth_url, auth_task) = spawn_mock(auth).await;
    let state = insight_state(
        auth_url,
        "http://localhost:8095".into(),
        None,
        None,
        None,
        Vec::new(),
    );

    let page = get_with(
        cluster_router(state.clone()),
        "/cluster",
        Some("verified.jwt"),
        false,
    )
    .await;
    assert_eq!(page.status(), StatusCode::FORBIDDEN);

    let api = get_with(
        cluster_router(state),
        "/api/admin/cluster/overview",
        Some("verified.jwt"),
        false,
    )
    .await;
    assert_eq!(api.status(), StatusCode::FORBIDDEN);
    assert_eq!(body_json(api).await["error"], "forbidden");

    auth_task.abort();
}

const TEST_INTERNAL_SECRET: &str = "test-internal-secret";

/// Trusted-hop check for the node mocks: the fan-out must present the same
/// `x-fiducia-internal-auth` secret the real node plane enforces.
fn internal_auth_ok(headers: &HeaderMap) -> bool {
    headers
        .get("x-fiducia-internal-auth")
        .and_then(|value| value.to_str().ok())
        == Some(TEST_INTERNAL_SECRET)
}

async fn healthy_node_shards(headers: HeaderMap) -> Response {
    if !internal_auth_ok(&headers) {
        return (
            StatusCode::UNAUTHORIZED,
            Json(json!({ "error": "internal_auth" })),
        )
            .into_response();
    }
    Json(json!({
        "node_id": "node-ok",
        "shard_count": 2,
        "leader_count": 1,
        "follower_count": 1,
        "quorum": {
            "leaderless_shards": [],
            "at_risk_led_shards": [],
            "all_led_shards_have_quorum": true,
            "storage_faulted_shards": [],
            "unresponsive_shards": [],
            "status_complete": true,
            "all_shard_storage_healthy": true
        },
        "shards": [
            {
                "shard_id": 0, "role": "leader", "term": 3, "leader_id": "node-ok",
                "commit_index": 42, "last_applied": 42, "last_log_index": 42,
                "snapshot_index": 0, "retained_log_entries": 42,
                "storage_healthy": true, "healthy_replicas": 3, "has_quorum": true,
                "replication": [
                    { "peer": "node-down", "match_index": 42, "lag": 0, "in_flight": false }
                ],
                "metrics": {
                    "append_rtt_ms_last": 2, "quorum_rtt_ms_last": 3,
                    "follower_lag_max": 0, "leader_transfer_count": 1
                }
            },
            {
                "shard_id": 1, "role": "follower", "term": 3, "leader_id": "node-down",
                "commit_index": 10, "last_applied": 10, "last_log_index": 10,
                "snapshot_index": 0, "retained_log_entries": 10,
                "storage_healthy": true, "healthy_replicas": 0, "has_quorum": false,
                "metrics": { "follower_lag_max": 0, "leader_transfer_count": 0 }
            }
        ]
    }))
    .into_response()
}

async fn healthy_node_metrics(headers: HeaderMap) -> Response {
    if !internal_auth_ok(&headers) {
        return (
            StatusCode::UNAUTHORIZED,
            Json(json!({ "error": "internal_auth" })),
        )
            .into_response();
    }
    Json(json!({
        "operations": [{
            "op": "kv.put", "count": 12, "errors": 1, "avg_ms": 2.5, "max_ms": 20.0,
            "buckets": [
                { "le_ms": 1.0, "count": 4 }, { "le_ms": 5.0, "count": 10 },
                { "le_ms": 25.0, "count": 12 }, { "le_ms": 100.0, "count": 12 },
                { "le_ms": 500.0, "count": 12 }, { "le_ms": 2000.0, "count": 12 },
                { "le_ms": null, "count": 12 }
            ]
        }]
    }))
    .into_response()
}

/// A captured fiducia-node JSON log line (tracing JSON layer, flattened
/// event fields) as promtail ships it to Loki.
const LOKI_TRANSFER_LINE: &str = r#"{"timestamp":"2025-07-13T09:58:01.123456Z","level":"INFO","message":"observed raft leadership transition","metric.name":"fiducia.raft.leader_transfer","shard":0,"from":"Follower","to":"Leader","reason":"became_leader","count":1,"target":"fiducia_node::consensus"}"#;

/// The full read path: mocked fiducia-auth (verified operator), fiducia-brain
/// (status + membership with dialable node addresses), one healthy node, one
/// node answering 500, Loki, and Prometheus. The overview must merge what is
/// reachable and carry the down node as a per-node error — never a 5xx.
#[tokio::test]
async fn overview_merges_all_planes_and_tolerates_a_down_node() {
    // The upstream client reads the trusted-hop secret once (OnceLock); the
    // node mocks below verify the fan-out actually presents it.
    std::env::set_var("FIDUCIA_INTERNAL_SECRET", TEST_INTERNAL_SECRET);

    let auth = Router::new().route(
        "/v1/me",
        get(|| async {
            // `dev-admin` exercises the debug-build registry shortcut, so this
            // test (db: None) covers the full handler path after auth.
            Json(json!({
                "user": { "user_id": "dev-admin", "email": "op@example.com", "roles": ["admin"] }
            }))
        }),
    );
    let (auth_url, auth_task) = spawn_mock(auth).await;

    let node_ok = Router::new()
        .route("/v1/observe/shards", get(healthy_node_shards))
        .route("/v1/observe/metrics", get(healthy_node_metrics));
    let (node_ok_url, node_ok_task) = spawn_mock(node_ok).await;

    let node_down = Router::new()
        .route(
            "/v1/observe/shards",
            get(|| async { StatusCode::INTERNAL_SERVER_ERROR }),
        )
        .route(
            "/v1/observe/metrics",
            get(|| async { StatusCode::INTERNAL_SERVER_ERROR }),
        );
    let (node_down_url, node_down_task) = spawn_mock(node_down).await;

    // The brain reports both nodes with the mock servers' real addresses, so
    // discovery (no FIDUCIA_NODE_URLS) dials them.
    let ok_address = node_ok_url.trim_start_matches("http://").to_string();
    let down_address = node_down_url.trim_start_matches("http://").to_string();
    let brain = Router::new()
            .route(
                "/v1/config",
                get(|| async {
                    Json(json!({
                        "cluster_id": "fiducia-test", "shard_count": 2, "replication_factor": 3
                    }))
                }),
            )
            .route(
                "/v1/policies",
                get(|| async {
                    Json(json!({ "policies": [{ "namespace": "orders", "home_region": "eu" }] }))
                }),
            )
            .route(
                "/v1/status",
                get(|| async {
                    Json(json!({
                        "service": "fiducia-brain", "version": "0.1.0",
                        "cluster_id": "fiducia-test", "nodes": 2,
                        "shard_count": 2, "replication_factor": 3,
                        "ready": false,
                        "topology": { "nodes_by_health": { "healthy": 1, "suspect": 1 } },
                        "placement": {
                            "placed_shards": 2, "unplaced_shards": 0,
                            "under_replicated_shards": 0, "leaderless_shards": 0,
                            "shards_with_unhealthy_replicas": 1
                        },
                        "brain_cluster": {
                            "placement_generation": 7, "is_leader": true, "leader": null,
                            "available": true, "ha_configured": false
                        }
                    }))
                }),
            )
            .route(
                "/v1/nodes",
                get(move || {
                    let ok_address = ok_address.clone();
                    let down_address = down_address.clone();
                    async move {
                    Json(json!({
                        "nodes": [
                            {
                                "node_id": "node-ok", "address": ok_address, "health": "healthy",
                                "failure_domain": "gcp/europe-west1", "last_seen_ms": 1_752_400_000_000i64,
                                "hosted_shards": [0, 1], "leading_shards": [0]
                            },
                            {
                                "node_id": "node-down", "address": down_address, "health": "suspect",
                                "failure_domain": "aws/eu-central-1", "last_seen_ms": 1_752_399_000_000i64,
                                "hosted_shards": [0, 1], "leading_shards": [1]
                            }
                        ]
                    }))
                    }
                }),
            );
    let (brain_url, brain_task) = spawn_mock(brain).await;

    let loki = Router::new().route(
        "/loki/api/v1/query_range",
        get(|| async {
            Json(json!({
                "status": "success",
                "data": {
                    "resultType": "streams",
                    "result": [{
                        "stream": { "namespace": "fiducia", "pod": "fiducia-node-0" },
                        "values": [["1752400681123456789", LOKI_TRANSFER_LINE]]
                    }]
                }
            }))
        }),
    );
    let (loki_url, loki_task) = spawn_mock(loki).await;

    let prometheus = Router::new()
        .route(
            "/api/v1/query",
            get(|| async {
                Json(json!({
                    "status": "success",
                    "data": {
                        "resultType": "vector",
                        "result": [
                            { "metric": { "pod": "fiducia-node-0" }, "value": [1752400681.0, "1"] },
                            { "metric": { "pod": "fiducia-node-1" }, "value": [1752400681.0, "1"] },
                            { "metric": { "pod": "fiducia-brain-0" }, "value": [1752400681.0, "0"] }
                        ]
                    }
                }))
            }),
        )
        .route(
            "/api/v1/query_range",
            get(|| async {
                Json(json!({
                    "status": "success",
                    "data": {
                        "resultType": "matrix",
                        "result": [{
                            "metric": { "pod": "fiducia-node-0" },
                            "values": [[1752400621.0, "1"], [1752400681.0, "1"]]
                        }]
                    }
                }))
            }),
        );
    let (prometheus_url, prometheus_task) = spawn_mock(prometheus).await;

    let state = insight_state(
        auth_url,
        brain_url,
        Some(prometheus_url),
        Some(loki_url),
        Some("/telemetry".into()),
        Vec::new(), // discovery path: node URLs come from brain /v1/nodes
    );

    // -- JSON overview: merged shards, per-node outcomes, quorum rollup ----
    let overview = get_with(
        cluster_router(state.clone()),
        "/api/admin/cluster/overview",
        Some("verified.jwt"),
        false,
    )
    .await;
    assert_eq!(overview.status(), StatusCode::OK);
    let overview = body_json(overview).await;
    assert_eq!(overview["cluster"]["cluster_id"], "fiducia-test");
    assert_eq!(overview["config"]["shard_count"], 2);
    assert_eq!(overview["policies"][0]["namespace"], "orders");
    let shards = overview["shards"].as_array().unwrap();
    assert_eq!(shards.len(), 2, "both shards merged from the healthy node");
    assert_eq!(shards[0]["shard_id"], 0);
    assert_eq!(shards[0]["reported_by"], "node-ok");
    assert_eq!(shards[0]["leader_view"], true);
    assert_eq!(shards[0]["replication"][0]["peer"], "node-down");
    assert_eq!(shards[1]["leader_view"], false, "leader is the down node");
    let observations = overview["node_observations"].as_array().unwrap();
    assert_eq!(observations.len(), 2);
    assert!(observations[0]["error"].is_null());
    assert!(
        observations[1]["error"].as_str().unwrap().contains("500"),
        "the down node is an error entry, not a page failure"
    );
    assert_eq!(overview["quorum"]["nodes_reporting"], 1);
    assert_eq!(overview["quorum"]["nodes_failed"], 1);
    // Shard 1's leader is the *down* node: its follower row still knows a
    // leader_id, so it is "leader unreached", never miscounted as leaderless
    // during a partial-visibility incident (M5).
    assert_eq!(overview["quorum"]["leaderless"], json!([]));
    assert_eq!(overview["quorum"]["leader_unreached"], json!([1]));
    assert_eq!(overview["prometheus"]["state"], "up");
    assert_eq!(
        overview["prometheus"]["targets"], 2,
        "only value==\"1\" counts"
    );

    // -- events API: clamped window + classified Loki lines ---------------
    let events = get_with(
        cluster_router(state.clone()),
        "/api/admin/cluster/events?since_minutes=999999",
        Some("verified.jwt"),
        false,
    )
    .await;
    assert_eq!(events.status(), StatusCode::OK);
    let events = body_json(events).await;
    assert_eq!(events["configured"], true);
    assert_eq!(events["since_minutes"], 1440, "clamped to the max window");
    assert_eq!(events["events"][0]["kind"], "leader_transfer");
    assert_eq!(events["events"][0]["shard"], 0);

    // -- metrics API: per-op fan-out with the down node carried as error ---
    let metrics = get_with(
        cluster_router(state.clone()),
        "/api/admin/cluster/metrics",
        Some("verified.jwt"),
        false,
    )
    .await;
    assert_eq!(metrics.status(), StatusCode::OK);
    let metrics = body_json(metrics).await;
    let nodes = metrics["nodes"].as_array().unwrap();
    assert_eq!(nodes.len(), 2);
    assert_eq!(nodes[0]["operations"][0]["op"], "kv.put");
    assert!(nodes[1]["error"].as_str().is_some());
    assert_eq!(
        metrics["prometheus_up_range"][0]["metric"]["pod"],
        "fiducia-node-0"
    );

    // -- full HTML page + htmx fragment ------------------------------------
    let page = get_with(
        cluster_router(state.clone()),
        "/cluster",
        Some("verified.jwt"),
        false,
    )
    .await;
    assert_eq!(page.status(), StatusCode::OK);
    let html = body_text(page).await;
    assert!(html.contains("Cluster insight"));
    assert!(html.contains("node-ok"));
    assert!(html.contains("unreachable"), "down node badge renders");
    assert!(html.contains("leader_transfer"), "Loki event renders");
    assert!(
        html.contains("/telemetry/explore?left="),
        "Grafana deep link"
    );

    let fragment = get_with(
        cluster_router(state),
        "/cluster/shards",
        Some("verified.jwt"),
        true,
    )
    .await;
    assert_eq!(fragment.status(), StatusCode::OK);
    let fragment = body_text(fragment).await;
    assert!(fragment.contains("shard-table"));
    assert!(!fragment.contains("<!DOCTYPE"), "fragment, not a full page");

    for task in [
        auth_task,
        brain_task,
        node_ok_task,
        node_down_task,
        loki_task,
        prometheus_task,
    ] {
        task.abort();
    }
}

/// Loki unset is a rendered state, not an error: the API says so and the
/// panel explains which variable enables it.
#[tokio::test]
async fn unconfigured_observability_renders_as_not_configured() {
    std::env::set_var("FIDUCIA_INTERNAL_SECRET", TEST_INTERNAL_SECRET);
    let auth = Router::new().route(
        "/v1/me",
        get(|| async {
            Json(json!({
                "user": { "user_id": "dev-admin", "email": "op@example.com", "roles": ["admin"] }
            }))
        }),
    );
    let (auth_url, auth_task) = spawn_mock(auth).await;
    let state = insight_state(
        auth_url,
        "http://localhost:8095".into(),
        None,
        None,
        None,
        Vec::new(),
    );

    let events = get_with(
        cluster_router(state.clone()),
        "/api/admin/cluster/events",
        Some("verified.jwt"),
        false,
    )
    .await;
    assert_eq!(events.status(), StatusCode::OK);
    let events = body_json(events).await;
    assert_eq!(events["configured"], false);
    assert_eq!(events["since_minutes"], 30);
    assert_eq!(events["events"], json!([]));

    let fragment = get_with(
        cluster_router(state),
        "/cluster/events",
        Some("verified.jwt"),
        true,
    )
    .await;
    assert_eq!(fragment.status(), StatusCode::OK);
    let html = body_text(fragment).await;
    assert!(html.contains("FIDUCIA_LOKI_URL"));

    auth_task.abort();
}

/// H1: the fan-out must (a) refuse a brain-supplied address that is not
/// in-cluster — never dialing it with the cluster secret — and (b) never
/// follow a redirect, so a trusted node that answers a cross-origin 302 can't
/// bounce the secret to an attacker's `Location`.
#[tokio::test]
async fn node_fanout_refuses_untrusted_addresses_and_never_follows_redirects() {
    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

    std::env::set_var("FIDUCIA_INTERNAL_SECRET", TEST_INTERNAL_SECRET);
    let auth = Router::new().route(
        "/v1/me",
        get(|| async {
            Json(json!({
                "user": { "user_id": "dev-admin", "email": "op@example.com", "roles": ["admin"] }
            }))
        }),
    );
    let (auth_url, auth_task) = spawn_mock(auth).await;

    // A capture server standing in for the attacker's redirect target. It
    // records any hit and whether the cluster secret rode along.
    let hits = Arc::new(AtomicUsize::new(0));
    let leaked = Arc::new(AtomicBool::new(false));
    let hits_handler = hits.clone();
    let leaked_handler = leaked.clone();
    let capture = Router::new().route(
        "/leak",
        get(move |headers: HeaderMap| {
            let hits_handler = hits_handler.clone();
            let leaked_handler = leaked_handler.clone();
            async move {
                hits_handler.fetch_add(1, Ordering::SeqCst);
                if headers
                    .get("x-fiducia-internal-auth")
                    .and_then(|value| value.to_str().ok())
                    == Some(TEST_INTERNAL_SECRET)
                {
                    leaked_handler.store(true, Ordering::SeqCst);
                }
                StatusCode::OK
            }
        }),
    );
    let (capture_url, capture_task) = spawn_mock(capture).await;

    // A trusted (loopback) node that answers observe with a cross-origin 302
    // pointing at the capture server.
    let leak_location = format!("{capture_url}/leak");
    let redirect_node = Router::new().route(
        "/v1/observe/shards",
        get(move || {
            let leak_location = leak_location.clone();
            async move { (StatusCode::FOUND, [(LOCATION, leak_location)]).into_response() }
        }),
    );
    let (redirect_url, redirect_task) = spawn_mock(redirect_node).await;
    let redirect_address = redirect_url.trim_start_matches("http://").to_string();

    let brain = Router::new()
            .route(
                "/v1/status",
                get(|| async {
                    Json(json!({
                        "service": "fiducia-brain", "version": "0.1.0",
                        "cluster_id": "fiducia-test", "shard_count": 0, "replication_factor": 3
                    }))
                }),
            )
            .route(
                "/v1/nodes",
                get(move || {
                    let redirect_address = redirect_address.clone();
                    async move {
                        Json(json!({
                            "nodes": [
                                // Not loopback, not in-cluster: must be refused pre-request.
                                { "node_id": "evil", "address": "attacker.example.com:8090", "health": "healthy" },
                                // Loopback (trusted) but answers with a redirect.
                                { "node_id": "redir", "address": redirect_address, "health": "healthy" }
                            ]
                        }))
                    }
                }),
            );
    let (brain_url, brain_task) = spawn_mock(brain).await;

    let state = insight_state(auth_url, brain_url, None, None, None, Vec::new());
    let response = get_with(
        cluster_router(state),
        "/api/admin/cluster/shards",
        Some("verified.jwt"),
        false,
    )
    .await;
    assert_eq!(response.status(), StatusCode::OK, "never a page failure");
    let body = body_json(response).await;
    let observations = body["node_observations"].as_array().unwrap();
    assert_eq!(observations.len(), 2);

    let evil = observations
        .iter()
        .find(|o| o["node_id"] == "evil")
        .unwrap();
    assert_eq!(
        evil["error"], "untrusted address",
        "the out-of-cluster address is a distinct refused state"
    );
    assert_eq!(evil["untrusted"], true);

    let redir = observations
        .iter()
        .find(|o| o["node_id"] == "redir")
        .unwrap();
    assert!(
        redir["error"].as_str().unwrap().contains("302"),
        "the 302 surfaces as an error, not followed: got {:?}",
        redir["error"]
    );

    assert_eq!(
        hits.load(Ordering::SeqCst),
        0,
        "the redirect was never followed"
    );
    assert!(
        !leaked.load(Ordering::SeqCst),
        "the cluster secret never reached the redirect target"
    );

    for task in [auth_task, brain_task, redirect_task, capture_task] {
        task.abort();
    }
}

/// M2: an upstream body past the cap is an error observation, not an OOM or a
/// panic — the fan-out reads with a running byte counter and aborts.
#[tokio::test]
async fn oversized_upstream_body_is_an_error_not_an_oom() {
    std::env::set_var("FIDUCIA_INTERNAL_SECRET", TEST_INTERNAL_SECRET);
    // Larger than upstream::MAX_UPSTREAM_BODY_BYTES (16 MiB).
    let oversized = "x".repeat(17 * 1024 * 1024);
    let node = Router::new().route(
        "/v1/observe/shards",
        get(move || {
            let oversized = oversized.clone();
            async move { oversized }
        }),
    );
    let (node_url, node_task) = spawn_mock(node).await;

    let targets = vec![cluster_insight::NodeTarget {
        node_id: "big".into(),
        base_url: node_url,
        trusted: true,
    }];
    let observations = cluster_insight::observe_shards_fanout(&targets).await;
    assert_eq!(observations.len(), 1);
    assert!(observations[0].shards.is_none());
    assert_eq!(
        observations[0].error.as_deref(),
        Some("oversized response"),
        "the body cap is enforced as bytes arrive"
    );

    node_task.abort();
}
