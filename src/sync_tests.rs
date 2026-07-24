//! Sync write/catch-up + idempotency HTTP tests. Extracted verbatim from main.rs;
//! `use super::*` resolves to the crate root exactly as when inline.

use super::*;
use axum::body::Body;
use axum::http::Request;
use tower::ServiceExt;

pub(super) fn test_state() -> Arc<AppState> {
    Arc::new(AppState {
        auth_url: "http://localhost:8097".into(),
        brain_url: "http://localhost:8095".into(),
        supabase_url: "https://example.supabase.co".into(),
        supabase_publishable_key: "test-publishable-key".into(),
        db: None,
        stream_tx: broadcast::channel(16).0,
        request_security: test_request_security(),
        prometheus_url: None,
        loki_url: None,
        grafana_public_url: None,
        node_urls: Vec::new(),
    })
}

async fn post_sync(
    state: Arc<AppState>,
    table: &str,
    key: Option<&str>,
) -> axum::response::Response {
    let app = Router::new()
        .route("/api/admin/sync/:table", post(sync_write))
        .with_state(state);
    let mut builder = Request::builder()
        .method("POST")
        .uri(format!("/api/admin/sync/{table}"))
        .header(CONTENT_TYPE, "application/json");
    if let Some(k) = key {
        builder = builder.header("idempotency-key", k);
    }
    let body = json!({ "id": "op1", "op": "upsert" }).to_string();
    app.oneshot(builder.body(Body::from(body)).unwrap())
        .await
        .unwrap()
}

#[tokio::test]
async fn sync_write_requires_an_operator_session_before_table_or_database_access() {
    let response = post_sync(test_state(), "infra_operations", None).await;
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);

    let unsupported = post_sync(test_state(), "operators", None).await;
    assert_eq!(unsupported.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn serves_the_vendored_sync_bundle() {
    let app = Router::new().route("/assets/fiducia-sync.js", get(sync_js));
    let resp = app
        .oneshot(
            Request::builder()
                .uri("/assets/fiducia-sync.js")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let ct = resp
        .headers()
        .get(CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    assert!(ct.contains("javascript"), "ct={ct}");
    let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX)
        .await
        .unwrap();
    assert!(String::from_utf8_lossy(&bytes).contains("FiduciaSyncAdmin"));
}

#[test]
fn durable_write_key_must_match_header_and_body() {
    let request = SyncWriteRequest {
        id: "op1".into(),
        op: Some("upsert".into()),
        payload: None,
        base_version: Some(7),
        key: Some("write-key-1".into()),
    };
    let mut headers = HeaderMap::new();
    headers.insert("idempotency-key", HeaderValue::from_static("write-key-1"));
    assert_eq!(
        validated_write_key(&headers, &request).unwrap(),
        "write-key-1"
    );

    headers.insert("idempotency-key", HeaderValue::from_static("write-key-2"));
    assert!(validated_write_key(&headers, &request).is_err());

    headers.append("idempotency-key", HeaderValue::from_static("write-key-1"));
    assert_eq!(
        validated_write_key(&headers, &request),
        Err(WriteKeyError::Invalid)
    );

    let invalid_body = SyncWriteRequest {
        key: Some("not a header-safe key".into()),
        ..request
    };
    assert_eq!(
        validated_write_key(&HeaderMap::new(), &invalid_body),
        Err(WriteKeyError::Invalid)
    );
}

#[test]
fn every_mutation_requires_a_nonempty_key_but_body_only_is_accepted() {
    let mut request = SyncWriteRequest {
        id: "op1".into(),
        op: Some("upsert".into()),
        payload: None,
        base_version: Some(7),
        key: None,
    };
    assert_eq!(
        validated_write_key(&HeaderMap::new(), &request),
        Err(WriteKeyError::Missing)
    );

    request.key = Some("body-only-key".into());
    assert_eq!(
        validated_write_key(&HeaderMap::new(), &request).unwrap(),
        "body-only-key"
    );
}

#[test]
fn catchup_page_advances_only_through_returned_global_sequences() {
    let change = |sequence| SyncCatchupChange {
        sequence,
        table_name: "infra_operations".to_string(),
        op: "upsert".to_string(),
        id: format!("op-{sequence}"),
        version: 1,
        row: Some(json!({ "id": format!("op-{sequence}") })),
    };
    let page = finish_catchup_page(vec![change(10), change(11), change(12)], 9, 2);
    assert_eq!(page.changes.len(), 2);
    assert_eq!(page.next_cursor, 11);
    assert!(page.has_more);

    let empty = finish_catchup_page(Vec::new(), page.next_cursor, 2);
    assert_eq!(empty.next_cursor, 11);
    assert!(!empty.has_more);
}

#[tokio::test]
async fn sync_mutation_requires_a_nonnegative_base_version_before_database_access() {
    let mut request = SyncWriteRequest {
        id: "00000000-0000-0000-0000-000000000001".into(),
        op: Some("upsert".into()),
        payload: Some(json!({ "status": "applied" })),
        base_version: None,
        key: Some("write-key-1".into()),
    };
    assert!(matches!(
        sync_write_infra_operations(&test_state(), &request, "write-key-1", "fingerprint").await,
        Err(SyncWriteError::MissingBaseVersion)
    ));

    request.base_version = Some(-1);
    assert!(matches!(
        sync_write_infra_operations(&test_state(), &request, "write-key-1", "fingerprint").await,
        Err(SyncWriteError::InvalidBaseVersion)
    ));
}

#[test]
fn write_fingerprint_is_canonical_and_binds_every_semantic_identity() {
    let session = Session::test_admin_bearer("operator-a", "verified.jwt");
    let first = SyncWriteRequest {
        id: "00000000-0000-0000-0000-000000000001".into(),
        op: Some("upsert".into()),
        payload: Some(serde_json::from_str(r#"{"status":"applied","target_nodes":7}"#).unwrap()),
        base_version: Some(4),
        key: Some("write-key-1".into()),
    };
    let reordered = SyncWriteRequest {
        payload: Some(serde_json::from_str(r#"{"target_nodes":7,"status":"applied"}"#).unwrap()),
        ..SyncWriteRequest {
            id: first.id.clone(),
            op: first.op.clone(),
            payload: None,
            base_version: first.base_version,
            key: first.key.clone(),
        }
    };
    let fingerprint = sync_write_fingerprint(&session, "infra_operations", &first);
    assert_eq!(fingerprint.len(), 64);
    assert!(fingerprint.bytes().all(|byte| byte.is_ascii_hexdigit()));
    assert_eq!(
        fingerprint,
        sync_write_fingerprint(&session, "infra_operations", &reordered)
    );

    let changed_payload = SyncWriteRequest {
        payload: Some(json!({ "status": "failed", "target_nodes": 7 })),
        ..reordered
    };
    assert_ne!(
        fingerprint,
        sync_write_fingerprint(&session, "infra_operations", &changed_payload)
    );
    assert_ne!(
        fingerprint,
        sync_write_fingerprint(
            &Session::test_admin_bearer("operator-b", "verified.jwt"),
            "infra_operations",
            &first,
        )
    );
    assert_ne!(
        fingerprint,
        sync_write_fingerprint(&session, "other_table", &first)
    );
}

#[test]
fn replay_requires_the_original_fingerprint() {
    assert!(matches!(
        idempotency_decision(Some("fingerprint-a"), Some(8), "fingerprint-a"),
        Ok(Idem::Replay(8))
    ));
    assert!(matches!(
        idempotency_decision(Some("fingerprint-a"), Some(8), "fingerprint-b"),
        Err(SyncWriteError::IdempotencyMismatch)
    ));
    // A completed pre-upgrade record has no reconstructable fingerprint;
    // fail closed rather than acknowledge an unprovable request.
    assert!(matches!(
        idempotency_decision(None, Some(8), "fingerprint-a"),
        Err(SyncWriteError::IdempotencyMismatch)
    ));
    assert!(matches!(
        idempotency_decision(Some("fingerprint-a"), None, "fingerprint-a"),
        Ok(Idem::InFlight)
    ));
}
