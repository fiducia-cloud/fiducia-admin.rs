//! Regression guard for the narrow Rust 1.95 compatibility repair in PR #60.
//!
//! The large-error allowance is intentionally restricted to four Axum boundary
//! helpers that return a concrete `Response` to preserve the exact rejection
//! wire contract. Shared-auth fixtures must stay aligned with the pinned adapter
//! rather than accumulating fields that do not exist in its `Identity` type.

const MAIN_SOURCE: &str = include_str!("../src/main.rs");
const SESSION_SOURCE: &str = include_str!("../src/session.rs");

#[test]
fn large_error_allowance_is_limited_to_the_four_response_boundaries() {
    assert_eq!(
        MAIN_SOURCE.matches("#[allow(clippy::result_large_err)]").count(),
        4,
        "new large-error exceptions require explicit review",
    );

    for signature in [
        "async fn require(headers: &HeaderMap, st: &AppState) -> Result<Session, Response>",
        "async fn require_admin(headers: &HeaderMap, st: &AppState) -> Result<Session, Response>",
        "async fn require_admin_api(headers: &HeaderMap, st: &AppState) -> Result<Session, Response>",
        "async fn cluster_data(st: &AppState) -> Result<ClusterData, Response>",
    ] {
        let offset = MAIN_SOURCE
            .find(signature)
            .unwrap_or_else(|| panic!("missing guarded Axum boundary: {signature}"));
        let prefix = &MAIN_SOURCE[..offset];
        assert!(
            prefix.ends_with("#[allow(clippy::result_large_err)]\n"),
            "{signature} lost its scoped Rust 1.95 rationale",
        );
    }
}

#[test]
fn shared_auth_fixture_uses_only_the_pinned_identity_contract() {
    assert!(SESSION_SOURCE.contains("fn shared_auth_identity_fixture_matches_pinned_adapter_contract"));
    assert!(!SESSION_SOURCE.contains("assurance_level:"));
    assert!(!SESSION_SOURCE.contains("auth_methods:"));

    for field in [
        "shared_user_id:",
        "provider:",
        "provider_tenant:",
        "provider_subject:",
        "project:",
        "supabase_user_id:",
        "session_id:",
        "email:",
        "email_verified:",
        "roles:",
        "authority:",
    ] {
        assert!(SESSION_SOURCE.contains(field), "fixture lost Identity field {field}");
    }
}
