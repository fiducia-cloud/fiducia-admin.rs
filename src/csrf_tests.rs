//! CSRF and request-security gate tests. Extracted verbatim from main.rs;
//! `use super::*` resolves to the crate root exactly as when inline.

use super::*;
use axum::body::Body;
use axum::http::Request;
use tower::ServiceExt;

fn browser_headers(origin: &str) -> HeaderMap {
    let mut headers = HeaderMap::new();
    headers.insert("host", HeaderValue::from_static("admin.fiducia.cloud"));
    headers.insert("origin", HeaderValue::from_str(origin).unwrap());
    headers.insert("sec-fetch-site", HeaderValue::from_static("same-origin"));
    headers
}

#[test]
fn form_security_requires_exact_origin_and_credential_bound_token() {
    let state = sync_tests::test_state();
    let session = Session::test_admin("dev-admin");
    let csrf = csrf_token(&state, &session);

    assert!(require_form_security(
        &browser_headers("https://admin.fiducia.cloud"),
        &state,
        &session,
        &csrf,
    )
    .is_ok());
    assert!(require_form_security(
        &browser_headers("https://app.fiducia.cloud"),
        &state,
        &session,
        &csrf,
    )
    .is_err());
    assert!(require_form_security(
        &browser_headers("https://admin.fiducia.cloud"),
        &state,
        &session,
        "tampered",
    )
    .is_err());
}

#[test]
fn login_security_requires_exact_origin_host_cookie_and_bound_token() {
    let state = sync_tests::test_state();
    let nonce = "unit-test-login-nonce";
    let csrf = state
        .request_security
        .csrf_token(&format!("login\0{nonce}"));
    let mut exact = browser_headers("https://admin.fiducia.cloud");
    exact.insert(
        "cookie",
        format!("{LOGIN_CSRF_COOKIE}={nonce}").parse().unwrap(),
    );
    assert!(require_login_security(&exact, &state, &csrf).is_ok());

    let mut sibling = exact.clone();
    sibling.insert(
        "origin",
        HeaderValue::from_static("https://app.fiducia.cloud"),
    );
    assert!(require_login_security(&sibling, &state, &csrf).is_err());

    let mut missing_cookie = exact;
    missing_cookie.remove("cookie");
    assert!(require_login_security(&missing_cookie, &state, &csrf).is_err());
}

#[test]
fn sync_security_distinguishes_cookie_and_bearer_provenance() {
    let state = sync_tests::test_state();
    let cookie_session = Session::test_admin_cookie("operator-a", "cookie.jwt");
    let csrf = csrf_token(&state, &cookie_session);
    let mut cookie_headers = browser_headers("https://admin.fiducia.cloud");
    cookie_headers.insert(CSRF_HEADER, HeaderValue::from_str(&csrf).unwrap());
    assert!(require_sync_write_security(&cookie_headers, &state, &cookie_session).is_ok());

    cookie_headers.remove(CSRF_HEADER);
    assert!(require_sync_write_security(&cookie_headers, &state, &cookie_session).is_err());

    let bearer_session = Session::test_admin_bearer("operator-a", "bearer.jwt");
    let mut bearer_headers = HeaderMap::new();
    bearer_headers.insert("host", HeaderValue::from_static("admin.fiducia.cloud"));
    assert!(require_sync_write_security(&bearer_headers, &state, &bearer_session).is_ok());

    bearer_headers.insert(
        "origin",
        HeaderValue::from_static("https://app.fiducia.cloud"),
    );
    assert!(require_sync_write_security(&bearer_headers, &state, &bearer_session).is_err());
}

#[tokio::test]
async fn response_headers_deny_framing() {
    let app = Router::new()
        .route("/healthz", get(health))
        .layer(middleware::from_fn(security_headers));
    let response = app
        .oneshot(
            Request::builder()
                .uri("/healthz")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(
        response
            .headers()
            .get("x-frame-options")
            .and_then(|value| value.to_str().ok()),
        Some("DENY")
    );
    assert!(response
        .headers()
        .get("content-security-policy")
        .and_then(|value| value.to_str().ok())
        .is_some_and(|value| value.contains("frame-ancestors 'none'")));
    // Health is deliberately cache-neutral; authenticated/dynamic routes
    // are covered separately by the middleware's path classification.
    assert!(response.headers().get("cache-control").is_none());
}

#[tokio::test]
async fn dynamic_responses_are_never_cached() {
    let app = Router::new()
        .route("/login", get(|| async { StatusCode::OK }))
        .layer(middleware::from_fn(security_headers));
    let response = app
        .oneshot(
            Request::builder()
                .uri("/login")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(
        response
            .headers()
            .get("cache-control")
            .and_then(|value| value.to_str().ok()),
        Some("no-store")
    );
}
