//! Operator login / session / MFA flow tests. Extracted verbatim from main.rs;
//! `use super::*` resolves to the crate root exactly as when inline.

use super::*;
use axum::body::Body;
use axum::http::Request;
use tower::ServiceExt;

pub(super) async fn spawn_mock(app: Router) -> (String, tokio::task::JoinHandle<()>) {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let task = tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });
    (format!("http://{address}"), task)
}

#[tokio::test]
async fn login_requires_the_operator_registry_after_trusted_auth() {
    let supabase = Router::new().route(
        "/auth/v1/token",
        post(|| async { Json(json!({ "access_token": "verified.jwt" })) }),
    );
    let auth = Router::new().route(
        "/v1/me",
        get(|| async {
            Json(json!({
                "user": {
                    "user_id": "00000000-0000-0000-0000-000000000001",
                    "email": "operator@example.com",
                    "orgs": ["org_admin"],
                    "roles": ["operator"]
                }
            }))
        }),
    );
    let (supabase_url, supabase_task) = spawn_mock(supabase).await;
    let (auth_url, auth_task) = spawn_mock(auth).await;

    let state = Arc::new(AppState {
        auth_url,
        brain_url: "http://localhost:8095".into(),
        supabase_url,
        supabase_publishable_key: "public-publishable-key".into(),
        db: None,
        stream_tx: broadcast::channel(4).0,
        request_security: test_request_security(),
        prometheus_url: None,
        loki_url: None,
        grafana_public_url: None,
        node_urls: Vec::new(),
    });
    let login_nonce = "registry-test-login-nonce";
    let login_csrf = state
        .request_security
        .csrf_token(&format!("login\0{login_nonce}"));
    let app = Router::new()
        .route("/login", post(login_submit))
        .with_state(state);
    let response = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/login")
                .header("host", "admin.fiducia.cloud")
                .header("origin", "https://admin.fiducia.cloud")
                .header("sec-fetch-site", "same-origin")
                .header("cookie", format!("{LOGIN_CSRF_COOKIE}={login_nonce}"))
                .header(CONTENT_TYPE, "application/x-www-form-urlencoded")
                .body(Body::from(format!(
                    "csrf_token={login_csrf}&email=operator%40example.com&password=correct-horse"
                )))
                .unwrap(),
        )
        .await
        .unwrap();

    supabase_task.abort();
    auth_task.abort();

    assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
    assert!(response.headers().get(SET_COOKIE).is_none());
}

#[test]
fn logout_expires_only_the_admin_cookie() {
    let cookie = clear_session_cookie();
    assert!(cookie.starts_with(&format!("{ADMIN_SESSION_COOKIE}=")));
    assert!(cookie.contains("Max-Age=0"));
    assert!(cookie.contains("HttpOnly"));
    assert!(cookie.contains("SameSite=Strict"));
    assert!(cookie.contains("Path=/"));
    assert!(!cookie.contains("Domain="));
    assert!(!cookie.contains("fiducia_session="));
    if !cfg!(debug_assertions) {
        assert!(cookie.starts_with("__Host-"));
        assert!(cookie.contains("; Secure"));
    }
}

#[test]
fn scale_target_rejects_below_floor_and_i32_overflow() {
    assert!(!scale_target_is_valid(0));
    assert!(!scale_target_is_valid(MIN_SCALE_TARGET_NODES - 1));
    assert!(scale_target_is_valid(MIN_SCALE_TARGET_NODES));
    assert!(scale_target_is_valid(i32::MAX as u32));
    // Above i32::MAX would wrap negative in the audit record's i32 column.
    assert!(!scale_target_is_valid(i32::MAX as u32 + 1));
    assert!(!scale_target_is_valid(u32::MAX));
}

#[test]
fn only_mutating_registry_roles_are_enabled() {
    for role in ["owner", "admin", "operator"] {
        assert!(operator_registry_role_allows_access(role), "role={role}");
    }
    for role in ["viewer", "authenticated", "customer", ""] {
        assert!(!operator_registry_role_allows_access(role), "role={role}");
    }
}

#[test]
fn grafana_public_url_validation_rejects_dangerous_schemes() {
    // Allowed: http(s) URLs and root-relative paths (deep-link prefixes).
    assert!(grafana_public_url_is_valid("https://grafana.example.com"));
    assert!(grafana_public_url_is_valid("http://dd-grafana:3000"));
    assert!(grafana_public_url_is_valid("/telemetry"));
    // Rejected: anything that could become a dangerous or off-origin href.
    assert!(!grafana_public_url_is_valid("javascript:alert(1)"));
    assert!(!grafana_public_url_is_valid(
        "data:text/html,<script>1</script>"
    ));
    assert!(!grafana_public_url_is_valid("//evil.example.com"));
    assert!(!grafana_public_url_is_valid("ftp://grafana"));
    assert!(!grafana_public_url_is_valid("telemetry")); // not root-relative
                                                        // A set-but-invalid value fails startup closed; unset stays a no-op.
    std::env::set_var("FIDUCIA_GRAFANA_PUBLIC_URL", "javascript:alert(1)");
    assert!(validated_grafana_public_url().is_err());
    std::env::set_var("FIDUCIA_GRAFANA_PUBLIC_URL", "/telemetry");
    assert_eq!(
        validated_grafana_public_url().unwrap(),
        Some("/telemetry".to_string())
    );
    std::env::remove_var("FIDUCIA_GRAFANA_PUBLIC_URL");
    assert_eq!(validated_grafana_public_url().unwrap(), None);
}

#[test]
fn insecure_cookie_escape_requires_an_explicit_truthy_value() {
    assert!(explicitly_enabled(Some("1")));
    assert!(explicitly_enabled(Some("true")));
    assert!(explicitly_enabled(Some(" TRUE ")));
    assert!(!explicitly_enabled(None));
    assert!(!explicitly_enabled(Some("0")));
    assert!(!explicitly_enabled(Some("yes")));
    assert_eq!(cookie_secure_suffix_for(false, true), "");
    assert_eq!(cookie_secure_suffix_for(false, false), "; Secure");
    assert_eq!(cookie_secure_suffix_for(true, true), "; Secure");
    assert_eq!(cookie_secure_suffix_for(true, false), "; Secure");
}
