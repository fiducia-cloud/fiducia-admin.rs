//! Dashboard session handling.
//!
//! Operators log in through Supabase Auth; the Supabase access token rides in a
//! host-only admin cookie (`__Host-fiducia_admin_session` in release builds) or
//! an `Authorization: Bearer` header. On each request we verify it via
//! `fiducia-auth`'s `GET /v1/me` and require the versioned `fiducia-admin`
//! authorization context derived there from trusted Supabase `app_metadata`.
//! Raw role strings, browser headers, customer audiences, and user-editable
//! metadata are never sufficient to create an operator session.

use axum::http::HeaderMap;
use std::fmt;
use std::time::Duration;

use serde::Deserialize;

const AUTHORIZATION_CONTEXT_VERSION: u16 = 1;
const ADMIN_SURFACE_AUDIENCE: &str = "fiducia-admin";
const CUSTOMER_SURFACE_AUDIENCE: &str = "fiducia-customer";
const KNOWN_SURFACE_AUDIENCES: &[&str] = &[ADMIN_SURFACE_AUDIENCE, CUSTOMER_SURFACE_AUDIENCE];
const KNOWN_ROLES: &[&str] = &["admin", "operator", "customer"];
const KNOWN_CAPABILITIES: &[&str] = &[
    "admin:read",
    "admin:operate",
    "admin:write",
    "customer:self-service",
];

const fn admin_session_cookie_name(release_hardened: bool) -> &'static str {
    if release_hardened {
        "__Host-fiducia_admin_session"
    } else {
        "fiducia_admin_session"
    }
}

const fn login_csrf_cookie_name(release_hardened: bool) -> &'static str {
    if release_hardened {
        "__Host-fiducia_admin_login_csrf"
    } else {
        "fiducia_admin_login_csrf"
    }
}

/// Release cookies use the browser-enforced `__Host-` prefix, which forbids a
/// sibling subdomain from planting a colliding Domain cookie. Debug builds keep
/// unprefixed names so the explicit plain-HTTP development mode remains usable.
pub(crate) const ADMIN_SESSION_COOKIE: &str = admin_session_cookie_name(!cfg!(debug_assertions));
pub(crate) const LOGIN_CSRF_COOKIE: &str = login_csrf_cookie_name(!cfg!(debug_assertions));

#[derive(Clone)]
pub struct Session {
    pub user_id: String,
    pub email: Option<String>,
    pub is_admin: bool,
    credential_binding: String,
    cookie_authenticated: bool,
}

impl Session {
    /// Opaque input for the request-CSRF HMAC. Never render or log this value.
    pub fn csrf_binding(&self) -> &str {
        &self.credential_binding
    }

    pub fn is_browser_session(&self) -> bool {
        self.cookie_authenticated || self.credential_binding.starts_with("development\0")
    }

    #[cfg(test)]
    pub fn test_admin(user_id: &str) -> Self {
        Self {
            user_id: user_id.to_string(),
            email: Some(format!("{user_id}@example.com")),
            is_admin: true,
            credential_binding: format!("development\0{user_id}"),
            cookie_authenticated: false,
        }
    }

    #[cfg(test)]
    pub fn test_admin_cookie(user_id: &str, token: &str) -> Self {
        Self {
            user_id: user_id.to_string(),
            email: Some(format!("{user_id}@example.com")),
            is_admin: true,
            credential_binding: format!("cookie\0{token}"),
            cookie_authenticated: true,
        }
    }

    #[cfg(test)]
    pub fn test_admin_bearer(user_id: &str, token: &str) -> Self {
        Self {
            user_id: user_id.to_string(),
            email: Some(format!("{user_id}@example.com")),
            is_admin: true,
            credential_binding: format!("authorization\0{token}"),
            cookie_authenticated: false,
        }
    }
}

impl fmt::Debug for Session {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("Session")
            .field("user_id", &self.user_id)
            .field("email", &self.email)
            .field("is_admin", &self.is_admin)
            .field("credential", &"[redacted]")
            .finish()
    }
}

/// Resolve the session for a request, or `None` if not signed in.
///
/// Tries real auth first — the bearer from the `Authorization` header or the
/// canonical admin session cookie, verified with `fiducia-auth` `GET /v1/me` —
/// and only then falls back to the debug-build-only dev bypass.
pub async fn current(headers: &HeaderMap, auth_url: &str) -> Option<Session> {
    if let Some(token) = authorization_token(headers) {
        // An explicitly selected bearer credential never silently downgrades to
        // an ambient cookie when verification fails.
        return from_token(auth_url, &token, false).await;
    }
    if headers.contains_key("authorization") {
        return None;
    }
    if let Some(token) = session_cookie(headers) {
        return from_token(auth_url, &token, true).await;
    }
    if cookie_name_present(headers, ADMIN_SESSION_COOKIE) {
        // A malformed or duplicate admin cookie is an explicit, invalid
        // credential. Do not turn it into the debug bypass below.
        return None;
    }
    dev_session()
}

/// Debug builds only: `FIDUCIA_ADMIN_DEV_SESSION=user|admin` fabricates a session
/// so the UI can be clicked through before auth is wired. It is a **full
/// authentication bypass** — anyone reaching the service becomes that user — so
/// the entire code path is compiled out of release binaries; no environment
/// variable can resurrect it in production.
#[cfg(debug_assertions)]
fn dev_session() -> Option<Session> {
    let role = std::env::var("FIDUCIA_ADMIN_DEV_SESSION").ok()?;
    tracing::warn!(
        role = %role,
        "INSECURE: serving a fabricated dev session (auth bypass) — for local dev only"
    );
    match role.as_str() {
        "admin" => Some(Session {
            user_id: "dev-admin".into(),
            email: Some("admin@example.com".into()),
            is_admin: true,
            credential_binding: "development\0dev-admin".into(),
            cookie_authenticated: false,
        }),
        "user" => Some(Session {
            user_id: "dev-user".into(),
            email: Some("user@example.com".into()),
            is_admin: false,
            credential_binding: "development\0dev-user".into(),
            cookie_authenticated: false,
        }),
        _ => None,
    }
}

/// Release builds: the dev bypass does not exist. A stray env var is reported
/// loudly and ignored — it can never mint a session.
#[cfg(not(debug_assertions))]
fn dev_session() -> Option<Session> {
    if std::env::var_os("FIDUCIA_ADMIN_DEV_SESSION").is_some() {
        tracing::error!(
            "FIDUCIA_ADMIN_DEV_SESSION is set but IGNORED: the dev auth bypass is \
             compiled out of release builds and cannot be enabled in production."
        );
    }
    None
}

#[derive(Debug, Deserialize)]
struct MeResponse {
    user: AuthUser,
}

#[derive(Debug, Deserialize)]
struct AuthUser {
    user_id: String,
    email: Option<String>,
    /// Retained only for wire compatibility and diagnostics. Authorization must
    /// use the normalized versioned context below, never these raw strings.
    #[serde(default, rename = "roles")]
    _raw_roles: Vec<String>,
    authorization: AuthorizationContext,
}

#[derive(Debug, Deserialize)]
struct AuthorizationContext {
    version: u16,
    #[serde(default)]
    surface_audiences: Vec<String>,
    #[serde(default)]
    roles: Vec<String>,
    #[serde(default)]
    capabilities: Vec<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum AdminAuthorizationDecision {
    Authorized,
    AuthenticatedNonAdmin,
    Invalid,
}

pub async fn from_bearer(auth_url: &str, token: &str) -> Option<Session> {
    from_token(auth_url, token, false).await
}

async fn from_token(auth_url: &str, token: &str, cookie_authenticated: bool) -> Option<Session> {
    match current_from_auth(auth_url, token).await {
        Ok(user) => match session_from_user(user, token, cookie_authenticated) {
            Some(session) => Some(session),
            None => {
                tracing::debug!(
                    policy = "admin_authorization_context_v1",
                    "fiducia-auth identity was not authorized for the admin surface"
                );
                None
            }
        },
        Err(error) => {
            tracing::debug!(error = %error, "fiducia-auth rejected admin session");
            None
        }
    }
}

async fn current_from_auth(auth_url: &str, token: &str) -> Result<AuthUser, reqwest::Error> {
    let url = format!("{}/v1/me", auth_url.trim_end_matches('/'));
    let user = reqwest::Client::builder()
        .timeout(Duration::from_secs(10))
        .build()?
        .get(url)
        .bearer_auth(token)
        .send()
        .await?
        .error_for_status()?
        .json::<MeResponse>()
        .await?
        .user;
    Ok(user)
}

fn session_from_user(user: AuthUser, token: &str, cookie_authenticated: bool) -> Option<Session> {
    let is_admin = match admin_authorization_decision(&user.authorization) {
        AdminAuthorizationDecision::Authorized => true,
        AdminAuthorizationDecision::AuthenticatedNonAdmin => false,
        AdminAuthorizationDecision::Invalid => return None,
    };

    let credential_kind = if cookie_authenticated {
        "cookie"
    } else {
        "authorization"
    };
    Some(Session {
        user_id: user.user_id,
        email: user.email,
        is_admin,
        credential_binding: format!("{credential_kind}\0{token}"),
        cookie_authenticated,
    })
}

fn authorization_allows_admin(authorization: &AuthorizationContext) -> bool {
    matches!(
        admin_authorization_decision(authorization),
        AdminAuthorizationDecision::Authorized
    )
}

fn admin_authorization_decision(
    authorization: &AuthorizationContext,
) -> AdminAuthorizationDecision {
    if authorization.version != AUTHORIZATION_CONTEXT_VERSION
        || !unique_known_values(&authorization.surface_audiences, KNOWN_SURFACE_AUDIENCES)
        || !unique_known_values(&authorization.roles, KNOWN_ROLES)
        || !unique_known_values(&authorization.capabilities, KNOWN_CAPABILITIES)
    {
        return AdminAuthorizationDecision::Invalid;
    }

    let has_admin = contains(&authorization.roles, "admin");
    let has_operator = contains(&authorization.roles, "operator");
    let has_customer = contains(&authorization.roles, "customer");
    let legacy_customer = authorization.roles.is_empty();

    let mut expected_audiences = Vec::new();
    if has_admin || has_operator {
        expected_audiences.push(ADMIN_SURFACE_AUDIENCE);
    }
    if has_customer || legacy_customer {
        expected_audiences.push(CUSTOMER_SURFACE_AUDIENCE);
    }

    let mut expected_capabilities = Vec::new();
    if has_admin {
        expected_capabilities.extend(["admin:read", "admin:operate", "admin:write"]);
    } else if has_operator {
        expected_capabilities.extend(["admin:read", "admin:operate"]);
    }
    if has_customer || legacy_customer {
        expected_capabilities.push("customer:self-service");
    }

    if !same_set(&authorization.surface_audiences, &expected_audiences)
        || !same_set(&authorization.capabilities, &expected_capabilities)
    {
        return AdminAuthorizationDecision::Invalid;
    }

    if has_admin || has_operator {
        AdminAuthorizationDecision::Authorized
    } else {
        AdminAuthorizationDecision::AuthenticatedNonAdmin
    }
}

fn unique_known_values(values: &[String], known: &[&str]) -> bool {
    values.iter().enumerate().all(|(index, value)| {
        known.contains(&value.as_str()) && !values[..index].iter().any(|seen| seen == value)
    })
}

fn same_set(values: &[String], expected: &[&str]) -> bool {
    values.len() == expected.len()
        && expected
            .iter()
            .all(|expected| values.iter().any(|value| value.as_str() == *expected))
}

fn contains(values: &[String], expected: &str) -> bool {
    values.iter().any(|value| value == expected)
}

pub(crate) fn cookie_value(headers: &HeaderMap, expected_name: &str) -> Option<String> {
    let mut found = None;
    for value in headers.get_all("cookie") {
        let Ok(value) = value.to_str() else {
            continue;
        };
        for part in value.split(';') {
            let Some((name, cookie_value)) = part.trim().split_once('=') else {
                continue;
            };
            if name == expected_name && !cookie_value.trim().is_empty() {
                if found.is_some() {
                    // Reject ambiguous cookie tossing (for example, a sibling
                    // subdomain's Domain cookie colliding with our host-only
                    // admin cookie) instead of trusting browser ordering.
                    return None;
                }
                found = Some(cookie_value.trim().to_string());
            }
        }
    }
    found
}

fn cookie_name_present(headers: &HeaderMap, expected_name: &str) -> bool {
    headers.get_all("cookie").iter().any(|value| {
        value.to_str().is_ok_and(|value| {
            value.split(';').any(|part| {
                part.trim()
                    .split_once('=')
                    .is_some_and(|(name, _)| name == expected_name)
            })
        })
    })
}

fn session_cookie(headers: &HeaderMap) -> Option<String> {
    cookie_value(headers, ADMIN_SESSION_COOKIE)
}

/// Pull a bearer token from the `Authorization` header. Cookie extraction stays
/// separate so the resulting session records which credential class succeeded.
fn authorization_token(headers: &HeaderMap) -> Option<String> {
    let mut values = headers.get_all("authorization").iter();
    let value = values.next()?.to_str().ok()?;
    if values.next().is_some() {
        return None;
    }
    value
        .strip_prefix("Bearer ")
        .filter(|jwt| !jwt.is_empty())
        .map(str::to_string)
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::http::HeaderValue;
    use serde_json::json;

    fn headers_with(name: &str, value: &str) -> HeaderMap {
        let mut headers = HeaderMap::new();
        headers.insert(
            axum::http::HeaderName::from_bytes(name.as_bytes()).unwrap(),
            value.parse().unwrap(),
        );
        headers
    }

    fn authorization(
        version: u16,
        audiences: &[&str],
        roles: &[&str],
        capabilities: &[&str],
    ) -> AuthorizationContext {
        AuthorizationContext {
            version,
            surface_audiences: audiences.iter().map(|value| (*value).to_string()).collect(),
            roles: roles.iter().map(|value| (*value).to_string()).collect(),
            capabilities: capabilities
                .iter()
                .map(|value| (*value).to_string())
                .collect(),
        }
    }

    fn auth_user(raw_roles: &[&str], authorization: AuthorizationContext) -> AuthUser {
        AuthUser {
            user_id: "user_1".to_string(),
            email: Some("operator@example.com".to_string()),
            _raw_roles: raw_roles.iter().map(|value| (*value).to_string()).collect(),
            authorization,
        }
    }

    #[test]
    fn authorization_token_reads_bearer_header() {
        let headers = headers_with("authorization", "Bearer abc.def");
        assert_eq!(authorization_token(&headers).as_deref(), Some("abc.def"));
    }

    #[test]
    fn duplicate_authorization_headers_are_rejected_as_ambiguous() {
        let mut headers = HeaderMap::new();
        headers.append(
            "authorization",
            HeaderValue::from_static("Bearer first.jwt"),
        );
        headers.append(
            "authorization",
            HeaderValue::from_static("Bearer second.jwt"),
        );
        assert_eq!(authorization_token(&headers), None);
    }

    #[test]
    fn session_cookie_is_separate_from_authorization_header() {
        let headers = headers_with(
            "cookie",
            &format!("other=1; {ADMIN_SESSION_COOKIE}=xyz; more=2"),
        );
        assert_eq!(session_cookie(&headers).as_deref(), Some("xyz"));
        assert_eq!(authorization_token(&headers), None);
    }

    #[test]
    fn tokens_absent_when_no_credential() {
        let headers = headers_with("cookie", "other=1");
        assert!(authorization_token(&headers).is_none());
        assert!(session_cookie(&headers).is_none());
    }

    #[test]
    fn versioned_admin_and_operator_contexts_authorize() {
        assert!(authorization_allows_admin(&authorization(
            1,
            &["fiducia-admin"],
            &["admin"],
            &["admin:read", "admin:operate", "admin:write"],
        )));
        assert!(authorization_allows_admin(&authorization(
            1,
            &["fiducia-admin"],
            &["operator"],
            &["admin:read", "admin:operate"],
        )));
        assert!(authorization_allows_admin(&authorization(
            1,
            &["fiducia-admin", "fiducia-customer"],
            &["operator", "customer"],
            &["admin:read", "admin:operate", "customer:self-service"],
        )));
    }

    #[test]
    fn customer_context_is_authenticated_but_non_admin_and_raw_roles_fail_closed() {
        let customer = auth_user(
            &["admin"],
            authorization(
                1,
                &["fiducia-customer"],
                &["customer"],
                &["customer:self-service"],
            ),
        );
        let customer = session_from_user(customer, "token", false)
            .expect("a valid customer context remains an authenticated identity");
        assert!(!customer.is_admin);

        let no_trusted_context = auth_user(&["admin", "operator"], authorization(1, &[], &[], &[]));
        assert!(session_from_user(no_trusted_context, "token", false).is_none());
    }

    #[test]
    fn unknown_version_role_audience_capability_and_duplicates_fail_closed() {
        for context in [
            authorization(
                2,
                &["fiducia-admin"],
                &["admin"],
                &["admin:read", "admin:operate", "admin:write"],
            ),
            authorization(
                1,
                &["fiducia-admin", "future-surface"],
                &["admin"],
                &["admin:read", "admin:operate", "admin:write"],
            ),
            authorization(
                1,
                &["fiducia-admin"],
                &["superadmin"],
                &["admin:read", "admin:operate", "admin:write"],
            ),
            authorization(
                1,
                &["fiducia-admin"],
                &["admin"],
                &["admin:read", "admin:operate", "admin:write", "future:power"],
            ),
            authorization(
                1,
                &["fiducia-admin", "fiducia-admin"],
                &["admin"],
                &["admin:read", "admin:operate", "admin:write"],
            ),
        ] {
            assert!(!authorization_allows_admin(&context));
        }
    }

    #[test]
    fn admin_and_operator_capability_sets_are_not_interchangeable() {
        assert!(!authorization_allows_admin(&authorization(
            1,
            &["fiducia-admin"],
            &["admin"],
            &["admin:read", "admin:operate"],
        )));
        assert!(!authorization_allows_admin(&authorization(
            1,
            &["fiducia-admin"],
            &["operator"],
            &["admin:read"],
        )));
    }

    #[test]
    fn missing_authorization_context_is_a_wire_contract_failure() {
        let legacy = json!({
            "user": {
                "user_id": "user_1",
                "email": "operator@example.com",
                "roles": ["admin"]
            }
        });
        assert!(serde_json::from_value::<MeResponse>(legacy).is_err());
    }

    #[test]
    fn session_cookie_reads_admin_session_from_cookie_header() {
        let mut headers = HeaderMap::new();
        headers.insert(
            "cookie",
            format!("theme=dark; {ADMIN_SESSION_COOKIE}=jwt.123; other=x")
                .parse()
                .unwrap(),
        );

        assert_eq!(session_cookie(&headers).as_deref(), Some("jwt.123"));
    }

    #[test]
    fn session_cookie_ignores_empty_admin_session_values() {
        let mut headers = HeaderMap::new();
        headers.insert(
            "cookie",
            format!("{ADMIN_SESSION_COOKIE}= ; theme=dark")
                .parse()
                .unwrap(),
        );

        assert_eq!(session_cookie(&headers), None);
    }

    #[test]
    fn session_cookie_ignores_customer_session_cookie() {
        let headers = headers_with("cookie", "fiducia_session=customer.jwt");
        assert_eq!(session_cookie(&headers), None);
    }

    #[test]
    fn session_cookie_scans_all_cookie_headers() {
        let mut headers = HeaderMap::new();
        headers.append("cookie", HeaderValue::from_static("theme=dark"));
        headers.append(
            "cookie",
            format!("{ADMIN_SESSION_COOKIE}=jwt.456").parse().unwrap(),
        );

        assert_eq!(session_cookie(&headers).as_deref(), Some("jwt.456"));
    }

    #[test]
    fn duplicate_admin_cookies_are_rejected_as_ambiguous() {
        let headers = headers_with(
            "cookie",
            &format!("{ADMIN_SESSION_COOKIE}=host.jwt; {ADMIN_SESSION_COOKIE}=domain.jwt"),
        );
        assert_eq!(session_cookie(&headers), None);
    }

    #[test]
    fn release_cookie_names_are_browser_enforced_host_only() {
        assert_eq!(
            admin_session_cookie_name(true),
            "__Host-fiducia_admin_session"
        );
        assert_eq!(
            login_csrf_cookie_name(true),
            "__Host-fiducia_admin_login_csrf"
        );
        assert!(!admin_session_cookie_name(false).starts_with("__Host-"));
        assert!(!login_csrf_cookie_name(false).starts_with("__Host-"));
    }
}
