//! Dashboard session handling.
//!
//! Operators log in through Supabase Auth; the Supabase access token rides in a
//! host-only admin cookie (`fiducia_admin_session`) or an `Authorization: Bearer`
//! header. On each request we verify it via `fiducia-auth`'s `GET /v1/me` (which
//! already does offline Supabase JWT verification) and require an `admin` or
//! `operator` role copied from trusted Supabase `app_metadata`.

use axum::http::HeaderMap;
use std::fmt;
use std::time::Duration;

use serde::Deserialize;

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

    pub fn is_cookie_authenticated(&self) -> bool {
        self.cookie_authenticated
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
/// `fiducia_admin_session` cookie, verified with `fiducia-auth` `GET /v1/me` — and only
/// then falls back to the debug-build-only dev bypass.
pub async fn current(headers: &HeaderMap, auth_url: &str) -> Option<Session> {
    if let Some(token) = authorization_token(headers) {
        if let Some(session) = from_token(auth_url, &token, false).await {
            return Some(session);
        }
    }
    if let Some(token) = session_cookie(headers) {
        if let Some(session) = from_token(auth_url, &token, true).await {
            return Some(session);
        }
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
    #[serde(default)]
    roles: Vec<String>,
}

pub async fn from_bearer(auth_url: &str, token: &str) -> Option<Session> {
    from_token(auth_url, token, false).await
}

async fn from_token(auth_url: &str, token: &str, cookie_authenticated: bool) -> Option<Session> {
    match current_from_auth(auth_url, token).await {
        Ok(user) => Some(session_from_user(user, token, cookie_authenticated)),
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

fn session_from_user(user: AuthUser, token: &str, cookie_authenticated: bool) -> Session {
    // fiducia-auth derives these roles exclusively from trusted Supabase
    // app_metadata. Neither email addresses nor caller-editable metadata are an
    // authorization source for the operator plane.
    let is_admin = has_operator_role(&user.roles);

    let credential_kind = if cookie_authenticated {
        "cookie"
    } else {
        "authorization"
    };
    Session {
        user_id: user.user_id,
        email: user.email,
        is_admin,
        credential_binding: format!("{credential_kind}\0{token}"),
        cookie_authenticated,
    }
}

fn has_operator_role(roles: &[String]) -> bool {
    roles
        .iter()
        .any(|role| matches!(role.as_str(), "admin" | "operator"))
}

pub(crate) fn cookie_value(headers: &HeaderMap, expected_name: &str) -> Option<String> {
    for value in headers.get_all("cookie") {
        let Ok(value) = value.to_str() else {
            continue;
        };
        for part in value.split(';') {
            let Some((name, cookie_value)) = part.trim().split_once('=') else {
                continue;
            };
            if name == expected_name && !cookie_value.trim().is_empty() {
                return Some(cookie_value.trim().to_string());
            }
        }
    }
    None
}

fn session_cookie(headers: &HeaderMap) -> Option<String> {
    cookie_value(headers, "fiducia_admin_session")
}

/// Pull the bearer token from the `Authorization` header, else fall back to the
/// `fiducia_admin_session` cookie — so both browser (cookie) and API (header) callers
/// work, as the module contract promises.
fn authorization_token(headers: &HeaderMap) -> Option<String> {
    headers
        .get("authorization")
        .and_then(|v| v.to_str().ok())
        .and_then(|s| s.strip_prefix("Bearer "))
        .filter(|jwt| !jwt.is_empty())
        .map(str::to_string)
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::http::HeaderValue;

    fn headers_with(name: &str, value: &str) -> HeaderMap {
        let mut h = HeaderMap::new();
        h.insert(
            axum::http::HeaderName::from_bytes(name.as_bytes()).unwrap(),
            value.parse().unwrap(),
        );
        h
    }

    #[test]
    fn authorization_token_reads_bearer_header() {
        let h = headers_with("authorization", "Bearer abc.def");
        assert_eq!(authorization_token(&h).as_deref(), Some("abc.def"));
    }

    #[test]
    fn session_cookie_is_separate_from_authorization_header() {
        let h = headers_with("cookie", "other=1; fiducia_admin_session=xyz; more=2");
        assert_eq!(session_cookie(&h).as_deref(), Some("xyz"));
        assert_eq!(authorization_token(&h), None);
    }

    #[test]
    fn tokens_absent_when_no_credential() {
        let h = headers_with("cookie", "other=1");
        assert!(authorization_token(&h).is_none());
        assert!(session_cookie(&h).is_none());
    }

    #[test]
    fn only_trusted_operator_roles_authorize_admin() {
        assert!(has_operator_role(&["admin".into()]));
        assert!(has_operator_role(&["operator".into()]));
        assert!(!has_operator_role(&[
            "authenticated".into(),
            "customer".into()
        ]));
    }

    #[test]
    fn session_cookie_reads_admin_session_from_cookie_header() {
        let mut headers = HeaderMap::new();
        headers.insert(
            "cookie",
            HeaderValue::from_static("theme=dark; fiducia_admin_session=jwt.123; other=x"),
        );

        assert_eq!(session_cookie(&headers).as_deref(), Some("jwt.123"));
    }

    #[test]
    fn session_cookie_ignores_empty_admin_session_values() {
        let mut headers = HeaderMap::new();
        headers.insert(
            "cookie",
            HeaderValue::from_static("fiducia_admin_session= ; theme=dark"),
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
            HeaderValue::from_static("fiducia_admin_session=jwt.456"),
        );

        assert_eq!(session_cookie(&headers).as_deref(), Some("jwt.456"));
    }
}
