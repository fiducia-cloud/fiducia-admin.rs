//! Dashboard session handling.
//!
//! Operators log in through Supabase Auth; the Supabase access token rides in a
//! host-only admin cookie (`fiducia_admin_session`) or an `Authorization: Bearer`
//! header. On each request we verify it via `fiducia-auth`'s `GET /v1/me` (which
//! already does offline Supabase JWT verification) and require an `admin` or
//! `operator` role copied from trusted Supabase `app_metadata`.

use axum::http::HeaderMap;
use std::time::Duration;

use serde::Deserialize;

#[derive(Debug, Clone)]
pub struct Session {
    pub user_id: String,
    pub email: Option<String>,
    pub is_admin: bool,
}

/// Resolve the session for a request, or `None` if not signed in.
///
/// Tries real auth first — the bearer from the `Authorization` header or the
/// `fiducia_admin_session` cookie, verified with `fiducia-auth` `GET /v1/me` — and only
/// then falls back to the dev bypass.
///
/// A dev bypass (`FIDUCIA_ADMIN_DEV_SESSION=user|admin`) lets you click through
/// the UI before auth is wired. It is a **full authentication bypass** — anyone
/// reaching the service becomes that user — so it is honored **only** in debug
/// builds, or when explicitly forced with `FIDUCIA_ALLOW_INSECURE_DEV_SESSION=1`.
/// Release builds otherwise refuse it and log loudly, so a stray env var in
/// production can't silently hand out admin.
pub async fn current(headers: &HeaderMap, auth_url: &str) -> Option<Session> {
    if let Some(token) = bearer_token(headers) {
        if let Some(session) = from_bearer(auth_url, &token).await {
            return Some(session);
        }
    }
    let role = std::env::var("FIDUCIA_ADMIN_DEV_SESSION").ok()?;

    if !dev_session_allowed() {
        tracing::error!(
            "FIDUCIA_ADMIN_DEV_SESSION is set but IGNORED: the dev auth bypass is \
             disabled in release builds. Set FIDUCIA_ALLOW_INSECURE_DEV_SESSION=1 \
             to force it (NEVER in production)."
        );
        return None;
    }

    tracing::warn!(
        role = %role,
        "INSECURE: serving a fabricated dev session (auth bypass) — for local dev only"
    );
    match role.as_str() {
        "admin" => Some(Session {
            user_id: "dev-admin".into(),
            email: Some("admin@example.com".into()),
            is_admin: true,
        }),
        "user" => Some(Session {
            user_id: "dev-user".into(),
            email: Some("user@example.com".into()),
            is_admin: false,
        }),
        _ => None,
    }
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
    match current_from_auth(auth_url, token).await {
        Ok(session) => Some(session),
        Err(error) => {
            tracing::debug!(error = %error, "fiducia-auth rejected admin session");
            None
        }
    }
}

async fn current_from_auth(auth_url: &str, token: &str) -> Result<Session, reqwest::Error> {
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
    let is_admin = has_operator_role(&user.roles);

    Ok(Session {
        user_id: user.user_id,
        email: user.email,
        is_admin,
    })
}

fn has_operator_role(roles: &[String]) -> bool {
    roles
        .iter()
        .any(|role| matches!(role.as_str(), "admin" | "operator"))
}

fn session_cookie(headers: &HeaderMap) -> Option<String> {
    for value in headers.get_all("cookie") {
        let Ok(value) = value.to_str() else {
            continue;
        };
        for part in value.split(';') {
            let Some((name, cookie_value)) = part.trim().split_once('=') else {
                continue;
            };
            if name == "fiducia_admin_session" && !cookie_value.trim().is_empty() {
                return Some(cookie_value.trim().to_string());
            }
        }
    }
    None
}

/// Pull the bearer token from the `Authorization` header, else fall back to the
/// `fiducia_admin_session` cookie — so both browser (cookie) and API (header) callers
/// work, as the module contract promises.
fn bearer_token(headers: &HeaderMap) -> Option<String> {
    if let Some(jwt) = headers
        .get("authorization")
        .and_then(|v| v.to_str().ok())
        .and_then(|s| s.strip_prefix("Bearer "))
    {
        if !jwt.is_empty() {
            return Some(jwt.to_string());
        }
    }
    session_cookie(headers)
}

/// The dev auth bypass is allowed only in debug builds, or when an operator
/// explicitly opts in via `FIDUCIA_ALLOW_INSECURE_DEV_SESSION=1`.
fn dev_session_allowed() -> bool {
    cfg!(debug_assertions)
        || std::env::var("FIDUCIA_ALLOW_INSECURE_DEV_SESSION").as_deref() == Ok("1")
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
    fn bearer_token_prefers_authorization_header() {
        let h = headers_with("authorization", "Bearer abc.def");
        assert_eq!(bearer_token(&h).as_deref(), Some("abc.def"));
    }

    #[test]
    fn bearer_token_falls_back_to_session_cookie() {
        let h = headers_with("cookie", "other=1; fiducia_admin_session=xyz; more=2");
        assert_eq!(bearer_token(&h).as_deref(), Some("xyz"));
    }

    #[test]
    fn bearer_token_absent_when_no_credential() {
        let h = headers_with("cookie", "other=1");
        assert!(bearer_token(&h).is_none());
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
