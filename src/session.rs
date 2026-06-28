//! Dashboard session handling.
//!
//! Admins/users log in through Supabase Auth in the browser; the Supabase access
//! token rides in a cookie (`fiducia_session`) or an `Authorization: Bearer`
//! header. On each request we verify it via `fiducia-auth`'s `GET /v1/me` (which
//! already does offline Supabase JWT verification) and resolve the caller's
//! org(s). `infra` pages require the `admin` role; account/key pages need any
//! authenticated user.

use axum::http::HeaderMap;
use std::time::Duration;

#[derive(Debug, Clone)]
pub struct Session {
    pub user_id: String,
    pub email: Option<String>,
    pub orgs: Vec<String>,
    pub is_admin: bool,
    /// The caller's bearer token, kept so key actions can be proxied to
    /// `fiducia-auth` as the same identity. `None` for a dev-bypass session.
    pub token: Option<String>,
}

/// Resolve the session for a request, or `None` if not signed in.
///
/// Reads the bearer (from the `Authorization` header or the `fiducia_session`
/// cookie) and verifies it with `fiducia-auth`; on success loads org(s) and
/// derives admin from `FIDUCIA_ADMIN_EMAILS`.
///
/// A dev bypass (`FIDUCIA_ADMIN_DEV_SESSION=user|admin`) lets you click through
/// the UI before auth is wired. It is a **full authentication bypass** — anyone
/// reaching the service becomes that user — so it is honored **only** in debug
/// builds, or when explicitly forced with `FIDUCIA_ALLOW_INSECURE_DEV_SESSION=1`.
/// Release builds otherwise refuse it and log loudly, so a stray env var in
/// production can't silently hand out admin.
pub async fn current(headers: &HeaderMap, auth_url: &str) -> Option<Session> {
    if let Some(session) = dev_session() {
        return Some(session);
    }

    let token = bearer_token(headers)?;
    verify_with_auth(auth_url, &token).await
}

/// Verify a bearer with `fiducia-auth` `GET /v1/me` and build a [`Session`].
async fn verify_with_auth(auth_url: &str, token: &str) -> Option<Session> {
    let url = format!("{}/v1/me", auth_url.trim_end_matches('/'));
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(10))
        .build()
        .ok()?;
    let resp = match client.get(&url).bearer_auth(token).send().await {
        Ok(resp) => resp,
        Err(e) => {
            tracing::warn!(error = %e, "session: fiducia-auth unreachable");
            return None;
        }
    };
    if !resp.status().is_success() {
        return None; // 401/403 → not signed in
    }
    let body: serde_json::Value = resp.json().await.ok()?;
    let user = body.get("user")?;
    let user_id = user.get("user_id")?.as_str()?.to_string();
    let email = user
        .get("email")
        .and_then(|e| e.as_str())
        .map(str::to_string);
    let orgs = user
        .get("orgs")
        .and_then(|o| o.as_array())
        .map(|a| {
            a.iter()
                .filter_map(|v| v.as_str().map(str::to_string))
                .collect()
        })
        .unwrap_or_default();

    Some(Session {
        user_id,
        is_admin: email.as_deref().map(is_admin_email).unwrap_or(false),
        email,
        orgs,
        token: Some(token.to_string()),
    })
}

/// Pull the bearer token from the `Authorization` header, else the
/// `fiducia_session` cookie.
fn bearer_token(headers: &HeaderMap) -> Option<String> {
    if let Some(jwt) = headers
        .get("authorization")
        .and_then(|v| v.to_str().ok())
        .and_then(|s| s.strip_prefix("Bearer "))
    {
        return Some(jwt.to_string());
    }
    let cookies = headers.get("cookie").and_then(|v| v.to_str().ok())?;
    for pair in cookies.split(';') {
        let pair = pair.trim();
        if let Some(value) = pair.strip_prefix("fiducia_session=") {
            if !value.is_empty() {
                return Some(value.to_string());
            }
        }
    }
    None
}

/// `admin` iff the verified email is listed in `FIDUCIA_ADMIN_EMAILS` (comma or
/// whitespace separated). No list configured → no admins (infra pages locked).
fn is_admin_email(email: &str) -> bool {
    let Ok(list) = std::env::var("FIDUCIA_ADMIN_EMAILS") else {
        return false;
    };
    let email = email.trim().to_ascii_lowercase();
    list.split([',', ' ', '\t', '\n'])
        .map(|e| e.trim().to_ascii_lowercase())
        .filter(|e| !e.is_empty())
        .any(|e| e == email)
}

/// The optional dev-only auth bypass.
fn dev_session() -> Option<Session> {
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
            orgs: vec!["org_dev".into()],
            is_admin: true,
            token: None,
        }),
        "user" => Some(Session {
            user_id: "dev-user".into(),
            email: Some("user@example.com".into()),
            orgs: vec!["org_dev".into()],
            is_admin: false,
            token: None,
        }),
        _ => None,
    }
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
        let h = headers_with("cookie", "other=1; fiducia_session=xyz; more=2");
        assert_eq!(bearer_token(&h).as_deref(), Some("xyz"));
    }

    #[test]
    fn bearer_token_absent_when_no_credential() {
        let h = headers_with("cookie", "other=1");
        assert!(bearer_token(&h).is_none());
    }

    #[test]
    fn admin_email_matches_configured_list_case_insensitively() {
        std::env::set_var("FIDUCIA_ADMIN_EMAILS", "boss@acme.com, Ops@Acme.com");
        assert!(is_admin_email("ops@acme.com"));
        assert!(is_admin_email("boss@acme.com"));
        assert!(!is_admin_email("intern@acme.com"));
        std::env::remove_var("FIDUCIA_ADMIN_EMAILS");
        assert!(!is_admin_email("boss@acme.com"));
    }
}
