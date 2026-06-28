//! Dashboard session handling.
//!
//! Admins/users log in through Supabase Auth in the browser; the Supabase access
//! token rides in a cookie. On each request we verify it (via `fiducia-auth`,
//! which already does offline Supabase JWT verification) and resolve the caller's
//! org(s) + role. `infra` pages require the `admin` role; account/key pages need
//! any authenticated user.

use axum::http::HeaderMap;
use serde::Deserialize;

#[derive(Debug, Clone)]
pub struct Session {
    pub user_id: String,
    pub email: Option<String>,
    pub orgs: Vec<String>,
    pub is_admin: bool,
    pub bearer_token: Option<String>,
}

/// Resolve the session for a request, or `None` if not signed in.
pub async fn current(headers: &HeaderMap, auth_url: &str) -> Option<Session> {
    if let Some(token) = session_cookie(headers) {
        match current_from_auth(auth_url, &token).await {
            Ok(session) => return Some(session),
            Err(err) => {
                tracing::debug!(error = %err, "fiducia-auth rejected dashboard session");
            }
        }
    }

    let Some(role) = std::env::var("FIDUCIA_ADMIN_DEV_SESSION").ok() else {
        return None;
    };

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
            bearer_token: None,
        }),
        "user" => Some(Session {
            user_id: "dev-user".into(),
            email: Some("user@example.com".into()),
            orgs: vec!["org_dev".into()],
            is_admin: false,
            bearer_token: None,
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
    orgs: Vec<String>,
}

async fn current_from_auth(auth_url: &str, token: &str) -> Result<Session, reqwest::Error> {
    let url = format!("{}/v1/me", auth_url.trim_end_matches('/'));
    let user = reqwest::Client::new()
        .get(url)
        .bearer_auth(token)
        .send()
        .await?
        .error_for_status()?
        .json::<MeResponse>()
        .await?
        .user;
    let is_admin = admin_all_users()
        || env_list_contains("FIDUCIA_ADMIN_USER_IDS", &user.user_id)
        || user
            .email
            .as_deref()
            .is_some_and(|email| env_list_contains("FIDUCIA_ADMIN_EMAILS", email));

    Ok(Session {
        user_id: user.user_id,
        email: user.email,
        orgs: user.orgs,
        is_admin,
        bearer_token: Some(token.to_string()),
    })
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
            if name == "fiducia_session" && !cookie_value.trim().is_empty() {
                return Some(cookie_value.trim().to_string());
            }
        }
    }
    None
}

fn admin_all_users() -> bool {
    matches!(
        std::env::var("FIDUCIA_ADMIN_ALL_USERS").as_deref(),
        Ok("1" | "true" | "TRUE" | "yes" | "YES" | "on" | "ON")
    )
}

fn env_list_contains(name: &str, needle: &str) -> bool {
    std::env::var(name)
        .ok()
        .map(|value| {
            value
                .split(',')
                .map(str::trim)
                .filter(|item| !item.is_empty())
                .any(|item| item == needle)
        })
        .unwrap_or(false)
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

    #[test]
    fn session_cookie_reads_fiducia_session_from_cookie_header() {
        let mut headers = HeaderMap::new();
        headers.insert(
            "cookie",
            HeaderValue::from_static("theme=dark; fiducia_session=jwt.123; other=x"),
        );

        assert_eq!(session_cookie(&headers).as_deref(), Some("jwt.123"));
    }
}
