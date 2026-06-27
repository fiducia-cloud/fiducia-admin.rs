//! Dashboard session handling (skeleton).
//!
//! Admins/users log in through Supabase Auth in the browser; the Supabase access
//! token rides in a cookie. On each request we verify it (via `fiducia-auth`,
//! which already does offline Supabase JWT verification) and resolve the caller's
//! org(s) + role. `infra` pages require the `admin` role; account/key pages need
//! any authenticated user.

use axum::http::HeaderMap;

#[derive(Debug, Clone)]
pub struct Session {
    pub user_id: String,
    pub email: Option<String>,
    pub orgs: Vec<String>,
    pub is_admin: bool,
}

/// Resolve the session for a request, or `None` if not signed in.
///
/// TODO: read the `fiducia_session` cookie, then verify it with
/// `fiducia-auth` (or directly via Supabase JWKS) and load org/role.
///
/// A dev bypass (`FIDUCIA_ADMIN_DEV_SESSION=user|admin`) lets you click through
/// the UI before auth is wired. It is a **full authentication bypass** — anyone
/// reaching the service becomes that user — so it is honored **only** in debug
/// builds, or when explicitly forced with `FIDUCIA_ALLOW_INSECURE_DEV_SESSION=1`.
/// Release builds otherwise refuse it and log loudly, so a stray env var in
/// production can't silently hand out admin.
pub async fn current(_headers: &HeaderMap, _auth_url: &str) -> Option<Session> {
    let Some(role) = std::env::var("FIDUCIA_ADMIN_DEV_SESSION").ok() else {
        return None; // TODO: real cookie/JWT verification
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
        }),
        "user" => Some(Session {
            user_id: "dev-user".into(),
            email: Some("user@example.com".into()),
            orgs: vec!["org_dev".into()],
            is_admin: false,
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
