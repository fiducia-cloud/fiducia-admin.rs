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
/// `fiducia-auth` (or directly via Supabase JWKS) and load org/role. A dev
/// bypass (`FIDUCIA_ADMIN_DEV_SESSION=user|admin`) lets you click through the UI
/// before auth is wired.
pub async fn current(_headers: &HeaderMap, _auth_url: &str) -> Option<Session> {
    match std::env::var("FIDUCIA_ADMIN_DEV_SESSION").ok().as_deref() {
        Some("admin") => Some(Session {
            user_id: "dev-admin".into(),
            email: Some("admin@example.com".into()),
            orgs: vec!["org_dev".into()],
            is_admin: true,
        }),
        Some("user") => Some(Session {
            user_id: "dev-user".into(),
            email: Some("user@example.com".into()),
            orgs: vec!["org_dev".into()],
            is_admin: false,
        }),
        _ => None, // TODO: real cookie/JWT verification
    }
}
