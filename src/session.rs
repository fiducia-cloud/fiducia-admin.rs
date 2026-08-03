//! Dashboard session handling through the Fiducia Shared Auth dual-provider guard.
//!
//! The login form starts with the ADMIN Supabase project. The process-wide guard
//! exchanges and introspects that provider token through Shared Auth, pins the
//! `fiducia-admin` project, requires an `admin` or `operator` role signed by
//! Shared Auth, and returns the short-lived Shared Auth token for the host-only
//! admin cookie. Direct Supabase verification can prove identity inside the
//! adapter, but it can never manufacture an admin role or a session upgrade.

use std::fmt;
use std::sync::OnceLock;
use std::time::Duration;

use axum::http::HeaderMap;
use fiducia_shared_auth_guard::{Config, Guard, Identity, Outcome, SessionUpgrade};

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

pub(crate) const ADMIN_SESSION_COOKIE: &str = admin_session_cookie_name(!cfg!(debug_assertions));
pub(crate) const LOGIN_CSRF_COOKIE: &str = login_csrf_cookie_name(!cfg!(debug_assertions));

struct ConfiguredGuard {
    shared_auth_base: String,
    guard: Guard,
}

static ADMIN_GUARD: OnceLock<Result<ConfiguredGuard, String>> = OnceLock::new();

/// Validate all Shared Auth and ADMIN Supabase configuration at startup. The
/// same cached guard is then reused for local JWKS verification and provider
/// races on every request.
pub fn initialize(shared_auth_base: &str) -> Result<(), String> {
    configured_guard(shared_auth_base).map(|_| ())
}

fn configured_guard(shared_auth_base: &str) -> Result<&'static Guard, String> {
    let configured = ADMIN_GUARD.get_or_init(|| build_guard(shared_auth_base));
    let configured = configured.as_ref().map_err(Clone::clone)?;
    if configured.shared_auth_base != shared_auth_base.trim_end_matches('/') {
        return Err("Shared Auth base URL changed after guard initialization".to_string());
    }
    Ok(&configured.guard)
}

fn build_guard(shared_auth_base: &str) -> Result<ConfiguredGuard, String> {
    let shared_auth_base = shared_auth_base.trim_end_matches('/').to_string();
    if shared_auth_base.is_empty() {
        return Err("SHARED_AUTH_URL must be set".to_string());
    }
    let guard = Guard::new(Config {
        shared_auth_base: shared_auth_base.clone(),
        issuer: required_env("SHARED_AUTH_ISSUER")?,
        audience: required_env("SHARED_AUTH_AUDIENCE")?,
        supabase_url: required_env("SUPABASE_URL")?,
        supabase_api_key: required_env("SUPABASE_PUBLISHABLE_KEY")?,
        project: "fiducia-admin".to_string(),
        introspect_secret: required_env("SHARED_AUTH_INTROSPECT_SECRET")?,
        required_roles: vec!["admin".to_string(), "operator".to_string()],
        arm_timeout: Duration::from_secs(10),
        race_deadline: Duration::from_secs(12),
        jwks_ttl: Duration::from_secs(300),
    })
    .map_err(|error| error.to_string())?;
    Ok(ConfiguredGuard {
        shared_auth_base,
        guard,
    })
}

fn required_env(name: &str) -> Result<String, String> {
    std::env::var(name)
        .ok()
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty())
        .ok_or_else(|| format!("{name} must be set"))
}

#[derive(Clone)]
pub struct Session {
    /// Supabase subject from the pinned `fiducia-admin` provider project. Local
    /// operator-registry joins use this value, never the Shared Auth principal id.
    pub user_id: String,
    pub email: Option<String>,
    pub is_admin: bool,
    credential_binding: String,
    cookie_authenticated: bool,
}

impl Session {
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

/// Login verification result. `session_upgrade` is present only when the Shared
/// Auth exchange arm won and is the only token the login handler may persist.
pub struct VerifiedSession {
    pub session: Session,
    pub session_upgrade: Option<SessionUpgrade>,
}

/// Resolve the session for a request, or `None` if not signed in.
///
/// Explicit Authorization always wins and never downgrades to an ambient cookie.
/// Duplicate/malformed credentials fail closed. Existing Shared Auth cookies are
/// verified locally; legacy provider cookies may complete the dual race but are
/// never silently rewritten in a response-less request path.
pub async fn current(headers: &HeaderMap, shared_auth_base: &str) -> Option<Session> {
    let guard = match configured_guard(shared_auth_base) {
        Ok(guard) => guard,
        Err(error) => {
            tracing::error!(%error, "admin Shared Auth guard is unavailable");
            return None;
        }
    };
    if let Some(token) = authorization_token(headers) {
        return from_token(guard, &token, false)
            .await
            .map(|verified| verified.session);
    }
    if headers.contains_key("authorization") {
        return None;
    }
    if let Some(token) = session_cookie(headers) {
        return from_token(guard, &token, true)
            .await
            .map(|verified| verified.session);
    }
    if cookie_name_present(headers, ADMIN_SESSION_COOKIE) {
        return None;
    }
    dev_session()
}

/// Verify a login-time provider bearer and retain a successful Shared Auth
/// session upgrade. The caller must refuse login when the upgrade is absent.
pub async fn from_bearer(shared_auth_base: &str, token: &str) -> Option<VerifiedSession> {
    let guard = configured_guard(shared_auth_base).ok()?;
    from_token(guard, token, false).await
}

async fn from_token(
    guard: &Guard,
    token: &str,
    cookie_authenticated: bool,
) -> Option<VerifiedSession> {
    let decision = guard.authorize(Some(token)).await;
    match decision.outcome {
        Outcome::Authenticated { identity, .. } => {
            let session = session_from_identity(identity.as_ref(), token, cookie_authenticated)?;
            Some(VerifiedSession {
                session,
                session_upgrade: decision.session_upgrade,
            })
        }
        Outcome::Forbidden => {
            tracing::debug!(
                policy = "shared_auth_admin_role",
                "Shared Auth identity lacks an admin role"
            );
            None
        }
        Outcome::Degraded { reason } => {
            tracing::warn!(reason, "Shared Auth admin role authority is unavailable");
            None
        }
        Outcome::Anonymous | Outcome::Unauthenticated => None,
    }
}

fn session_from_identity(
    identity: &Identity,
    token: &str,
    cookie_authenticated: bool,
) -> Option<Session> {
    let is_admin = identity
        .roles
        .iter()
        .any(|role| matches!(role.as_str(), "admin" | "operator"));
    if !is_admin || identity.project != "fiducia-admin" {
        return None;
    }
    let credential_kind = if cookie_authenticated {
        "cookie"
    } else {
        "authorization"
    };
    Some(Session {
        user_id: identity.supabase_user_id.clone(),
        email: identity.email.clone(),
        is_admin,
        credential_binding: format!("{credential_kind}\0{token}"),
        cookie_authenticated,
    })
}

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

fn authorization_token(headers: &HeaderMap) -> Option<String> {
    let mut values = headers.get_all("authorization").iter();
    let value = values.next()?.to_str().ok()?;
    if values.next().is_some() {
        return None;
    }
    value
        .strip_prefix("Bearer ")
        .map(str::trim)
        .filter(|token| !token.is_empty() && token.len() <= 16 * 1024)
        .map(str::to_string)
}

#[cfg(test)]
mod tests {
    use super::*;
    use fiducia_shared_auth_guard::Authority;

    fn headers_with(name: &str, value: &str) -> HeaderMap {
        let mut headers = HeaderMap::new();
        headers.insert(
            axum::http::HeaderName::from_bytes(name.as_bytes()).unwrap(),
            value.parse().unwrap(),
        );
        headers
    }

    fn identity(project: &str, roles: &[&str]) -> Identity {
        Identity {
            shared_user_id: "shared-user".to_string(),
            provider: "supabase".to_string(),
            provider_tenant: project.to_string(),
            provider_subject: "11111111-1111-4111-8111-111111111111".to_string(),
            project: project.to_string(),
            supabase_user_id: "11111111-1111-4111-8111-111111111111".to_string(),
            session_id: Some("22222222-2222-4222-8222-222222222222".to_string()),
            email: Some("operator@example.com".to_string()),
            email_verified: true,
            roles: roles.iter().map(|role| (*role).to_string()).collect(),
            authority: Authority::SharedAuth,
        }
    }

    #[test]
    fn admin_identity_maps_to_provider_subject_and_redacts_credential() {
        let session = session_from_identity(
            &identity("fiducia-admin", &["operator"]),
            "secret-token",
            true,
        )
        .unwrap();
        assert_eq!(session.user_id, "11111111-1111-4111-8111-111111111111");
        assert!(session.is_admin);
        assert!(session.is_browser_session());
        let debug = format!("{session:?}");
        assert!(debug.contains("[redacted]"));
        assert!(!debug.contains("secret-token"));
    }

    #[test]
    fn customer_or_wrong_project_identity_cannot_create_admin_session() {
        assert!(
            session_from_identity(&identity("fiducia-admin", &["customer"]), "token", false,)
                .is_none()
        );
        assert!(
            session_from_identity(&identity("fiducia-customer", &["admin"]), "token", false,)
                .is_none()
        );
    }

    #[test]
    fn authorization_token_reads_one_bounded_bearer() {
        let headers = headers_with("authorization", "Bearer abc.def");
        assert_eq!(authorization_token(&headers).as_deref(), Some("abc.def"));
    }

    #[test]
    fn duplicate_authorization_headers_are_rejected() {
        let mut headers = HeaderMap::new();
        headers.append("authorization", "Bearer first".parse().unwrap());
        headers.append("authorization", "Bearer second".parse().unwrap());
        assert!(authorization_token(&headers).is_none());
    }

    #[test]
    fn duplicate_admin_cookies_are_rejected() {
        let headers = headers_with(
            "cookie",
            &format!("{ADMIN_SESSION_COOKIE}=first; {ADMIN_SESSION_COOKIE}=second"),
        );
        assert!(session_cookie(&headers).is_none());
        assert!(cookie_name_present(&headers, ADMIN_SESSION_COOKIE));
    }

    #[test]
    fn release_cookie_names_are_host_prefixed() {
        assert_eq!(
            admin_session_cookie_name(true),
            "__Host-fiducia_admin_session"
        );
        assert_eq!(
            login_csrf_cookie_name(true),
            "__Host-fiducia_admin_login_csrf"
        );
    }
}
