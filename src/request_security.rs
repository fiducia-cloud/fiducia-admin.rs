//! Exact-origin request checks and stateless, credential-bound CSRF tokens.
//!
//! `SameSite=Strict` is not a complete boundary for the admin app: sibling
//! `*.fiducia.cloud` hosts are same-site. Cookie-authenticated mutations and the
//! WebSocket handshake therefore require the configured admin Host + Origin.

use std::{env, io};

use axum::http::{header::HOST, HeaderMap};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use hmac::{Hmac, Mac};
use sha2::Sha256;

const ORIGIN: &str = "origin";
const SEC_FETCH_SITE: &str = "sec-fetch-site";
const MIN_CSRF_SECRET_BYTES: usize = 32;

type HmacSha256 = Hmac<Sha256>;

#[derive(Clone)]
pub struct RequestSecurity {
    expected_origin: String,
    expected_host: String,
    csrf_secret: Vec<u8>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RequestSecurityError {
    AmbiguousHost,
    AmbiguousOrigin,
    InvalidCsrfToken,
    MissingHost,
    MissingOrigin,
    MismatchedHost,
    MismatchedOrigin,
    CrossSiteFetch,
}

impl RequestSecurityError {
    pub const fn code(self) -> &'static str {
        match self {
            Self::AmbiguousHost => "ambiguous_host",
            Self::AmbiguousOrigin => "ambiguous_origin",
            Self::InvalidCsrfToken => "invalid_csrf_token",
            Self::MissingHost => "missing_host",
            Self::MissingOrigin => "missing_origin",
            Self::MismatchedHost => "mismatched_host",
            Self::MismatchedOrigin => "mismatched_origin",
            Self::CrossSiteFetch => "cross_site_fetch",
        }
    }
}

impl RequestSecurity {
    /// Load the canonical admin origin and CSRF signing key.
    ///
    /// Release builds fail closed when either value is absent. Debug builds use
    /// an exact loopback origin and a loudly logged development-only key so local
    /// `FIDUCIA_ADMIN_DEV_SESSION=admin` remains usable.
    pub fn from_env(port: u16) -> Result<Self, io::Error> {
        let origin = match env::var("FIDUCIA_ADMIN_ORIGIN")
            .ok()
            .filter(|value| !value.trim().is_empty())
        {
            Some(origin) => origin,
            None if cfg!(debug_assertions) => {
                let origin = format!("http://127.0.0.1:{port}");
                tracing::warn!(%origin, "FIDUCIA_ADMIN_ORIGIN unset; using debug-only loopback origin");
                origin
            }
            None => return Err(invalid_input("FIDUCIA_ADMIN_ORIGIN must be set")),
        };
        let csrf_secret = match env::var("FIDUCIA_ADMIN_CSRF_SECRET")
            .ok()
            .filter(|value| !value.trim().is_empty())
        {
            Some(secret) => secret.into_bytes(),
            None if cfg!(debug_assertions) => {
                tracing::warn!("FIDUCIA_ADMIN_CSRF_SECRET unset; using a debug-only CSRF key");
                b"fiducia-admin-debug-only-csrf-key-never-production".to_vec()
            }
            None => return Err(invalid_input("FIDUCIA_ADMIN_CSRF_SECRET must be set")),
        };
        let security = Self::new(&origin, csrf_secret)?;
        if !cfg!(debug_assertions) && !security.expected_origin.starts_with("https://") {
            return Err(invalid_input(
                "FIDUCIA_ADMIN_ORIGIN must use https in release builds",
            ));
        }
        Ok(security)
    }

    pub fn new(origin: &str, csrf_secret: Vec<u8>) -> Result<Self, io::Error> {
        if csrf_secret.len() < MIN_CSRF_SECRET_BYTES {
            return Err(invalid_input(
                "FIDUCIA_ADMIN_CSRF_SECRET must contain at least 32 bytes",
            ));
        }

        let parsed = reqwest::Url::parse(origin.trim())
            .map_err(|_| invalid_input("FIDUCIA_ADMIN_ORIGIN must be an absolute URL"))?;
        if !matches!(parsed.scheme(), "http" | "https")
            || parsed.host_str().is_none()
            || !parsed.username().is_empty()
            || parsed.password().is_some()
            || parsed.query().is_some()
            || parsed.fragment().is_some()
            || parsed.path() != "/"
        {
            return Err(invalid_input(
                "FIDUCIA_ADMIN_ORIGIN must contain only http(s) scheme and authority",
            ));
        }

        let host = parsed
            .host_str()
            .ok_or_else(|| invalid_input("FIDUCIA_ADMIN_ORIGIN must include a host"))?;
        let expected_host = match parsed.port() {
            Some(port) => format!("{host}:{port}"),
            None => host.to_string(),
        };
        let expected_origin = parsed.origin().ascii_serialization();

        Ok(Self {
            expected_origin,
            expected_host,
            csrf_secret,
        })
    }

    /// Require the exact configured request authority.
    pub fn require_host(&self, headers: &HeaderMap) -> Result<(), RequestSecurityError> {
        let mut hosts = headers.get_all(HOST).iter();
        let host = hosts
            .next()
            .and_then(|value| value.to_str().ok())
            .ok_or(RequestSecurityError::MissingHost)?;
        if hosts.next().is_some() {
            return Err(RequestSecurityError::AmbiguousHost);
        }
        if !host.eq_ignore_ascii_case(&self.expected_host) {
            return Err(RequestSecurityError::MismatchedHost);
        }
        Ok(())
    }

    /// Require a browser request to originate from the exact admin origin.
    /// `same-site` is intentionally rejected: sibling subdomains are not trusted.
    pub fn require_same_origin(&self, headers: &HeaderMap) -> Result<(), RequestSecurityError> {
        self.require_host(headers)?;
        let mut origins = headers.get_all(ORIGIN).iter();
        let origin = origins
            .next()
            .and_then(|value| value.to_str().ok())
            .ok_or(RequestSecurityError::MissingOrigin)?;
        if origins.next().is_some() {
            return Err(RequestSecurityError::AmbiguousOrigin);
        }
        if origin != self.expected_origin {
            return Err(RequestSecurityError::MismatchedOrigin);
        }
        if let Some(fetch_site) = headers
            .get(SEC_FETCH_SITE)
            .and_then(|value| value.to_str().ok())
        {
            if fetch_site != "same-origin" && fetch_site != "none" {
                return Err(RequestSecurityError::CrossSiteFetch);
            }
        }
        Ok(())
    }

    /// Validate an optional browser Origin on a bearer-authenticated API call.
    /// Non-browser clients may omit Origin, but never bypass the exact Host check.
    pub fn require_api_host(&self, headers: &HeaderMap) -> Result<(), RequestSecurityError> {
        self.require_host(headers)?;
        if headers.contains_key(ORIGIN) {
            self.require_same_origin(headers)?;
        } else if headers
            .get_all(SEC_FETCH_SITE)
            .iter()
            .filter_map(|value| value.to_str().ok())
            .any(|value| value != "same-origin" && value != "none")
        {
            return Err(RequestSecurityError::CrossSiteFetch);
        }
        Ok(())
    }

    pub fn csrf_token(&self, credential_binding: &str) -> String {
        let mut mac = HmacSha256::new_from_slice(&self.csrf_secret)
            .expect("HMAC accepts keys of any non-empty size");
        mac.update(b"fiducia-admin-csrf-v1\0");
        mac.update(credential_binding.as_bytes());
        URL_SAFE_NO_PAD.encode(mac.finalize().into_bytes())
    }

    pub fn verify_csrf_token(
        &self,
        credential_binding: &str,
        provided: &str,
    ) -> Result<(), RequestSecurityError> {
        let decoded = URL_SAFE_NO_PAD
            .decode(provided)
            .map_err(|_| RequestSecurityError::InvalidCsrfToken)?;
        let mut mac = HmacSha256::new_from_slice(&self.csrf_secret)
            .expect("HMAC accepts keys of any non-empty size");
        mac.update(b"fiducia-admin-csrf-v1\0");
        mac.update(credential_binding.as_bytes());
        mac.verify_slice(&decoded)
            .map_err(|_| RequestSecurityError::InvalidCsrfToken)
    }
}

fn invalid_input(message: &str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidInput, message)
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::http::HeaderValue;

    fn security() -> RequestSecurity {
        RequestSecurity::new(
            "https://admin.fiducia.cloud",
            b"0123456789abcdef0123456789abcdef".to_vec(),
        )
        .unwrap()
    }

    fn browser_headers(origin: &'static str) -> HeaderMap {
        let mut headers = HeaderMap::new();
        headers.insert(HOST, HeaderValue::from_static("admin.fiducia.cloud"));
        headers.insert(ORIGIN, HeaderValue::from_static(origin));
        headers.insert(SEC_FETCH_SITE, HeaderValue::from_static("same-origin"));
        headers
    }

    #[test]
    fn exact_admin_origin_is_accepted() {
        assert_eq!(
            security().require_same_origin(&browser_headers("https://admin.fiducia.cloud")),
            Ok(())
        );
    }

    #[test]
    fn sibling_origin_is_rejected_even_though_it_is_same_site() {
        assert_eq!(
            security().require_same_origin(&browser_headers("https://app.fiducia.cloud")),
            Err(RequestSecurityError::MismatchedOrigin)
        );
    }

    #[test]
    fn mismatched_host_is_rejected() {
        let mut headers = browser_headers("https://admin.fiducia.cloud");
        headers.insert(HOST, HeaderValue::from_static("app.fiducia.cloud"));
        assert_eq!(
            security().require_same_origin(&headers),
            Err(RequestSecurityError::MismatchedHost)
        );
    }

    #[test]
    fn same_site_fetch_metadata_is_not_treated_as_same_origin() {
        let mut headers = browser_headers("https://admin.fiducia.cloud");
        headers.insert(SEC_FETCH_SITE, HeaderValue::from_static("same-site"));
        assert_eq!(
            security().require_same_origin(&headers),
            Err(RequestSecurityError::CrossSiteFetch)
        );
    }

    #[test]
    fn csrf_token_is_bound_to_the_verified_credential() {
        let security = security();
        let token = security.csrf_token("cookie\0verified.jwt");
        assert_eq!(
            security.verify_csrf_token("cookie\0verified.jwt", &token),
            Ok(())
        );
        assert_eq!(
            security.verify_csrf_token("cookie\0other.jwt", &token),
            Err(RequestSecurityError::InvalidCsrfToken)
        );
    }

    #[test]
    fn configured_origin_rejects_paths_and_short_secrets() {
        assert!(RequestSecurity::new(
            "https://admin.fiducia.cloud/login",
            b"0123456789abcdef0123456789abcdef".to_vec()
        )
        .is_err());
        assert!(RequestSecurity::new("https://admin.fiducia.cloud", b"short".to_vec()).is_err());
    }

    #[test]
    fn duplicate_security_authorities_are_rejected() {
        let mut duplicate_origin = browser_headers("https://admin.fiducia.cloud");
        duplicate_origin.append(
            ORIGIN,
            HeaderValue::from_static("https://admin.fiducia.cloud"),
        );
        assert_eq!(
            security().require_same_origin(&duplicate_origin),
            Err(RequestSecurityError::AmbiguousOrigin)
        );

        let mut duplicate_host = browser_headers("https://admin.fiducia.cloud");
        duplicate_host.append(HOST, HeaderValue::from_static("admin.fiducia.cloud"));
        assert_eq!(
            security().require_same_origin(&duplicate_host),
            Err(RequestSecurityError::AmbiguousHost)
        );
    }

    #[test]
    fn ipv6_origins_preserve_brackets_in_the_expected_host() {
        let security = RequestSecurity::new(
            "http://[::1]:8096",
            b"0123456789abcdef0123456789abcdef".to_vec(),
        )
        .unwrap();
        let mut headers = HeaderMap::new();
        headers.insert(HOST, HeaderValue::from_static("[::1]:8096"));
        headers.insert(ORIGIN, HeaderValue::from_static("http://[::1]:8096"));
        assert_eq!(security.require_same_origin(&headers), Ok(()));
    }

    #[test]
    fn bearer_api_rejects_cross_site_fetch_metadata_without_origin() {
        let mut headers = HeaderMap::new();
        headers.insert(HOST, HeaderValue::from_static("admin.fiducia.cloud"));
        headers.insert(SEC_FETCH_SITE, HeaderValue::from_static("cross-site"));
        assert_eq!(
            security().require_api_host(&headers),
            Err(RequestSecurityError::CrossSiteFetch)
        );
    }
}
