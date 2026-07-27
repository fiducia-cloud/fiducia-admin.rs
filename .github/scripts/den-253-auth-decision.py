from pathlib import Path

path = Path("src/session.rs")
source = path.read_text()

context_anchor = '''struct AuthorizationContext {
    version: u16,
    #[serde(default)]
    surface_audiences: Vec<String>,
    #[serde(default)]
    roles: Vec<String>,
    #[serde(default)]
    capabilities: Vec<String>,
}
'''
context_replacement = context_anchor + '''
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum AdminAuthorizationDecision {
    Authorized,
    AuthenticatedNonAdmin,
    Invalid,
}
'''

old_policy = '''fn session_from_user(user: AuthUser, token: &str, cookie_authenticated: bool) -> Option<Session> {
    if !authorization_allows_admin(&user.authorization) {
        return None;
    }

    let credential_kind = if cookie_authenticated {
        "cookie"
    } else {
        "authorization"
    };
    Some(Session {
        user_id: user.user_id,
        email: user.email,
        is_admin: true,
        credential_binding: format!("{credential_kind}\\0{token}"),
        cookie_authenticated,
    })
}

fn authorization_allows_admin(authorization: &AuthorizationContext) -> bool {
    if authorization.version != AUTHORIZATION_CONTEXT_VERSION
        || !unique_known_values(&authorization.surface_audiences, KNOWN_SURFACE_AUDIENCES)
        || !unique_known_values(&authorization.roles, KNOWN_ROLES)
        || !unique_known_values(&authorization.capabilities, KNOWN_CAPABILITIES)
        || !contains(&authorization.surface_audiences, ADMIN_SURFACE_AUDIENCE)
    {
        return false;
    }

    let is_admin = contains(&authorization.roles, "admin");
    let is_operator = contains(&authorization.roles, "operator");
    if !is_admin && !is_operator {
        return false;
    }

    let has_read = contains(&authorization.capabilities, "admin:read");
    let has_operate = contains(&authorization.capabilities, "admin:operate");
    let has_write = contains(&authorization.capabilities, "admin:write");
    has_read && has_operate && (!is_admin || has_write)
}

fn unique_known_values(values: &[String], known: &[&str]) -> bool {
'''
new_policy = '''fn session_from_user(user: AuthUser, token: &str, cookie_authenticated: bool) -> Option<Session> {
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
        credential_binding: format!("{credential_kind}\\0{token}"),
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
'''

old_test = '''    #[test]
    fn customer_or_raw_role_only_contexts_cannot_create_admin_sessions() {
        let customer = auth_user(
            &["admin"],
            authorization(
                1,
                &["fiducia-customer"],
                &["customer"],
                &["customer:self-service"],
            ),
        );
        assert!(session_from_user(customer, "token", false).is_none());

        let no_trusted_context = auth_user(&["admin", "operator"], authorization(1, &[], &[], &[]));
        assert!(session_from_user(no_trusted_context, "token", false).is_none());
    }
'''
new_test = '''    #[test]
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
'''

same_set_anchor = '''fn contains(values: &[String], expected: &str) -> bool {
    values.iter().any(|value| value == expected)
}
'''
same_set_replacement = '''fn same_set(values: &[String], expected: &[&str]) -> bool {
    values.len() == expected.len()
        && expected
            .iter()
            .all(|expected| values.iter().any(|value| value.as_str() == *expected))
}

''' + same_set_anchor

if "enum AdminAuthorizationDecision" in source:
    print("admin authorization decision already migrated")
    raise SystemExit(0)

for name, old in [
    ("authorization context", context_anchor),
    ("authorization policy", old_policy),
    ("customer session test", old_test),
    ("same_set anchor", same_set_anchor),
]:
    count = source.count(old)
    if count != 1:
        raise SystemExit(f"expected exactly one {name} anchor, found {count}")

source = source.replace(context_anchor, context_replacement)
source = source.replace(old_policy, new_policy)
source = source.replace(old_test, new_test)
source = source.replace(same_set_anchor, same_set_replacement)
path.write_text(source)
