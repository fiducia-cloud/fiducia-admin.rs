#!/usr/bin/env python3
"""Generate the reviewed admin Shared Auth runtime wiring in a read-only CI checkout.

This helper never writes Git refs. It edits the working tree only, checks every
source anchor for uniqueness, and is deleted after the generated files are
committed to the feature branch.
"""

from __future__ import annotations

from pathlib import Path

MAIN = Path("src/main.rs")
text = MAIN.read_text(encoding="utf-8")


def replace_once(old: str, new: str, description: str) -> None:
    global text
    count = text.count(old)
    if count != 1:
        raise SystemExit(f"{description}: expected one match, found {count}")
    text = text.replace(old, new, 1)


replace_once(
    "//! Auth is a Supabase session (verified through `fiducia-auth`). This is the\n",
    "//! Auth starts at the isolated ADMIN Supabase project and is upgraded through\n"
    "//! Shared Auth before any reusable browser session is persisted.\n",
    "module auth description",
)

# Keep the private AppState field name stable so existing router/unit fixtures do
# not churn. Its source and semantics change: it now contains SHARED_AUTH_URL,
# never the removed legacy FIDUCIA_AUTH_URL endpoint.
state_marker = "    let state = Arc::new(AppState {\n"
state_prefix = (
    "    let shared_auth_url = required_env(\"SHARED_AUTH_URL\")?;\n"
    "    session::initialize(&shared_auth_url).map_err(|error| {\n"
    "        io::Error::new(\n"
    "            io::ErrorKind::InvalidInput,\n"
    "            format!(\"invalid Shared Auth configuration: {error}\"),\n"
    "        )\n"
    "    })?;\n"
    "    let supabase_url = required_env(\"SUPABASE_URL\")?;\n"
    "    let supabase_publishable_key = required_env(\"SUPABASE_PUBLISHABLE_KEY\")?;\n"
    "\n"
    "    let state = Arc::new(AppState {\n"
)
replace_once(state_marker, state_prefix, "AppState initialization marker")
replace_once(
    "        auth_url: required_env(\"FIDUCIA_AUTH_URL\")?,\n",
    "        auth_url: shared_auth_url,\n",
    "legacy auth environment field",
)
replace_once(
    "        supabase_url: required_env(\"SUPABASE_URL\")?,\n",
    "        supabase_url,\n",
    "Supabase URL state field",
)
replace_once(
    "        supabase_publishable_key: required_env(\"SUPABASE_PUBLISHABLE_KEY\")?,\n",
    "        supabase_publishable_key,\n",
    "Supabase publishable-key state field",
)

login_start_marker = (
    "    let Some(session) = "
    "session::from_bearer(&st.auth_url, &password_session.access_token).await\n"
)
login_end_marker = (
    "    append_set_cookie(\n"
    "        &mut response,\n"
    "        &make_session_cookie(&password_session.access_token),\n"
    "    );\n"
)
start_count = text.count(login_start_marker)
end_count = text.count(login_end_marker)
if start_count != 1 or end_count != 1:
    raise SystemExit(
        "admin login block anchors did not match uniquely: "
        f"start={start_count}, end={end_count}"
    )
start = text.index(login_start_marker)
end = text.index(login_end_marker, start) + len(login_end_marker)
new_login = (
    "    let Some(verified) =\n"
    "        session::from_bearer(&st.auth_url, &password_session.access_token).await\n"
    "    else {\n"
    "        return login_page(\n"
    "            &st,\n"
    "            Some(\"Shared Auth could not authorize this admin identity.\"),\n"
    "        );\n"
    "    };\n"
    "    let session = verified.session;\n"
    "    let Some(session_upgrade) = verified.session_upgrade else {\n"
    "        return dependency_error(\n"
    "            \"shared_auth_session_upgrade_missing\",\n"
    "            \"Shared Auth authorized the provider token without issuing a reusable session\",\n"
    "        );\n"
    "    };\n"
    "    if !session.is_admin {\n"
    "        return (StatusCode::FORBIDDEN, views::forbidden(&session, None)).into_response();\n"
    "    }\n"
    "    match operator_is_enabled(&st, &session).await {\n"
    "        Ok(true) => {}\n"
    "        Ok(false) => {\n"
    "            return (StatusCode::FORBIDDEN, views::forbidden(&session, None)).into_response()\n"
    "        }\n"
    "        Err(error) => return dependency_error(\"operator_registry_unavailable\", error),\n"
    "    }\n"
    "\n"
    "    let mut response = redirect(\"/\");\n"
    "    append_set_cookie(\n"
    "        &mut response,\n"
    "        &make_session_cookie(session_upgrade.access_token()),\n"
    "    );\n"
)
text = text[:start] + new_login + text[end:]

if "FIDUCIA_AUTH_URL" in text:
    raise SystemExit("legacy FIDUCIA_AUTH_URL remains in src/main.rs")
if "make_session_cookie(&password_session.access_token)" in text:
    raise SystemExit("raw provider token would still be persisted")
if text.count("shared_auth_session_upgrade_missing") != 1:
    raise SystemExit("login no-upgrade fail-closed path is missing or duplicated")
if text.count('required_env("SHARED_AUTH_URL")') != 1:
    raise SystemExit("Shared Auth URL must be read exactly once during startup")

MAIN.write_text(text, encoding="utf-8")
