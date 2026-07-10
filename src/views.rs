//! Server-rendered HTML — the MASH stack's **M** (Maud).
//!
//! Maud is a compile-checked template macro that HTML-escapes every dynamic
//! interpolation *by construction*: any value spliced with `(value)` or `#{…}`
//! is escaped, so a key name like `<script>…` renders inert instead of executing
//! (stored XSS). This replaces the previous hand-rolled string templates + the
//! bespoke `esc()` helper — the escaping guarantee is now the framework's, not a
//! function we have to remember to call at every interpolation site.
//!
//! HTMX progressive enhancement: the create/revoke/scale forms carry both a plain
//! `method="post" action=…` (works with JS off) *and* `hx-post`/`hx-target` (swaps
//! a fragment in place with JS on). The handlers return either a redirect (no-JS)
//! or one of the fragment helpers here (HTMX), depending on the `HX-Request`
//! header — so the same routes serve both.

use maud::{html, Markup, PreEscaped, DOCTYPE};
use serde_json::Value;

use crate::session::Session;

const CSS: &str = r#"
:root{--bg:#0a1024;--panel:#121a36;--line:#243066;--ink:#e9ecf8;--dim:#9aa3c7;--grad:linear-gradient(135deg,#c084fc,#6366f1)}
*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--ink);font:15px/1.5 system-ui,sans-serif}
a{color:#c4b5fd;text-decoration:none}a:hover{text-decoration:underline}
.nav{display:flex;gap:1.2rem;align-items:center;padding:.9rem 1.4rem;border-bottom:1px solid var(--line);background:rgba(18,26,54,.6)}
.brand{font-weight:700}.brand b{background:var(--grad);-webkit-background-clip:text;background-clip:text;color:transparent}
.nav .sp{flex:1}.nav .who{color:var(--dim);font-size:.9rem}
.wrap{max-width:980px;margin:0 auto;padding:1.6rem 1.4rem}
.card{background:var(--panel);border:1px solid var(--line);border-radius:14px;padding:1.2rem 1.4rem;margin:1rem 0}
h1{font-size:1.5rem;margin:.2rem 0 1rem}h2{font-size:1.1rem;margin:.2rem 0 .8rem}
table{width:100%;border-collapse:collapse}th,td{text-align:left;padding:.5rem .6rem;border-bottom:1px solid var(--line)}
th{color:var(--dim);font-weight:600;font-size:.85rem}
.btn{display:inline-block;background:var(--grad);color:#fff;border:0;border-radius:9px;padding:.5rem .9rem;font:inherit;cursor:pointer}
.btn--ghost{background:transparent;border:1px solid var(--line);color:var(--ink)}
input,select{background:#0c1330;border:1px solid var(--line);color:var(--ink);border-radius:8px;padding:.5rem .6rem;font:inherit}
.muted{color:var(--dim)}.tag{font-size:.75rem;color:var(--dim);border:1px solid var(--line);border-radius:6px;padding:.05rem .4rem}
"#;

/// The signed-in identity label (email, else the user id).
fn ident(s: &Session) -> String {
    s.email.clone().unwrap_or_else(|| s.user_id.clone())
}

/// Wrap a page body in the shared layout + nav. Loads the vendored, same-origin
/// htmx bundle (served by the app at `/assets/htmx.min.js` — no CDN, works
/// offline in the E2E) so the `hx-*` attributes activate.
pub fn page(title: &str, session: Option<&Session>, body: Markup) -> Markup {
    html! {
        (DOCTYPE)
        html lang="en" {
            head {
                meta charset="utf-8";
                meta name="viewport" content="width=device-width,initial-scale=1";
                title { (title) " · Fiducia Admin" }
                style { (PreEscaped(CSS)) }
                script src="/assets/htmx.min.js" defer {}
                // Local-first sync client (@fiducia/sync), vendored self-contained
                // (wasm inlined) and served same-origin — no CDN, no bundler.
                script src="/assets/fiducia-sync.js" defer {}
            }
            body {
                nav class="nav" {
                    span class="brand" { "Fiducia" b { ".admin" } }
                    @if let Some(s) = session {
                        a href="/" { "Dashboard" }
                        a href="/keys" { "API keys" }
                        a href="/account" { "Account" }
                        @if s.is_admin { a href="/infra" { "Infra" } }
                    } @else {
                        a href="/login" { "Sign in" }
                    }
                    span class="sp" {}
                    @if let Some(s) = session {
                        span class="who" {
                            (ident(s))
                            @if s.is_admin { " · admin" }
                        }
                    }
                }
                div class="wrap" { (body) }
            }
        }
    }
}

/// 403 body for the admin gate (`require_admin`).
pub fn forbidden(s: &Session) -> Markup {
    page(
        "Forbidden",
        Some(s),
        html! {
            h1 { "403" }
            p class="muted" { "Admin role required." }
        },
    )
}

pub fn login() -> Markup {
    page(
        "Sign in",
        None,
        html! {
            h1 { "Sign in" }
            div class="card" {
                p class="muted" {
                    "Authenticate with your Supabase account. The dashboard verifies the "
                    "session via " code { "fiducia-auth" } "."
                }
                form method="post" action="/login" {
                    label { "Supabase access token" }
                    input name="token" type="password" autocomplete="current-password" required;
                    button class="btn" { "Sign in" }
                }
                p class="muted" {
                    "For local development, " code { "FIDUCIA_ADMIN_DEV_SESSION=admin" }
                    " still enables the explicit dev bypass."
                }
            }
        },
    )
}

pub fn dashboard(s: &Session) -> Markup {
    page(
        "Dashboard",
        Some(s),
        html! {
            h1 { "Dashboard" }
            div class="card" {
                h2 { "Welcome" }
                p class="muted" {
                    "Signed in as " b { (ident(s)) } ". Orgs: " (s.orgs.join(", ")) "."
                }
                p { a href="/keys" { "Manage API keys →" } }
                @if s.is_admin {
                    p { a href="/infra" { "Cluster & infra ops →" } }
                }
            }
        },
    )
}

pub fn account(s: &Session) -> Markup {
    page(
        "Account",
        Some(s),
        html! {
            h1 { "Account" }
            div class="card" {
                h2 { "Organization & members" }
                p class="muted" {
                    "Identity and organization membership come from the verified session."
                }
                @if s.orgs.is_empty() {
                    p class="muted" { "No organizations are attached to this session." }
                } @else {
                    ul {
                        @for org in &s.orgs { li { (org) } }
                    }
                }
            }
        },
    )
}

// ---- API keys ---------------------------------------------------------------

const SCOPE_OPTIONS: &[&str] = &[
    "requests:write",
    "locks:write",
    "kv:read",
    "kv:write",
    "services:read",
    "services:write",
    "elections:write",
    "cron:write",
    "rate-limit:write",
];

/// The create-key form. Doubles as a no-JS `POST /keys` and, with htmx, swaps the
/// refreshed keys panel in place (`#keys-panel`).
fn create_key_form() -> Markup {
    html! {
        form method="post" action="/keys"
            hx-post="/keys" hx-target="#keys-panel" hx-swap="innerHTML"
            style="display:flex;gap:.6rem;flex-wrap:wrap" {
            input name="name" placeholder="key name (e.g. prod-checkout)" required;
            select name="scope" aria-label="Scope" {
                @for scope in SCOPE_OPTIONS {
                    option value=(scope) { (scope) }
                }
            }
            select name="env" aria-label="Environment" {
                option value="live" { "live" }
                option value="test" { "test" }
            }
            button class="btn" type="submit" { "Create" }
        }
    }
}

pub fn keys(s: &Session, keys: &[Value]) -> Markup {
    page(
        "API keys",
        Some(s),
        html! {
            h1 { "API keys" }
            div class="card" {
                h2 { "Create a key" }
                (create_key_form())
                p class="muted" { "The raw key is shown once on creation. Only its hash is stored." }
            }
            // htmx swap target: the create/revoke handlers return `keys_panel`.
            div id="keys-panel" { (keys_panel(keys, None)) }
        },
    )
}

fn key_scopes(k: &Value) -> String {
    k.get("scopes")
        .and_then(Value::as_array)
        .map(|values| {
            values
                .iter()
                .filter_map(Value::as_str)
                .collect::<Vec<_>>()
                .join(", ")
        })
        .unwrap_or_else(|| "—".to_string())
}

fn key_row(k: &Value) -> Markup {
    let key_id = k.get("key_id").and_then(Value::as_str).unwrap_or("");
    html! {
        tr {
            td { (k.get("name").and_then(Value::as_str).unwrap_or("—")) }
            td { span class="tag" { (k.get("env").and_then(Value::as_str).unwrap_or("live")) } }
            td class="muted" { (if key_id.is_empty() { "—" } else { key_id }) }
            td class="muted" { (key_scopes(k)) }
            td {
                form method="post" action=(format!("/keys/{key_id}/revoke"))
                    hx-post=(format!("/keys/{key_id}/revoke")) hx-target="#keys-panel" hx-swap="innerHTML" {
                    button class="btn btn--ghost" { "Revoke" }
                }
            }
        }
    }
}

/// The "Your keys" panel — an optional status banner (after a create/revoke)
/// followed by the keys table. This is the htmx fragment the mutating handlers
/// return, and it is also embedded on the full page.
pub fn keys_panel(keys: &[Value], status: Option<Markup>) -> Markup {
    html! {
        @if let Some(status) = status { (status) }
        div class="card" {
            h2 { "Your keys" }
            table {
                tr { th { "Name" } th { "Env" } th { "Key ID" } th { "Scopes" } th {} }
                @if keys.is_empty() {
                    tr { td colspan="5" class="muted" {
                        "No keys yet — create one above. (Live data comes from fiducia-auth.)"
                    } }
                } @else {
                    @for k in keys { (key_row(k)) }
                }
            }
        }
    }
}

/// Fragment returned after a create. `created` is the upstream `fiducia-auth`
/// response; when it carries a one-time raw secret we surface it, otherwise we
/// confirm the submission (the E2E / dev path has no upstream to mint a secret).
pub fn keys_after_create(name: &str, created: &Value, keys: &[Value]) -> Markup {
    let secret = ["key", "secret", "raw", "token", "api_key"]
        .iter()
        .find_map(|f| created.get(*f).and_then(Value::as_str));
    let status = html! {
        div class="card" data-keys-status="" {
            @match secret {
                Some(sec) => {
                    p { "Key " b { (name) } " created. Store this secret now — it is shown once:" }
                    p { code { (sec) } }
                }
                None => {
                    p { "Key " b { (name) } " submitted." }
                }
            }
        }
    };
    keys_panel(keys, Some(status))
}

/// Fragment returned after a revoke.
pub fn keys_after_revoke(revoked: bool, keys: &[Value]) -> Markup {
    let status = html! {
        div class="card" data-keys-status="" {
            p { (if revoked { "Key revoked." } else { "Revoke request submitted." }) }
        }
    };
    keys_panel(keys, Some(status))
}

// ---- Infra ------------------------------------------------------------------

fn scale_form() -> Markup {
    html! {
        form method="post" action="/infra/scale"
            hx-post="/infra/scale" hx-target="#infra-panel" hx-swap="innerHTML"
            style="display:flex;gap:.6rem;align-items:center" {
            label class="muted" { "Target nodes" }
            input name="target_nodes" type="number" min="3" value="9" style="width:6rem";
            button class="btn" type="submit" { "Apply" }
        }
    }
}

pub fn infra(s: &Session, nodes: &[Value], placement: &[Value], recent: &[Value]) -> Markup {
    page(
        "Infra",
        Some(s),
        html! {
            h1 { "Cluster & infra" }
            div class="card" {
                h2 { "Scale" }
                (scale_form())
                p class="muted" {
                    "Drives " code { "fiducia-brain" } " " code { "POST /v1/scale" } " (admin only)."
                }
            }
            // htmx swap target: the scale handler returns `infra_panel`.
            div id="infra-panel" { (infra_panel(nodes, placement, recent, None)) }
        },
    )
}

fn op_when(op: &Value) -> String {
    op.get("created_at")
        .and_then(Value::as_str)
        .unwrap_or("—")
        .to_string()
}

/// The infra status panel — an optional "scale requested" banner, the node /
/// placement counts, and (when the admin DB is wired, P2) the recent operations
/// audit list. htmx fragment for the scale handler; also embedded on the page.
pub fn infra_panel(
    nodes: &[Value],
    placement: &[Value],
    recent: &[Value],
    applied: Option<u32>,
) -> Markup {
    html! {
        @if let Some(n) = applied {
            div class="card" data-scale-status="" {
                p { "Scale to " b { (n) } " nodes requested." }
            }
        }
        div class="card" {
            h2 { "Nodes" }
            p class="muted" { (nodes.len()) " known (live from fiducia-brain /v1/nodes)." }
        }
        div class="card" {
            h2 { "Shard placement" }
            p class="muted" { (placement.len()) " shards mapped (fiducia-brain /v1/placement)." }
        }
        @if !recent.is_empty() {
            div class="card" {
                h2 { "Recent operations" }
                table {
                    tr { th { "Action" } th { "Target nodes" } th { "Status" } th { "Version" } th { "When" } }
                    @for op in recent {
                        tr {
                            td { (op.get("action").and_then(Value::as_str).unwrap_or("—")) }
                            td { (op.get("target_nodes").and_then(Value::as_i64).map(|n| n.to_string()).unwrap_or_else(|| "—".into())) }
                            td { span class="tag" { (op.get("status").and_then(Value::as_str).unwrap_or("—")) } }
                            td class="muted" { (op.get("version").and_then(Value::as_i64).unwrap_or_default()) }
                            td class="muted" { (op_when(op)) }
                        }
                    }
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn user() -> Session {
        Session {
            user_id: "u".into(),
            email: Some("a@b.c".into()),
            orgs: vec!["org".into()],
            is_admin: false,
            bearer_token: None,
        }
    }

    // The MASH "M" auto-escapes every interpolation, so a hostile key name must
    // render inert (the old esc()-based guarantee, now enforced by Maud).
    #[test]
    fn key_names_are_escaped_in_the_table() {
        let key_list = vec![json!({
            "name": "<script>alert(1)</script>",
            "env": "live",
            "key_id": "abc123",
        })];
        let html = keys(&user(), &key_list).into_string();
        assert!(
            !html.contains("<script>alert(1)</script>"),
            "raw payload leaked"
        );
        assert!(html.contains("&lt;script&gt;alert(1)&lt;/script&gt;"));
    }

    // A hostile key name routed through the htmx create fragment must also be
    // escaped — the fragment path skips the full page but not Maud's escaping.
    #[test]
    fn create_fragment_escapes_key_name() {
        let html = keys_after_create("<img src=x onerror=alert(1)>", &json!({}), &[]).into_string();
        assert!(!html.contains("<img src=x onerror=alert(1)>"));
        assert!(html.contains("&lt;img src=x onerror=alert(1)&gt;"));
    }

    #[test]
    fn dashboard_keeps_welcome_and_infra_link_for_admin() {
        let mut admin = user();
        admin.is_admin = true;
        let html = dashboard(&admin).into_string();
        assert!(html.contains("Dashboard"));
        assert!(html.contains("Welcome"));
        assert!(html.contains(r#"href="/infra""#));
    }

    #[test]
    fn infra_renders_scale_controls_and_recent_ops_when_present() {
        let mut admin = user();
        admin.is_admin = true;
        let recent = vec![json!({
            "action": "scale",
            "target_nodes": 9,
            "status": "requested",
            "version": 1,
            "created_at": "2026-07-08T00:00:00Z",
        })];
        let html = infra(&admin, &[], &[], &recent).into_string();
        assert!(html.contains("Cluster &amp; infra"));
        assert!(html.contains("Scale"));
        assert!(html.contains(r#"name="target_nodes""#));
        assert!(html.contains("Apply"));
        assert!(html.contains("Recent operations"));
    }
}
