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
pub fn page(
    title: &str,
    session: Option<&Session>,
    csrf_token: Option<&str>,
    body: Markup,
) -> Markup {
    html! {
        (DOCTYPE)
        html lang="en" {
            head {
                meta charset="utf-8";
                meta name="viewport" content="width=device-width,initial-scale=1";
                @if let Some(csrf_token) = csrf_token {
                    meta name="fiducia-admin-csrf" content=(csrf_token);
                }
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
                    @if session.is_some() {
                        a href="/" { "Dashboard" }
                        a href="/infra" { "Infra" }
                    } @else {
                        a href="/login" { "Sign in" }
                    }
                    span class="sp" {}
                    @if let Some(s) = session {
                        span class="who" {
                            (ident(s))
                            " · operator"
                        }
                        @if let Some(csrf_token) = csrf_token {
                            form method="post" action="/logout" style="margin:0" {
                                input type="hidden" name="csrf_token" value=(csrf_token);
                                button class="btn btn--ghost" type="submit" { "Sign out" }
                            }
                        }
                    }
                }
                div class="wrap" { (body) }
                // Bring up admin-plane sync only on pages that declare synced
                // tables via `data-fiducia-sync` (deferred scripts above have run
                // by DOMContentLoaded, so window.FiduciaSyncAdmin + htmx exist).
                script { (PreEscaped(SYNC_INIT_JS)) }
            }
        }
    }
}

/// Gated bring-up: reads `data-fiducia-sync="table[,table]"` markers on the page
/// and, if any, boots the vendored @fiducia/sync admin client for those tables
/// (opening IndexedDB, subscribing /admin/ws, registering the htmx-optimistic ext).
const SYNC_INIT_JS: &str = r#"
window.addEventListener("DOMContentLoaded", function () {
  var nodes = document.querySelectorAll("[data-fiducia-sync]");
  if (!nodes.length || !window.FiduciaSyncAdmin) return;
  var tables = [];
  nodes.forEach(function (n) {
    (n.getAttribute("data-fiducia-sync") || "").split(",").forEach(function (t) {
      t = t.trim(); if (t && tables.indexOf(t) === -1) tables.push(t);
    });
  });
  if (!tables.length) return;
  var csrf = document.querySelector('meta[name="fiducia-admin-csrf"]');
  window.FiduciaSyncAdmin.init({
    tables: tables,
    htmx: window.htmx,
    csrfToken: csrf ? csrf.content : ""
  }).then(function (sync) {
    window.__fiduciaSync = sync; // exposed for debugging / future optimistic writes
  }).catch(function (e) { console.error("fiducia-sync init failed", e); });
});
"#;

/// 403 body for the admin gate (`require_admin`).
pub fn forbidden(s: &Session, csrf_token: Option<&str>) -> Markup {
    // A failed login has a verified bearer identity but no browser session
    // cookie, so it must not render a logout form that cannot authenticate.
    let navigation_session = csrf_token.map(|_| s);
    page(
        "Forbidden",
        navigation_session,
        csrf_token,
        html! {
            h1 { "403" }
            p class="muted" { "Admin role required." }
        },
    )
}

pub fn login(message: Option<&str>, login_csrf_token: &str) -> Markup {
    page(
        "Sign in",
        None,
        None,
        html! {
            h1 { "Sign in" }
            div class="card" {
                p class="muted" {
                    "Authenticate with an operator Supabase account. " code { "fiducia-auth" }
                    " verifies the session and trusted operator role before an admin cookie is issued."
                }
                form method="post" action="/login" {
                    input type="hidden" name="csrf_token" value=(login_csrf_token);
                    label { "Email" }
                    input name="email" type="email" autocomplete="username" required;
                    label { "Password" }
                    input name="password" type="password" autocomplete="current-password" required;
                    button class="btn" { "Sign in" }
                }
                @if let Some(message) = message {
                    p class="muted" role="alert" { (message) }
                }
                // The dev-bypass hint only exists where the bypass itself does:
                // debug builds. Release builds render no trace of it.
                @if cfg!(debug_assertions) {
                    p class="muted" {
                        "For local development, " code { "FIDUCIA_ADMIN_DEV_SESSION=admin" }
                        " still enables the explicit dev bypass."
                    }
                }
            }
        },
    )
}

pub fn dashboard(s: &Session, csrf_token: &str) -> Markup {
    page(
        "Dashboard",
        Some(s),
        Some(csrf_token),
        html! {
            h1 { "Dashboard" }
            div class="card" {
                h2 { "Welcome" }
                p class="muted" {
                    "Signed in as operator " b { (ident(s)) } "."
                }
                p { a href="/infra" { "Cluster & infra ops →" } }
            }
        },
    )
}

// ---- Infra ------------------------------------------------------------------

fn scale_form(csrf_token: &str) -> Markup {
    html! {
        form method="post" action="/infra/scale"
            hx-post="/infra/scale" hx-target="#infra-panel" hx-swap="innerHTML"
            style="display:flex;gap:.6rem;align-items:center" {
            input type="hidden" name="csrf_token" value=(csrf_token);
            label class="muted" { "Target nodes" }
            input name="target_nodes" type="number" min="3" value="9" style="width:6rem";
            button class="btn" type="submit" { "Apply" }
        }
    }
}

pub fn infra(
    s: &Session,
    csrf_token: &str,
    nodes: &[Value],
    placement: &[Value],
    recent: &[Value],
) -> Markup {
    page(
        "Infra",
        Some(s),
        Some(csrf_token),
        // `data-fiducia-sync` opts this page into the local-first sync client:
        // infra_operations changes stream over /admin/ws into IndexedDB.
        html! {
            div data-fiducia-sync="infra_operations" {
            h1 { "Cluster & infra" }
            div class="card" {
                h2 { "Scale" }
                (scale_form(csrf_token))
                p class="muted" {
                    "Drives " code { "fiducia-brain" } " " code { "POST /v1/scale" } " (admin only)."
                }
            }
            // htmx swap target: the scale handler returns `infra_panel`.
            div id="infra-panel" { (infra_panel(nodes, placement, recent, None)) }
            }
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
        Session::test_admin("u")
    }

    #[test]
    fn dashboard_keeps_welcome_and_infra_link_for_admin() {
        let admin = user();
        let html = dashboard(&admin, "csrf-test-token").into_string();
        assert!(html.contains("Dashboard"));
        assert!(html.contains("Welcome"));
        assert!(html.contains(r#"href="/infra""#));
    }

    #[test]
    fn login_collects_credentials_without_exposing_token_paste() {
        let html = login(Some("Invalid email or password."), "login-csrf-token").into_string();
        assert!(html.contains(r#"name="email""#));
        assert!(html.contains(r#"name="password""#));
        assert!(html.contains("Invalid email or password."));
        assert!(html.contains(r#"name="csrf_token""#));
        assert!(html.contains(r#"value="login-csrf-token""#));
        assert!(!html.contains(r#"name="token""#));
        assert!(!html.contains("access token"));
    }

    #[test]
    fn infra_renders_scale_controls_and_recent_ops_when_present() {
        let admin = user();
        let recent = vec![json!({
            "action": "scale",
            "target_nodes": 9,
            "status": "requested",
            "version": 1,
            "created_at": "2026-07-08T00:00:00Z",
        })];
        let html = infra(&admin, "csrf-test-token", &[], &[], &recent).into_string();
        assert!(html.contains("Cluster &amp; infra"));
        assert!(html.contains("Scale"));
        assert!(html.contains(r#"name="target_nodes""#));
        assert!(html.contains(r#"name="csrf_token""#));
        assert!(html.contains("Apply"));
        assert!(html.contains("Recent operations"));
        // Opts the page into the local-first sync client + loads the vendored bundle.
        assert!(html.contains(r#"data-fiducia-sync="infra_operations""#));
        assert!(html.contains(r#"src="/assets/fiducia-sync.js""#));
    }
}
