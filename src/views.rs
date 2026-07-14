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

use crate::cluster_insight::{
    grafana_explore_loki_url, grafana_explore_prom_url, loki_events_logql, now_ms, relative_age,
    utc_timestamp, ClusterEvent, ClusterQuorum, MergedShard, NodeObservation, PromScrape,
    PROM_FIDUCIA_UP_QUERY,
};
use crate::entity::{admin_audit_log, admin_broadcast_notices};
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
.tag--ok{color:#6ee7b7;border-color:#166534}.tag--warn{color:#fcd34d;border-color:#854d0e}.tag--bad{color:#fca5a5;border-color:#991b1b}
.grid{display:grid;grid-template-columns:repeat(auto-fill,minmax(200px,1fr));gap:.8rem;margin:1rem 0}
.stat{background:var(--panel);border:1px solid var(--line);border-radius:14px;padding:.8rem 1rem}
.stat .n{font-size:1.35rem;font-weight:700}.stat .l{color:var(--dim);font-size:.8rem}
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
                        a href="/cluster" { "Cluster" }
                        a href="/notices" { "Notices" }
                        a href="/audit" { "Audit" }
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
                p { a href="/audit" { "Operator audit →" } }
            }
        },
    )
}

/// Minimal, read-only audit projection for an already-authorized operator.
/// `admin_audit_log.meta`, source IP, and user-agent fields are deliberately
/// omitted: detailed diagnostics stay in the database, not an HTML response.
pub fn audit(s: &Session, csrf_token: &str, events: &[admin_audit_log::Model]) -> Markup {
    page(
        "Audit",
        Some(s),
        Some(csrf_token),
        html! {
            h1 { "Operator audit" }
            div class="card" {
                p class="muted" {
                    "Read-only, append-only actions for the isolated admin plane. "
                    "Sensitive diagnostic fields remain server-side."
                }
                table {
                    thead {
                        tr {
                            th { "When" }
                            th { "Actor" }
                            th { "Action" }
                            th { "Target" }
                            th { "Request" }
                        }
                    }
                    tbody {
                        @if events.is_empty() {
                            tr { td colspan="5" class="muted" { "No audit events recorded yet." } }
                        } @else {
                            @for event in events {
                                tr {
                                    td { (event.created_at.to_rfc3339()) }
                                    td { (event.actor.as_deref().unwrap_or("system")) }
                                    td { code { (&event.action) } }
                                    td { (event.target.as_deref().unwrap_or("—")) }
                                    td { code { (event.request_id.as_deref().unwrap_or("—")) } }
                                }
                            }
                        }
                    }
                }
            }
        },
    )
}

/// Operator broadcast notices: the active/scheduled banner set plus a create
/// form. Operator-gated; `record_notice` writes an audit row alongside every
/// insert. Marked `data-fiducia-sync` so open consoles reconcile live.
pub fn notices(
    s: &Session,
    csrf_token: &str,
    notices: &[admin_broadcast_notices::Model],
    message: Option<&str>,
) -> Markup {
    page(
        "Notices",
        Some(s),
        Some(csrf_token),
        html! {
            h1 { "Broadcast notices" }
            div class="card" {
                p class="muted" {
                    "Operator-authored announcements shown across the admin console. "
                    "Every publish is recorded in the operator audit log."
                }
                (notice_form(csrf_token))
            }
            div id="notice-list" data-fiducia-sync="admin_broadcast_notices" {
                (notice_table(notices, message))
            }
        },
    )
}

fn notice_form(csrf_token: &str) -> Markup {
    html! {
        form method="post" action="/notices"
            hx-post="/notices" hx-target="#notice-list" hx-swap="innerHTML"
            style="display:grid;gap:.6rem;max-width:40rem;margin-top:.8rem" {
            input type="hidden" name="csrf_token" value=(csrf_token);
            label class="muted" for="notice-severity" { "Severity" }
            select id="notice-severity" name="severity" {
                option value="info" { "info" }
                option value="warning" { "warning" }
                option value="critical" { "critical" }
            }
            label class="muted" for="notice-title" { "Title" }
            input id="notice-title" name="title" type="text" maxlength="200" required;
            label class="muted" for="notice-body" { "Body" }
            textarea id="notice-body" name="body" rows="3" maxlength="2000" {}
            button class="btn" type="submit" { "Publish notice" }
        }
    }
}

/// Just the notice table — returned on its own from the HTMX create POST so the
/// list re-renders in place.
pub fn notice_table(notices: &[admin_broadcast_notices::Model], message: Option<&str>) -> Markup {
    html! {
        div class="card" {
            @if let Some(message) = message {
                p class="inline-message" role="status" { (message) }
            }
            table {
                thead {
                    tr {
                        th { "Published" }
                        th { "Severity" }
                        th { "Title" }
                        th { "State" }
                    }
                }
                tbody {
                    @if notices.is_empty() {
                        tr { td colspan="4" class="muted" { "No notices published yet." } }
                    } @else {
                        @for notice in notices {
                            tr {
                                td { (notice.starts_at.to_rfc3339()) }
                                td { code { (&notice.severity) } }
                                td {
                                    b { (&notice.title) }
                                    @if !notice.body.is_empty() { div class="muted" { (&notice.body) } }
                                }
                                td { @if notice.active { "active" } @else { "inactive" } }
                            }
                        }
                    }
                }
            }
        }
    }
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

// ---- Cluster insight ----------------------------------------------------------

/// The events panel's tri-state: Loki not configured, the query failed, or the
/// classified events. Unset observability config renders as information, never
/// as a page error.
pub enum EventsPanel {
    NotConfigured,
    Error(String),
    Events(Vec<ClusterEvent>),
}

fn status_str<'a>(status: &'a Value, path: &[&str]) -> &'a str {
    let mut value = status;
    for key in path {
        match value.get(key) {
            Some(inner) => value = inner,
            None => return "—",
        }
    }
    value.as_str().unwrap_or("—")
}

fn status_u64(status: &Value, path: &[&str]) -> u64 {
    let mut value = status;
    for key in path {
        match value.get(key) {
            Some(inner) => value = inner,
            None => return 0,
        }
    }
    value.as_u64().unwrap_or(0)
}

fn health_tag_class(health: &str) -> &'static str {
    match health {
        "healthy" => "tag tag--ok",
        "suspect" | "draining" => "tag tag--warn",
        "dead" => "tag tag--bad",
        _ => "tag",
    }
}

fn event_tag_class(kind: &str) -> &'static str {
    match kind {
        "node_dead" | "check_quorum_step_down" | "step_down" => "tag tag--bad",
        "election_won" | "node_registered" => "tag tag--ok",
        _ => "tag tag--warn",
    }
}

/// A count that reads green at zero and red above it, linking to the detail
/// anchor so every number on a summary card goes somewhere.
fn gap_count(label: &str, count: u64, href: &str) -> Markup {
    html! {
        a href=(href) {
            span class=(if count == 0 { "tag tag--ok" } else { "tag tag--bad" }) {
                (count) " " (label)
            }
        }
        " "
    }
}

/// The full `/cluster` page. The three volatile panels poll their fragment
/// endpoints via htmx (the same handlers serve this full page to non-htmx
/// requests, mirroring the infra pattern).
pub fn cluster(
    s: &Session,
    csrf_token: &str,
    status_panel: Markup,
    nodes_panel: Markup,
    events_panel: Markup,
) -> Markup {
    page(
        "Cluster",
        Some(s),
        Some(csrf_token),
        html! {
            h1 { "Cluster insight" }
            div id="cluster-status" hx-get="/cluster/shards" hx-trigger="every 5s"
                hx-swap="innerHTML" { (status_panel) }
            div id="cluster-nodes" hx-get="/cluster/nodes" hx-trigger="every 5s"
                hx-swap="innerHTML" { (nodes_panel) }
            div id="cluster-events" hx-get="/cluster/events" hx-trigger="every 15s"
                hx-swap="innerHTML" { (events_panel) }
        },
    )
}

/// Summary cards (brain `/v1/status` + the observe fan-out rollup) and the
/// merged per-shard table. htmx fragment for `/cluster/shards`.
pub fn cluster_status_panel(
    status: &Value,
    shards: &[MergedShard],
    quorum: &ClusterQuorum,
    prometheus: &PromScrape,
    grafana: Option<&str>,
) -> Markup {
    let nodes_by_health = status
        .get("topology")
        .and_then(|topology| topology.get("nodes_by_health"))
        .and_then(Value::as_object);
    html! {
        div class="grid" {
            div class="stat" {
                div class="n" { (status_str(status, &["cluster_id"])) }
                div class="l" { "cluster · brain v" (status_str(status, &["version"])) }
            }
            div class="stat" {
                div class="n" {
                    a href="#shard-table" {
                        (status_u64(status, &["shard_count"]))
                        " × RF" (status_u64(status, &["replication_factor"]))
                    }
                }
                div class="l" { "shards × replication factor" }
            }
            div class="stat" {
                div class="n" {
                    a href="/infra" { (status_u64(status, &["brain_cluster", "placement_generation"])) }
                }
                div class="l" { "placement generation" }
            }
            div class="stat" {
                div class="n" {
                    @if status.get("brain_cluster").and_then(|b| b.get("is_leader")).and_then(Value::as_bool) == Some(true) {
                        "this brain"
                    } @else {
                        (status_str(status, &["brain_cluster", "leader"]))
                    }
                }
                div class="l" {
                    "brain leader · "
                    @if status.get("brain_cluster").and_then(|b| b.get("ha_configured")).and_then(Value::as_bool) == Some(true) {
                        span class="tag tag--ok" { "HA" }
                    } @else {
                        span class="tag tag--warn" { "no HA" }
                    }
                    " "
                    @if status.get("brain_cluster").and_then(|b| b.get("available")).and_then(Value::as_bool) == Some(true) {
                        span class="tag tag--ok" { "available" }
                    } @else {
                        span class="tag tag--bad" { "unavailable" }
                    }
                }
            }
            div class="stat" {
                div class="n" {
                    @if let Some(by_health) = nodes_by_health {
                        @for (health, count) in by_health {
                            a href="#node-table" {
                                span class=(health_tag_class(health)) {
                                    (count.as_u64().unwrap_or(0)) " " (health)
                                }
                            }
                            " "
                        }
                    } @else {
                        a href="#node-table" { "0" }
                    }
                }
                div class="l" { "nodes by health (fiducia-brain)" }
            }
            div class="stat" {
                div class="n" {
                    (gap_count("unplaced", status_u64(status, &["placement", "unplaced_shards"]), "#shard-table"))
                    (gap_count("under-replicated", status_u64(status, &["placement", "under_replicated_shards"]), "#shard-table"))
                    (gap_count("leaderless", status_u64(status, &["placement", "leaderless_shards"]), "#shard-table"))
                    (gap_count("unhealthy-replica", status_u64(status, &["placement", "shards_with_unhealthy_replicas"]), "#shard-table"))
                }
                div class="l" { "placement gaps (desired vs observed)" }
            }
            div class="stat" {
                div class="n" {
                    (gap_count("leaderless", quorum.leaderless.len() as u64, "#shard-table"))
                    (gap_count("leader-unreached", quorum.leader_unreached.len() as u64, "#shard-table"))
                    (gap_count("dual-leader", quorum.dual_leader.len() as u64, "#shard-table"))
                    (gap_count("at-risk", quorum.at_risk.len() as u64, "#shard-table"))
                    (gap_count("storage-faulted", quorum.storage_faulted.len() as u64, "#shard-table"))
                    (gap_count("unresponsive", quorum.unresponsive.len() as u64, "#shard-table"))
                }
                div class="l" {
                    "raft quorum (observed from "
                    a href="#node-table" { (quorum.nodes_reporting) " of " (quorum.nodes_reporting + quorum.nodes_failed) " nodes" }
                    ")"
                    @if let Some(total) = quorum.targets_truncated_from {
                        " · "
                        span class="tag tag--warn" {
                            "targets truncated (showing " (crate::cluster_insight::MAX_NODES) " of " (total) ")"
                        }
                    }
                }
            }
            div class="stat" {
                @match prometheus {
                    PromScrape::NotConfigured => {
                        div class="n muted" { "—" }
                        div class="l" { "Prometheus not configured (FIDUCIA_PROMETHEUS_URL)" }
                    }
                    PromScrape::Error { error } => {
                        div class="n" { span class="tag tag--bad" title=(error) { "query failed" } }
                        div class="l" { "Prometheus " code { (PROM_FIDUCIA_UP_QUERY) } }
                    }
                    PromScrape::Up { targets } => {
                        div class="n" {
                            @if let Some(grafana) = grafana {
                                a href=(grafana_explore_prom_url(grafana, PROM_FIDUCIA_UP_QUERY)) { (targets) }
                            } @else {
                                (targets)
                            }
                        }
                        div class="l" { "up scrape targets (" code { (PROM_FIDUCIA_UP_QUERY) } ")" }
                    }
                }
            }
        }
        div class="card" id="shard-table" {
            h2 { "Shards" }
            @if shards.is_empty() {
                p class="muted" {
                    "No shard reports."
                    @if quorum.nodes_failed > 0 {
                        " (" (quorum.nodes_failed) " node fetches failed — see the node table.)"
                    }
                }
            } @else {
                table {
                    tr {
                        th { "Shard" } th { "Role" } th { "Leader" } th { "Term" }
                        th { "Commit / applied" } th { "Lag max" } th { "Quorum" }
                        th { "Storage" } th { "Reported by" }
                    }
                    @for shard in shards {
                        tr {
                            td { (shard.shard_id) }
                            td {
                                span class="tag" { (shard.view.role) }
                                @if shard.dual_leader {
                                    " "
                                    span class="tag tag--bad"
                                        title="two nodes reported leadership for this shard (split-brain); the higher-term view is shown" {
                                        "dual-leader"
                                    }
                                }
                            }
                            td { (shard.view.leader_id.as_deref().unwrap_or("—")) }
                            td class="muted" { (shard.view.term) }
                            td class="muted" { (shard.view.commit_index) " / " (shard.view.last_applied) }
                            td class="muted" { (shard.view.metrics.follower_lag_max) }
                            td {
                                @if !shard.leader_view {
                                    @if shard.view.leader_id.is_some() {
                                        span class="tag tag--warn" { "no leader report" }
                                    } @else {
                                        span class="tag tag--bad" { "leaderless" }
                                    }
                                } @else if shard.view.has_quorum {
                                    span class="tag tag--ok" { "quorum (" (shard.view.healthy_replicas) ")" }
                                } @else {
                                    span class="tag tag--bad" { "at risk (" (shard.view.healthy_replicas) ")" }
                                }
                            }
                            td {
                                @if shard.view.storage_healthy {
                                    span class="tag tag--ok" { "ok" }
                                } @else {
                                    span class="tag tag--bad" title=[shard.view.storage_error.as_deref()] { "fault" }
                                }
                            }
                            td class="muted" { (shard.reported_by) }
                        }
                    }
                }
            }
        }
    }
}

/// One node's observe-fetch outcome badge for the registry table: reachable
/// (with its leadership share), unreachable (error in the tooltip), or not in
/// the fan-out target set at all.
fn observe_cell(observation: Option<&NodeObservation>) -> Markup {
    match observation {
        // Refused before any request: a distinct state from unreachable (H1).
        Some(observation) if observation.untrusted => html! {
            span class="tag tag--warn"
                title="brain-supplied address is not in-cluster; refused (never dialed with the cluster secret)" {
                "untrusted address"
            }
        },
        Some(NodeObservation {
            shards: Some(shards),
            ..
        }) => html! {
            span class="tag tag--ok" {
                "ok · leads " (shards.leader_count) " of " (shards.shards.len())
            }
        },
        Some(NodeObservation {
            error: Some(error), ..
        }) => html! { span class="tag tag--bad" title=(error) { "unreachable" } },
        Some(_) => html! { span class="tag" { "—" } },
        None => html! { span class="tag" title="not in the observe target set" { "—" } },
    }
}

/// Node registry (brain `/v1/nodes`) merged with each node's observe fetch
/// outcome. htmx fragment for `/cluster/nodes`.
pub fn cluster_nodes_panel(nodes: &[Value], observations: &[NodeObservation]) -> Markup {
    let now = now_ms();
    html! {
        div class="card" id="node-table" {
            h2 { "Nodes" }
            @if nodes.is_empty() {
                p class="muted" { "No nodes registered with fiducia-brain." }
            } @else {
                table {
                    tr {
                        th { "Node" } th { "Health" } th { "Failure domain" } th { "Address" }
                        th { "Hosted / leading" } th { "Last seen" } th { "Observe" }
                    }
                    @for node in nodes {
                        @let node_id = node.get("node_id").and_then(Value::as_str).unwrap_or("—");
                        @let last_seen = node.get("last_seen_ms").and_then(Value::as_i64).unwrap_or(0);
                        tr {
                            td { (node_id) }
                            td {
                                @let health = node.get("health").and_then(Value::as_str).unwrap_or("—");
                                span class=(health_tag_class(health)) { (health) }
                            }
                            td class="muted" { (node.get("failure_domain").and_then(Value::as_str).unwrap_or("—")) }
                            td class="muted" { (node.get("address").and_then(Value::as_str).unwrap_or("—")) }
                            td class="muted" {
                                (node.get("hosted_shards").and_then(Value::as_array).map_or(0, Vec::len))
                                " / "
                                (node.get("leading_shards").and_then(Value::as_array).map_or(0, Vec::len))
                            }
                            td class="muted" title=(utc_timestamp(last_seen)) { (relative_age(last_seen, now)) }
                            td {
                                (observe_cell(observations.iter().find(|observation| observation.node_id == node_id)))
                            }
                        }
                    }
                }
            }
        }
    }
}

/// Recent cluster events from Loki (leader transfers, elections, step-downs,
/// membership and placement changes). htmx fragment for `/cluster/events`.
pub fn cluster_events_panel(
    events: &EventsPanel,
    since_minutes: i64,
    grafana: Option<&str>,
) -> Markup {
    let now = now_ms();
    html! {
        div class="card" id="event-table" {
            h2 {
                "Recent cluster events "
                span class="tag" { "last " (since_minutes) "m" }
                @if let Some(grafana) = grafana {
                    " "
                    a class="btn btn--ghost"
                        href=(grafana_explore_loki_url(grafana, &loki_events_logql(), since_minutes)) {
                        "Open in Grafana"
                    }
                }
            }
            @match events {
                EventsPanel::NotConfigured => {
                    p class="muted" {
                        "Loki is not configured (" code { "FIDUCIA_LOKI_URL" } " unset) — raft/membership "
                        "events from the pods' JSON logs appear here once it is."
                    }
                }
                EventsPanel::Error(error) => {
                    p class="muted" role="alert" { "Loki query failed: " (error) }
                }
                EventsPanel::Events(events) => {
                    @if events.is_empty() {
                        p class="muted" { "No leadership, membership, or placement events in this window." }
                    } @else {
                        table {
                            tr { th { "When" } th { "Event" } th { "Shard" } th { "Node" } th { "Detail" } }
                            @for event in events {
                                tr {
                                    td class="muted" title=(utc_timestamp(event.at_ms)) { (relative_age(event.at_ms, now)) }
                                    td { span class=(event_tag_class(event.kind)) { (event.kind) } }
                                    td class="muted" { (event.shard.map(|shard| shard.to_string()).unwrap_or_else(|| "—".into())) }
                                    td class="muted" { (event.node.as_deref().unwrap_or("—")) }
                                    td class="muted" {
                                        @if let (Some(from), Some(to)) = (&event.from, &event.to) {
                                            (from) " → " (to)
                                            @if let Some(reason) = &event.reason { " (" (reason) ")" }
                                        } @else {
                                            (event.message)
                                        }
                                    }
                                }
                            }
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

    #[test]
    fn cluster_page_polls_its_fragments_and_the_nav_links_it() {
        let admin = user();
        let html = cluster(&admin, "csrf-test-token", html! {}, html! {}, html! {}).into_string();
        assert!(html.contains("Cluster insight"));
        assert!(html.contains(r#"href="/cluster""#), "nav link");
        assert!(html.contains(r#"hx-get="/cluster/shards""#));
        assert!(html.contains(r#"hx-get="/cluster/nodes""#));
        assert!(html.contains(r#"hx-get="/cluster/events""#));
        assert!(html.contains(r#"hx-trigger="every 5s""#));
    }

    #[test]
    fn cluster_status_panel_renders_cards_badges_and_shard_rows() {
        let status = json!({
            "cluster_id": "fiducia-test", "version": "0.1.0",
            "shard_count": 2, "replication_factor": 3,
            "topology": { "nodes_by_health": { "healthy": 2, "dead": 1 } },
            "placement": {
                "unplaced_shards": 0, "under_replicated_shards": 1,
                "leaderless_shards": 0, "shards_with_unhealthy_replicas": 0
            },
            "brain_cluster": {
                "placement_generation": 7, "is_leader": true, "leader": null,
                "available": true, "ha_configured": true
            }
        });
        let view: crate::cluster_insight::ShardView = serde_json::from_value(json!({
            "shard_id": 0, "role": "leader", "term": 3, "leader_id": "node-a",
            "commit_index": 42, "last_applied": 41, "storage_healthy": false,
            "storage_error": "disk full", "healthy_replicas": 3, "has_quorum": true
        }))
        .unwrap();
        let shards = vec![MergedShard {
            shard_id: 0,
            reported_by: "node-a".into(),
            leader_view: true,
            dual_leader: false,
            view,
        }];
        let quorum = ClusterQuorum {
            leaderless: vec![],
            leader_unreached: vec![],
            dual_leader: vec![],
            at_risk: vec![0],
            storage_faulted: vec![0],
            unresponsive: vec![],
            nodes_reporting: 2,
            nodes_failed: 1,
            targets_truncated_from: None,
        };
        let html = cluster_status_panel(
            &status,
            &shards,
            &quorum,
            &PromScrape::Up { targets: 2 },
            Some("/telemetry"),
        )
        .into_string();
        assert!(html.contains("fiducia-test"));
        assert!(html.contains("placement generation"));
        assert!(html.contains("2 healthy"));
        assert!(html.contains("1 dead"));
        assert!(html.contains("1 under-replicated"));
        assert!(html.contains("1 at-risk"));
        assert!(html.contains("2 of 3 nodes"), "fan-out coverage is shown");
        assert!(html.contains(r#"id="shard-table""#));
        assert!(html.contains("quorum (3)"));
        assert!(html.contains("disk full"), "storage fault tooltip");
        assert!(
            html.contains("/telemetry/explore?left="),
            "Grafana prom link"
        );
    }

    #[test]
    fn cluster_nodes_panel_badges_reachability_per_node() {
        let nodes = vec![json!({
            "node_id": "node-a", "address": "10.0.0.1:8090", "health": "healthy",
            "failure_domain": "gcp/europe-west1", "last_seen_ms": 1_752_400_000_000i64,
            "hosted_shards": [0, 1], "leading_shards": [0]
        })];
        let observations = vec![NodeObservation {
            node_id: "node-a".into(),
            base_url: "http://10.0.0.1:8090".into(),
            shards: None,
            error: Some("connect timeout".into()),
            untrusted: false,
        }];
        let html = cluster_nodes_panel(&nodes, &observations).into_string();
        assert!(html.contains(r#"id="node-table""#));
        assert!(html.contains("node-a"));
        assert!(html.contains("unreachable"));
        assert!(
            html.contains("connect timeout"),
            "error carried in the tooltip"
        );
        assert!(html.contains("2 / 1"), "hosted / leading counts");
    }

    #[test]
    fn cluster_nodes_panel_shows_untrusted_address_as_a_distinct_state() {
        let nodes = vec![json!({
            "node_id": "spoofed", "address": "attacker.example.com:8090", "health": "healthy",
            "last_seen_ms": 1_752_400_000_000i64, "hosted_shards": [], "leading_shards": []
        })];
        let observations = vec![NodeObservation {
            node_id: "spoofed".into(),
            base_url: "http://attacker.example.com:8090".into(),
            shards: None,
            error: Some("untrusted address".into()),
            untrusted: true,
        }];
        let html = cluster_nodes_panel(&nodes, &observations).into_string();
        assert!(html.contains("untrusted address"), "distinct refused badge");
        // It must not read as a mere transient reachability failure.
        assert!(!html.contains(">unreachable<"));
    }

    #[test]
    fn cluster_status_panel_flags_dual_leader_unreached_and_truncation() {
        let status = json!({ "cluster_id": "fiducia-test", "version": "0.1.0" });
        let leader_view: crate::cluster_insight::ShardView = serde_json::from_value(json!({
            "shard_id": 0, "role": "leader", "term": 9, "leader_id": "node-b", "has_quorum": true
        }))
        .unwrap();
        let follower_view: crate::cluster_insight::ShardView = serde_json::from_value(json!({
            "shard_id": 1, "role": "follower", "term": 4, "leader_id": "node-z"
        }))
        .unwrap();
        let shards = vec![
            MergedShard {
                shard_id: 0,
                reported_by: "node-b".into(),
                leader_view: true,
                dual_leader: true,
                view: leader_view,
            },
            MergedShard {
                shard_id: 1,
                reported_by: "node-a".into(),
                leader_view: false,
                dual_leader: false,
                view: follower_view,
            },
        ];
        let quorum = ClusterQuorum {
            leaderless: vec![],
            leader_unreached: vec![1],
            dual_leader: vec![0],
            at_risk: vec![],
            storage_faulted: vec![],
            unresponsive: vec![],
            nodes_reporting: 2,
            nodes_failed: 1,
            targets_truncated_from: Some(900),
        };
        let html =
            cluster_status_panel(&status, &shards, &quorum, &PromScrape::NotConfigured, None)
                .into_string();
        assert!(
            html.contains("dual-leader"),
            "split-brain badge + card count"
        );
        assert!(html.contains("1 leader-unreached"), "M5 bucket in the card");
        assert!(html.contains("1 dual-leader"), "M4 count in the card");
        assert!(
            html.contains("targets truncated (showing 512 of 900)"),
            "M3 truncation note"
        );
        // Shard 1 has a known leader_id, so it reads as "no leader report", not leaderless.
        assert!(html.contains("no leader report"));
    }

    #[test]
    fn cluster_events_panel_renders_all_three_states() {
        let unconfigured =
            cluster_events_panel(&EventsPanel::NotConfigured, 30, None).into_string();
        assert!(unconfigured.contains("FIDUCIA_LOKI_URL"));

        let failed =
            cluster_events_panel(&EventsPanel::Error("boom".into()), 30, None).into_string();
        assert!(failed.contains("Loki query failed: boom"));

        let events = vec![ClusterEvent {
            at_ms: 1_752_400_681_123,
            kind: "leader_transfer",
            shard: Some(3),
            node: None,
            from: Some("Follower".into()),
            to: Some("Leader".into()),
            reason: Some("became_leader".into()),
            message: "observed raft leadership transition".into(),
        }];
        let rendered = cluster_events_panel(&EventsPanel::Events(events), 30, Some("/telemetry"))
            .into_string();
        assert!(rendered.contains("leader_transfer"));
        assert!(rendered.contains("Follower"));
        assert!(rendered.contains("became_leader"));
        assert!(rendered.contains("last 30m"));
        assert!(rendered.contains("Open in Grafana"));
        assert!(rendered.contains("/telemetry/explore?left="));
    }
}
