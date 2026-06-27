//! Server-rendered HTML (skeleton).
//!
//! Plain Rust string templates to stay dependency-light. For a real build, move
//! to a compile-checked template engine (`maud`/`askama`) and HTML-escape all
//! dynamic values (the stubbed data here is static, so escaping is a `TODO`).

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
input{background:#0c1330;border:1px solid var(--line);color:var(--ink);border-radius:8px;padding:.5rem .6rem;font:inherit}
.muted{color:var(--dim)}.tag{font-size:.75rem;color:var(--dim);border:1px solid var(--line);border-radius:6px;padding:.05rem .4rem}
"#;

/// Wrap a page body in the shared layout + nav.
pub fn page(title: &str, session: Option<&Session>, body: &str) -> String {
    let nav_links = if session.is_some() {
        let admin = if session.map(|s| s.is_admin).unwrap_or(false) {
            r#"<a href="/infra">Infra</a>"#
        } else {
            ""
        };
        format!(r#"<a href="/">Dashboard</a><a href="/keys">API keys</a><a href="/account">Account</a>{admin}"#)
    } else {
        r#"<a href="/login">Sign in</a>"#.to_string()
    };
    let who = match session {
        Some(s) => format!(
            r#"<span class="who">{}{}</span>"#,
            s.email.clone().unwrap_or_else(|| s.user_id.clone()),
            if s.is_admin { " · admin" } else { "" }
        ),
        None => String::new(),
    };
    format!(
        r#"<!doctype html><html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>{title} · Fiducia Admin</title><style>{CSS}</style></head><body>
<nav class="nav"><span class="brand">Fiducia<b>.admin</b></span>{nav_links}<span class="sp"></span>{who}</nav>
<div class="wrap">{body}</div></body></html>"#
    )
}

pub fn login() -> String {
    let body = r#"<h1>Sign in</h1>
<div class="card">
  <p class="muted">Authenticate with your Supabase account. The dashboard verifies the
  session via <code>fiducia-auth</code>.</p>
  <p class="muted">TODO: embed the Supabase JS client here; on success store the session
  cookie and redirect to <code>/</code>.</p>
  <p><a class="btn" href="/">Continue (dev)</a></p>
</div>"#;
    page("Sign in", None, body)
}

pub fn dashboard(s: &Session) -> String {
    let body = format!(
        r#"<h1>Dashboard</h1>
<div class="card"><h2>Welcome</h2>
<p class="muted">Signed in as <b>{}</b>. Orgs: {}.</p>
<p><a href="/keys">Manage API keys →</a></p>
{}</div>"#,
        s.email.clone().unwrap_or_else(|| s.user_id.clone()),
        s.orgs.join(", "),
        if s.is_admin { r#"<p><a href="/infra">Cluster &amp; infra ops →</a></p>"# } else { "" }
    );
    page("Dashboard", Some(s), &body)
}

pub fn account(s: &Session) -> String {
    let body = r#"<h1>Account</h1>
<div class="card"><h2>Organization &amp; members</h2>
<p class="muted">TODO: org details + member management (invite/remove, roles), backed by
Supabase. Identity comes from the verified session.</p></div>"#;
    page("Account", Some(s), body)
}

pub fn keys(s: &Session, keys: &[Value]) -> String {
    let rows = if keys.is_empty() {
        r#"<tr><td colspan="4" class="muted">No keys yet — create one above. (Live data comes from fiducia-auth.)</td></tr>"#.to_string()
    } else {
        keys.iter()
            .map(|k| {
                format!(
                    r#"<tr><td>{}</td><td><span class="tag">{}</span></td><td class="muted">{}</td>
<td><form method="post" action="/keys/{}/revoke"><button class="btn btn--ghost">Revoke</button></form></td></tr>"#,
                    k.get("name").and_then(Value::as_str).unwrap_or("—"),
                    k.get("env").and_then(Value::as_str).unwrap_or("live"),
                    k.get("key_id").and_then(Value::as_str).unwrap_or("—"),
                    k.get("key_id").and_then(Value::as_str).unwrap_or(""),
                )
            })
            .collect::<String>()
    };
    let body = format!(
        r#"<h1>API keys</h1>
<div class="card"><h2>Create a key</h2>
<form method="post" action="/keys" style="display:flex;gap:.6rem">
  <input name="name" placeholder="key name (e.g. prod-checkout)" required>
  <button class="btn" type="submit">Create</button>
</form>
<p class="muted">The raw key is shown once on creation. Only its hash is stored.</p></div>
<div class="card"><h2>Your keys</h2>
<table><tr><th>Name</th><th>Env</th><th>Key ID</th><th></th></tr>{rows}</table></div>"#
    );
    page("API keys", Some(s), &body)
}

pub fn infra(s: &Session, nodes: &[Value], placement: &[Value]) -> String {
    let body = format!(
        r#"<h1>Cluster &amp; infra</h1>
<div class="card"><h2>Scale</h2>
<form method="post" action="/infra/scale" style="display:flex;gap:.6rem;align-items:center">
  <label class="muted">Target nodes</label>
  <input name="target_nodes" type="number" min="3" value="9" style="width:6rem">
  <button class="btn" type="submit">Apply</button>
</form>
<p class="muted">Drives <code>fiducia-brain</code> <code>POST /v1/scale</code> (admin only).</p></div>
<div class="card"><h2>Nodes</h2><p class="muted">{} known (live from fiducia-brain /v1/nodes).</p></div>
<div class="card"><h2>Shard placement</h2><p class="muted">{} shards mapped (fiducia-brain /v1/placement).</p></div>"#,
        nodes.len(),
        placement.len()
    );
    page("Infra", Some(s), &body)
}
