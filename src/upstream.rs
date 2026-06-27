//! Calls to the other fiducia services (skeleton).
//!
//! The admin app is a thin web tier: it renders HTML but the data and actions
//! live elsewhere — **accounts/API keys** in `fiducia-auth`, **infra** in
//! `fiducia-brain`. These are stubbed; wire them with an HTTP client (reqwest)
//! plus the caller's session for authz.

use serde_json::{json, Value};

/// `fiducia-auth`: list an org's API keys (masked).
/// TODO: GET `{auth_url}/v1/keys` with the user's session.
pub async fn list_keys(_auth_url: &str, _org: &str) -> Vec<Value> {
    vec![]
}

/// `fiducia-auth`: create a key. Returns the raw key (shown once) + meta.
/// TODO: POST `{auth_url}/v1/keys`.
pub async fn create_key(_auth_url: &str, _org: &str, _name: &str) -> Value {
    json!({ "todo": "create via fiducia-auth" })
}

/// `fiducia-auth`: revoke a key. TODO: DELETE `{auth_url}/v1/keys/{id}`.
pub async fn revoke_key(_auth_url: &str, _org: &str, _key_id: &str) -> bool {
    false
}

/// `fiducia-brain`: cluster membership. TODO: GET `{brain_url}/v1/nodes`.
pub async fn nodes(_brain_url: &str) -> Vec<Value> {
    vec![]
}

/// `fiducia-brain`: shard placement map. TODO: GET `{brain_url}/v1/placement`.
pub async fn placement(_brain_url: &str) -> Vec<Value> {
    vec![]
}

/// `fiducia-brain`: set the desired scale plan. TODO: POST `{brain_url}/v1/scale`.
pub async fn set_scale(_brain_url: &str, _target_nodes: u32) -> bool {
    false
}
