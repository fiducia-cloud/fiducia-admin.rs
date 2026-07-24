//! Generated fiducia-interfaces contract import tests. Extracted verbatim from main.rs;
//! `use super::*` resolves to the crate root exactly as when inline.

use fiducia_interfaces::{LockAcquireManyRequest, ProposeErrorReason};

#[test]
fn generated_interfaces_are_importable() {
    let request = LockAcquireManyRequest {
        keys: vec!["orders/42".to_string(), "inventory/sku-7".to_string()],
        holder: "worker-a".to_string(),
        request_id: Some("interface-contract-attempt".to_string()),
        ttl_ms: Some(30_000),
        wait: Some(true),
        wait_timeout_ms: Some(5_000),
    };

    assert_eq!(request.keys.len(), 2);
    assert_eq!(request.holder, "worker-a");
    assert_eq!(
        request.request_id.as_deref(),
        Some("interface-contract-attempt")
    );
    assert_eq!(request.wait_timeout_ms, Some(5_000));
    assert!(matches!(
        ProposeErrorReason::NotLeader,
        ProposeErrorReason::NotLeader
    ));
}
