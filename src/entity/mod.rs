//! SeaORM entities for the isolated admin plane.
//!
//! These models mirror `fiducia-interfaces/sql/admin.sql`. The schema remains
//! canonical there; this module only gives the admin application typed ORM
//! access to the tables it owns.

pub mod admin_audit_log;
pub mod infra_operations;
pub mod operators;
pub mod sync_idempotency_keys;
