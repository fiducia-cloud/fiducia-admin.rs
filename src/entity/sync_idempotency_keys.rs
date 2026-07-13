//! SeaORM entity for the durable admin sync idempotency ledger.

use sea_orm::entity::prelude::*;

#[derive(Clone, Debug, PartialEq, Eq, DeriveEntityModel)]
#[sea_orm(table_name = "sync_idempotency_keys")]
pub struct Model {
    #[sea_orm(primary_key, auto_increment = false)]
    pub key: String,
    /// Canonical SHA-256 digest of the operator and write semantics. Nullable
    /// only for rows created before fingerprint binding was deployed.
    pub request_fingerprint: Option<String>,
    pub committed_version: Option<i64>,
    pub created_at: DateTimeWithTimeZone,
}

#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {}

impl ActiveModelBehavior for ActiveModel {}
