//! SeaORM projection of the append-only admin-plane audit log.
//!
//! This deliberately excludes source addresses, user agents, and arbitrary
//! metadata from the dashboard model. Operators can see a minimal accountable
//! history without an incidental browser endpoint becoming a diagnostics dump.

use sea_orm::entity::prelude::*;

#[derive(Clone, Debug, PartialEq, DeriveEntityModel)]
#[sea_orm(table_name = "admin_audit_log")]
pub struct Model {
    #[sea_orm(primary_key, auto_increment = false)]
    pub id: Uuid,
    pub actor_operator_id: Option<Uuid>,
    pub actor: Option<String>,
    pub action: String,
    pub target: Option<String>,
    pub request_id: Option<String>,
    /// Persisted for durable forensic context; never serialized by the admin
    /// page or JSON endpoint.
    pub meta: Json,
    pub created_at: DateTimeWithTimeZone,
    pub retention_expires_at: Option<DateTimeWithTimeZone>,
}

#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {}

impl ActiveModelBehavior for ActiveModel {}
