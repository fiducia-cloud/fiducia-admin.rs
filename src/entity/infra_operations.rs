//! SeaORM entity for the admin-plane `infra_operations` audit table.

use sea_orm::entity::prelude::*;

#[derive(Clone, Debug, PartialEq, DeriveEntityModel, serde::Serialize)]
#[sea_orm(table_name = "infra_operations")]
pub struct Model {
    #[sea_orm(primary_key, auto_increment = false)]
    pub id: Uuid,
    pub operator_id: Option<Uuid>,
    pub action: String,
    pub target: Option<String>,
    pub target_nodes: Option<i32>,
    pub params: Json,
    pub status: String,
    pub request_id: Option<String>,
    pub error: Option<String>,
    pub created_at: DateTimeWithTimeZone,
    pub updated_at: DateTimeWithTimeZone,
    pub version: i64,
    /// Plane-wide, commit-ordered cursor used only for catch-up pagination.
    pub sync_sequence: i64,
}

#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {}

impl ActiveModelBehavior for ActiveModel {}
