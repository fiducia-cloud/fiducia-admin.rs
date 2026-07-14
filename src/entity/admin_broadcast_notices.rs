//! SeaORM entity for `admin_broadcast_notices` — operator-authored dashboard
//! announcements (maintenance windows, incident notes). Operator plane only;
//! never surfaced to customers. The BEFORE trigger `admin_broadcast_notices_bump`
//! stamps `version`/`updated_at`/`sync_sequence`. Schema:
//! `fiducia-interfaces/sql/admin.sql`.

use sea_orm::entity::prelude::*;

#[derive(Clone, Debug, PartialEq, Eq, DeriveEntityModel, serde::Serialize)]
#[sea_orm(table_name = "admin_broadcast_notices")]
pub struct Model {
    #[sea_orm(primary_key, auto_increment = false)]
    pub id: Uuid,
    pub operator_id: Option<Uuid>,
    pub severity: String,
    pub title: String,
    pub body: String,
    pub active: bool,
    pub starts_at: DateTimeWithTimeZone,
    pub ends_at: Option<DateTimeWithTimeZone>,
    pub created_at: DateTimeWithTimeZone,
    pub updated_at: DateTimeWithTimeZone,
    pub version: i64,
    pub sync_sequence: i64,
}

#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {}

impl ActiveModelBehavior for ActiveModel {}
