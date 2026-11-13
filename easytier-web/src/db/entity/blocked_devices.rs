//! `SeaORM` Entity for tenant-scoped blocked devices.

use sea_orm::entity::prelude::*;
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, PartialEq, DeriveEntityModel, Eq, Serialize, Deserialize)]
#[sea_orm(table_name = "blocked_devices")]
pub struct Model {
    #[sea_orm(primary_key, auto_increment = false)]
    pub user_id: i32,
    #[sea_orm(primary_key, auto_increment = false, column_type = "Text")]
    pub machine_id: String,
    #[sea_orm(column_type = "Text")]
    pub hostname: String,
    pub blocked_time: DateTimeWithTimeZone,
    pub attempt_count: i32,
    pub last_attempt_time: Option<DateTimeWithTimeZone>,
}

#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {}

impl ActiveModelBehavior for ActiveModel {}
