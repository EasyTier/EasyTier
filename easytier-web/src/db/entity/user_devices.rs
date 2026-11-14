//! `SeaORM` Entity for persisted web devices.

use sea_orm::entity::prelude::*;
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, PartialEq, DeriveEntityModel, Eq, Serialize, Deserialize)]
#[sea_orm(table_name = "user_devices")]
pub struct Model {
    #[sea_orm(primary_key)]
    pub id: i32,
    pub user_id: i32,
    #[sea_orm(column_type = "Text")]
    pub machine_id: String,
    #[sea_orm(column_type = "Text")]
    pub client_url: String,
    #[sea_orm(column_type = "Text")]
    pub hostname: String,
    #[sea_orm(column_type = "Text", nullable)]
    pub remark: Option<String>,
    #[sea_orm(column_type = "Text")]
    pub easytier_version: String,
    #[sea_orm(column_type = "Text")]
    pub report_time: String,
    pub create_time: DateTimeWithTimeZone,
    pub update_time: DateTimeWithTimeZone,
}

#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {
    #[sea_orm(
        belongs_to = "super::users::Entity",
        from = "Column::UserId",
        to = "super::users::Column::Id",
        on_update = "Cascade",
        on_delete = "Cascade"
    )]
    Users,
}

impl Related<super::users::Entity> for Entity {
    fn to() -> RelationDef {
        Relation::Users.def()
    }
}

impl ActiveModelBehavior for ActiveModel {}
