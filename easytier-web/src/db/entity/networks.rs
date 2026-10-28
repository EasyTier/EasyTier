//! Tenant-scoped central network intent.

use sea_orm::entity::prelude::*;
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, PartialEq, DeriveEntityModel, Eq, Serialize, Deserialize)]
#[sea_orm(table_name = "networks")]
pub struct Model {
    #[sea_orm(primary_key, auto_increment = false)]
    pub user_id: i32,
    #[sea_orm(primary_key, auto_increment = false, column_type = "Text")]
    pub id: String,
    #[sea_orm(column_type = "Text")]
    pub display_name: String,
    #[sea_orm(column_type = "Text")]
    pub network_name: String,
    #[sea_orm(column_type = "Text")]
    pub network_secret: String,
    #[sea_orm(column_type = "Text")]
    pub networking_method: String,
    #[sea_orm(column_type = "Text", nullable)]
    pub public_server_url: Option<String>,
    #[sea_orm(column_type = "Text")]
    pub peer_urls: String,
    #[sea_orm(column_type = "Text", nullable)]
    pub virtual_cidr: Option<String>,
    pub secure_mode: bool,
    #[sea_orm(column_type = "Text", nullable)]
    pub acl_policy: Option<String>,
    pub create_time: DateTimeWithTimeZone,
    pub update_time: DateTimeWithTimeZone,
}

#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {}

impl ActiveModelBehavior for ActiveModel {}
