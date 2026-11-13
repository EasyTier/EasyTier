//! A member of a tenant-scoped central network.

use sea_orm::entity::prelude::*;
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, PartialEq, DeriveEntityModel, Eq, Serialize, Deserialize)]
#[sea_orm(table_name = "network_members")]
pub struct Model {
    #[sea_orm(primary_key, auto_increment = false)]
    pub user_id: i32,
    #[sea_orm(primary_key, auto_increment = false, column_type = "Text")]
    pub network_id: String,
    #[sea_orm(primary_key, auto_increment = false, column_type = "Text")]
    pub id: String,
    #[sea_orm(column_type = "Text")]
    pub device_id: String,
    #[sea_orm(column_type = "Text", nullable)]
    pub hostname_override: Option<String>,
    #[sea_orm(column_type = "Text", nullable)]
    pub virtual_ipv4: Option<String>,
    #[sea_orm(column_type = "Text", nullable)]
    pub allocated_ipv4: Option<String>,
    #[sea_orm(column_type = "Text", nullable)]
    pub override_config: Option<String>,
    #[sea_orm(column_type = "Text", nullable)]
    pub credential_id: Option<String>,
    #[sea_orm(column_type = "Text", nullable)]
    pub acl_group_secret: Option<String>,
    pub create_time: DateTimeWithTimeZone,
    pub update_time: DateTimeWithTimeZone,
}

#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {}

impl ActiveModelBehavior for ActiveModel {}
