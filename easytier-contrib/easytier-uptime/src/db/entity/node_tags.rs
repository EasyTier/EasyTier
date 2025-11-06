//! `SeaORM` Entity for node tags

use sea_orm::entity::prelude::*;
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, PartialEq, DeriveEntityModel, Eq, Serialize, Deserialize)]
#[sea_orm(table_name = "node_tags")]
pub struct Model {
    #[sea_orm(primary_key)]
    pub id: i32,
    pub node_id: i32,
    pub tag: String,
    pub created_at: DateTimeWithTimeZone,
}

#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {
    #[sea_orm(
        belongs_to = "super::shared_nodes::Entity",
        from = "Column::NodeId",
        to = "super::shared_nodes::Column::Id"
    )]
    SharedNodes,
}

impl Related<super::shared_nodes::Entity> for Entity {
    fn to() -> RelationDef {
        Relation::SharedNodes.def()
    }
}

impl ActiveModelBehavior for ActiveModel {}
