use sea_orm_migration::{prelude::*, schema::*};

#[derive(DeriveMigrationName)]
pub struct Migration;

#[derive(DeriveIden)]
enum NodeTags {
    Table,
    Id,
    NodeId,
    Tag,
    CreatedAt,
}

#[derive(DeriveIden)]
enum SharedNodes {
    Table,
    Id,
}

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        // 创建 node_tags 表
        manager
            .create_table(
                Table::create()
                    .table(NodeTags::Table)
                    .if_not_exists()
                    .col(pk_auto(NodeTags::Id).not_null())
                    .col(integer(NodeTags::NodeId).not_null())
                    .col(string(NodeTags::Tag).not_null())
                    .col(
                        timestamp_with_time_zone(NodeTags::CreatedAt)
                            .not_null()
                            .default(Expr::current_timestamp()),
                    )
                    .foreign_key(
                        ForeignKey::create()
                            .name("fk_node_tags_node")
                            .from(NodeTags::Table, NodeTags::NodeId)
                            .to(SharedNodes::Table, SharedNodes::Id)
                            .on_delete(ForeignKeyAction::Cascade)
                            .on_update(ForeignKeyAction::Cascade),
                    )
                    .to_owned(),
            )
            .await?;

        // 索引：NodeId
        manager
            .create_index(
                Index::create()
                    .name("idx_node_tags_node")
                    .table(NodeTags::Table)
                    .col(NodeTags::NodeId)
                    .to_owned(),
            )
            .await?;

        // 索引：Tag
        manager
            .create_index(
                Index::create()
                    .name("idx_node_tags_tag")
                    .table(NodeTags::Table)
                    .col(NodeTags::Tag)
                    .to_owned(),
            )
            .await?;

        // 唯一索引：每个节点的标签唯一
        manager
            .create_index(
                Index::create()
                    .name("uniq_node_tag_per_node")
                    .table(NodeTags::Table)
                    .col(NodeTags::NodeId)
                    .col(NodeTags::Tag)
                    .unique()
                    .to_owned(),
            )
            .await?;

        Ok(())
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        // 先删除索引
        manager
            .drop_index(
                Index::drop()
                    .name("idx_node_tags_node")
                    .table(NodeTags::Table)
                    .to_owned(),
            )
            .await?;
        manager
            .drop_index(
                Index::drop()
                    .name("idx_node_tags_tag")
                    .table(NodeTags::Table)
                    .to_owned(),
            )
            .await?;
        manager
            .drop_index(
                Index::drop()
                    .name("uniq_node_tag_per_node")
                    .table(NodeTags::Table)
                    .to_owned(),
            )
            .await?;

        manager
            .drop_table(Table::drop().table(NodeTags::Table).to_owned())
            .await
    }
}
