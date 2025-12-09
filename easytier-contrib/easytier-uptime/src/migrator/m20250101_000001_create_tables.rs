use sea_orm_migration::{prelude::*, schema::*};

pub struct Migration;

impl MigrationName for Migration {
    fn name(&self) -> &str {
        "m20250101_000001_create_tables"
    }
}

#[derive(DeriveIden)]
pub enum SharedNodes {
    Table,
    Id,
    Name,
    Host,
    Port,
    Protocol,
    Version,
    AllowRelay,
    NetworkName,
    NetworkSecret,
    Description,
    MaxConnections,
    CurrentConnections,
    IsActive,
    IsApproved,
    QQNumber,
    Wechat,
    Mail,
    CreatedAt,
    UpdatedAt,
}

#[derive(DeriveIden)]
pub enum HealthRecords {
    Table,
    Id,
    NodeId,
    Status,
    ResponseTime,
    ErrorMessage,
    CheckedAt,
}

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        // 创建共享节点表
        manager
            .create_table(
                Table::create()
                    .if_not_exists()
                    .table(SharedNodes::Table)
                    .col(pk_auto(SharedNodes::Id).not_null())
                    .col(string(SharedNodes::Name).not_null())
                    .col(string(SharedNodes::Host).not_null())
                    .col(integer(SharedNodes::Port).not_null())
                    .col(string(SharedNodes::Protocol).not_null().default("tcp"))
                    .col(string(SharedNodes::Version))
                    .col(boolean(SharedNodes::AllowRelay).default(false))
                    .col(string(SharedNodes::NetworkName))
                    .col(string(SharedNodes::NetworkSecret))
                    .col(text(SharedNodes::Description))
                    .col(integer(SharedNodes::MaxConnections).default(100))
                    .col(integer(SharedNodes::CurrentConnections).default(0))
                    .col(boolean(SharedNodes::IsActive).default(true))
                    .col(boolean(SharedNodes::IsApproved).default(false))
                    .col(string(SharedNodes::QQNumber))
                    .col(string(SharedNodes::Wechat))
                    .col(string(SharedNodes::Mail))
                    .col(
                        timestamp_with_time_zone(SharedNodes::CreatedAt)
                            .default(Expr::current_timestamp()),
                    )
                    .col(
                        timestamp_with_time_zone(SharedNodes::UpdatedAt)
                            .default(Expr::current_timestamp()),
                    )
                    .to_owned(),
            )
            .await?;

        // 创建唯一约束
        manager
            .create_index(
                Index::create()
                    .name("idx_shared_nodes_host_port_protocol")
                    .table(SharedNodes::Table)
                    .col(SharedNodes::Host)
                    .col(SharedNodes::Port)
                    .col(SharedNodes::Protocol)
                    .unique()
                    .to_owned(),
            )
            .await?;

        // 创建健康度记录表
        manager
            .create_table(
                Table::create()
                    .if_not_exists()
                    .table(HealthRecords::Table)
                    .col(pk_auto(HealthRecords::Id).not_null())
                    .col(integer(HealthRecords::NodeId).not_null())
                    .col(string(HealthRecords::Status).not_null())
                    .col(integer(HealthRecords::ResponseTime))
                    .col(text(HealthRecords::ErrorMessage).null())
                    .col(
                        timestamp_with_time_zone(HealthRecords::CheckedAt)
                            .default(Expr::current_timestamp()),
                    )
                    .foreign_key(
                        ForeignKey::create()
                            .name("fk_health_records_node_id_to_shared_nodes_id")
                            .from(HealthRecords::Table, HealthRecords::NodeId)
                            .to(SharedNodes::Table, SharedNodes::Id)
                            .on_delete(ForeignKeyAction::Cascade)
                            .on_update(ForeignKeyAction::Cascade),
                    )
                    .to_owned(),
            )
            .await?;

        // 创建健康度记录索引
        manager
            .create_index(
                Index::create()
                    .name("idx_health_records_node_id")
                    .table(HealthRecords::Table)
                    .col(HealthRecords::NodeId)
                    .to_owned(),
            )
            .await?;

        manager
            .create_index(
                Index::create()
                    .name("idx_health_records_checked_at")
                    .table(HealthRecords::Table)
                    .col(HealthRecords::CheckedAt)
                    .to_owned(),
            )
            .await?;

        manager
            .create_index(
                Index::create()
                    .name("idx_health_records_node_time")
                    .table(HealthRecords::Table)
                    .col(HealthRecords::NodeId)
                    .col(HealthRecords::CheckedAt)
                    .to_owned(),
            )
            .await?;

        manager
            .create_index(
                Index::create()
                    .name("idx_health_records_status")
                    .table(HealthRecords::Table)
                    .col(HealthRecords::Status)
                    .to_owned(),
            )
            .await?;

        Ok(())
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .drop_table(Table::drop().table(HealthRecords::Table).to_owned())
            .await?;

        manager
            .drop_table(Table::drop().table(SharedNodes::Table).to_owned())
            .await?;

        Ok(())
    }
}
