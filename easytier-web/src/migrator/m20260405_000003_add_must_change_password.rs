use sea_orm_migration::prelude::*;

pub struct Migration;

#[derive(DeriveIden)]
enum Users {
    Table,
    Username,
    MustChangePassword,
}

impl MigrationName for Migration {
    fn name(&self) -> &str {
        "m20260405_000003_add_must_change_password"
    }
}

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .alter_table(
                Table::alter()
                    .table(Users::Table)
                    .add_column(
                        ColumnDef::new(Users::MustChangePassword)
                            .boolean()
                            .not_null()
                            .default(false),
                    )
                    .to_owned(),
            )
            .await?;

        manager
            .exec_stmt(
                Query::update()
                    .table(Users::Table)
                    .value(Users::MustChangePassword, true)
                    .and_where(Expr::col(Users::Username).is_in(["admin", "user"]))
                    .to_owned(),
            )
            .await?;

        Ok(())
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .alter_table(
                Table::alter()
                    .table(Users::Table)
                    .drop_column(Users::MustChangePassword)
                    .to_owned(),
            )
            .await?;

        Ok(())
    }
}
