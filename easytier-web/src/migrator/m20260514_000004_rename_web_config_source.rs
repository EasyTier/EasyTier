use sea_orm_migration::prelude::*;

pub struct Migration;

impl MigrationName for Migration {
    fn name(&self) -> &str {
        "m20260514_000004_rename_web_config_source"
    }
}

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        let db = manager.get_connection();
        db.execute_unprepared(
            r#"
            UPDATE user_running_network_configs
            SET source = 'web'
            WHERE source = 'webhook';

            UPDATE user_running_network_configs
            SET source = 'user'
            WHERE source = 'legacy';
            "#,
        )
        .await?;
        Ok(())
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        let db = manager.get_connection();
        db.execute_unprepared(
            r#"
            UPDATE user_running_network_configs
            SET source = 'webhook'
            WHERE source = 'web';
            "#,
        )
        .await?;
        Ok(())
    }
}
