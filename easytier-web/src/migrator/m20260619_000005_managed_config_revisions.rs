use sea_orm_migration::prelude::*;

pub struct Migration;

impl MigrationName for Migration {
    fn name(&self) -> &str {
        "m20260619_000005_managed_config_revisions"
    }
}

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .get_connection()
            .execute_unprepared(
                r#"
                CREATE TABLE managed_config_revisions (
                    id INTEGER PRIMARY KEY AUTOINCREMENT NOT NULL,
                    user_id INTEGER NOT NULL,
                    device_id TEXT NOT NULL,
                    config_revision TEXT NOT NULL,
                    create_time TEXT NOT NULL,
                    update_time TEXT NOT NULL,
                    CONSTRAINT fk_managed_config_revisions_user_id_to_users_id
                        FOREIGN KEY (user_id) REFERENCES users(id)
                        ON DELETE CASCADE
                        ON UPDATE CASCADE
                );

                CREATE UNIQUE INDEX idx_managed_config_revisions_scope
                    ON managed_config_revisions(user_id, device_id);
                "#,
            )
            .await?;
        Ok(())
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .get_connection()
            .execute_unprepared("DROP TABLE managed_config_revisions;")
            .await?;
        Ok(())
    }
}
