use sea_orm_migration::prelude::*;

pub struct Migration;

impl MigrationName for Migration {
    fn name(&self) -> &str {
        "m20261014_000011_device_tokens"
    }
}

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .get_connection()
            .execute_unprepared(
                r#"
                CREATE TABLE device_tokens (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    user_id INTEGER NOT NULL,
                    name TEXT NOT NULL DEFAULT '',
                    token TEXT NOT NULL,
                    machine_id TEXT,
                    created_time TEXT NOT NULL,
                    last_used_time TEXT,
                    revoked_at TEXT,
                    CONSTRAINT uq_device_tokens_token UNIQUE (token),
                    CONSTRAINT fk_device_tokens_user_id_to_users_id
                        FOREIGN KEY (user_id) REFERENCES users(id)
                        ON DELETE CASCADE
                        ON UPDATE CASCADE
                );

                CREATE INDEX idx_device_tokens_user
                    ON device_tokens(user_id, revoked_at);
                "#,
            )
            .await?;
        Ok(())
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .get_connection()
            .execute_unprepared("DROP TABLE device_tokens;")
            .await?;
        Ok(())
    }
}
