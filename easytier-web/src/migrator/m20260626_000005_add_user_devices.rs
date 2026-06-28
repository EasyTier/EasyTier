use sea_orm_migration::prelude::*;

pub struct Migration;

impl MigrationName for Migration {
    fn name(&self) -> &str {
        "m20260626_000005_add_user_devices"
    }
}

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        let db = manager.get_connection();

        db.execute_unprepared(
            r#"
            CREATE TABLE IF NOT EXISTS user_devices (
                id INTEGER PRIMARY KEY AUTOINCREMENT NOT NULL,
                user_id INTEGER NOT NULL,
                machine_id TEXT NOT NULL,
                client_url TEXT NOT NULL,
                hostname TEXT NOT NULL,
                remark TEXT NULL,
                easytier_version TEXT NOT NULL,
                report_time TEXT NOT NULL,
                create_time TEXT NOT NULL,
                update_time TEXT NOT NULL,
                CONSTRAINT fk_user_devices_user_id_to_users_id
                    FOREIGN KEY (user_id) REFERENCES users(id)
                    ON DELETE CASCADE
                    ON UPDATE CASCADE
            );

            CREATE INDEX IF NOT EXISTS idx_user_devices_user_id
                ON user_devices(user_id);
            CREATE UNIQUE INDEX IF NOT EXISTS idx_user_devices_scope_machine
                ON user_devices(user_id, machine_id);
            "#,
        )
        .await?;

        Ok(())
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .drop_table(Table::drop().table(Alias::new("user_devices")).to_owned())
            .await
    }
}
