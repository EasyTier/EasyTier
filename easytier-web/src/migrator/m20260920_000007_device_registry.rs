use sea_orm_migration::prelude::*;

pub struct Migration;

impl MigrationName for Migration {
    fn name(&self) -> &str {
        "m20260920_000007_device_registry"
    }
}

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .get_connection()
            .execute_unprepared(
                r#"
                CREATE TABLE devices (
                    user_id INTEGER NOT NULL,
                    machine_id TEXT NOT NULL,
                    hostname TEXT NOT NULL DEFAULT '',
                    alias TEXT NOT NULL DEFAULT '',
                    easytier_version TEXT NOT NULL DEFAULT '',
                    device_os TEXT NOT NULL DEFAULT '{}',
                    client_url TEXT NOT NULL DEFAULT '',
                    first_seen_time TEXT NOT NULL,
                    last_seen_time TEXT NOT NULL,
                    CONSTRAINT pk_devices PRIMARY KEY (user_id, machine_id),
                    CONSTRAINT fk_devices_user_id_to_users_id
                        FOREIGN KEY (user_id) REFERENCES users(id)
                        ON DELETE CASCADE
                        ON UPDATE CASCADE
                );

                CREATE INDEX idx_devices_user_last_seen
                    ON devices(user_id, last_seen_time DESC);

                CREATE TABLE blocked_devices (
                    user_id INTEGER NOT NULL,
                    machine_id TEXT NOT NULL,
                    hostname TEXT NOT NULL DEFAULT '',
                    blocked_time TEXT NOT NULL,
                    attempt_count INTEGER NOT NULL DEFAULT 0
                        CHECK (attempt_count >= 0),
                    last_attempt_time TEXT,
                    CONSTRAINT pk_blocked_devices PRIMARY KEY (user_id, machine_id),
                    CONSTRAINT fk_blocked_devices_user_id_to_users_id
                        FOREIGN KEY (user_id) REFERENCES users(id)
                        ON DELETE CASCADE
                        ON UPDATE CASCADE
                );

                CREATE INDEX idx_blocked_devices_user_last_attempt
                    ON blocked_devices(user_id, last_attempt_time DESC);
                "#,
            )
            .await?;
        Ok(())
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .get_connection()
            .execute_unprepared(
                r#"
                DROP TABLE blocked_devices;
                DROP TABLE devices;
                "#,
            )
            .await?;
        Ok(())
    }
}
