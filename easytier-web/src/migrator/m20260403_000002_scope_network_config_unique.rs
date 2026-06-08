use sea_orm_migration::prelude::*;

pub struct Migration;

impl MigrationName for Migration {
    fn name(&self) -> &str {
        "m20260403_000002_scope_network_config_unique"
    }
}

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        let db = manager.get_connection();

        db.execute_unprepared(
            r#"
            CREATE TABLE user_running_network_configs_new (
                id INTEGER PRIMARY KEY AUTOINCREMENT NOT NULL,
                user_id INTEGER NOT NULL,
                device_id TEXT NOT NULL,
                network_instance_id TEXT NOT NULL,
                network_config TEXT NOT NULL,
                disabled BOOLEAN NOT NULL DEFAULT FALSE,
                create_time TEXT NOT NULL,
                update_time TEXT NOT NULL,
                CONSTRAINT fk_user_running_network_configs_user_id_to_users_id
                    FOREIGN KEY (user_id) REFERENCES users(id)
                    ON DELETE CASCADE
                    ON UPDATE CASCADE
            );

            INSERT INTO user_running_network_configs_new (
                id,
                user_id,
                device_id,
                network_instance_id,
                network_config,
                disabled,
                create_time,
                update_time
            )
            SELECT
                id,
                user_id,
                device_id,
                network_instance_id,
                network_config,
                disabled,
                create_time,
                update_time
            FROM user_running_network_configs;

            DROP TABLE user_running_network_configs;
            ALTER TABLE user_running_network_configs_new RENAME TO user_running_network_configs;

            CREATE INDEX idx_user_running_network_configs_user_id
                ON user_running_network_configs(user_id);
            CREATE UNIQUE INDEX idx_user_running_network_configs_scope_inst
                ON user_running_network_configs(user_id, device_id, network_instance_id);
            "#,
        )
        .await?;

        Ok(())
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        let db = manager.get_connection();

        db.execute_unprepared(
            r#"
            CREATE TABLE user_running_network_configs_old (
                id INTEGER PRIMARY KEY AUTOINCREMENT NOT NULL,
                user_id INTEGER NOT NULL,
                device_id TEXT NOT NULL,
                network_instance_id TEXT NOT NULL UNIQUE,
                network_config TEXT NOT NULL,
                disabled BOOLEAN NOT NULL DEFAULT FALSE,
                create_time TEXT NOT NULL,
                update_time TEXT NOT NULL,
                CONSTRAINT fk_user_running_network_configs_user_id_to_users_id
                    FOREIGN KEY (user_id) REFERENCES users(id)
                    ON DELETE CASCADE
                    ON UPDATE CASCADE
            );

            INSERT INTO user_running_network_configs_old (
                id,
                user_id,
                device_id,
                network_instance_id,
                network_config,
                disabled,
                create_time,
                update_time
            )
            SELECT
                id,
                user_id,
                device_id,
                network_instance_id,
                network_config,
                disabled,
                create_time,
                update_time
            FROM user_running_network_configs;

            DROP TABLE user_running_network_configs;
            ALTER TABLE user_running_network_configs_old RENAME TO user_running_network_configs;

            CREATE INDEX idx_user_running_network_configs_user_id
                ON user_running_network_configs(user_id);
            "#,
        )
        .await?;

        Ok(())
    }
}
