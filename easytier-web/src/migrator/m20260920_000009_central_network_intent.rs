use sea_orm_migration::prelude::*;

pub struct Migration;

impl MigrationName for Migration {
    fn name(&self) -> &str {
        "m20260920_000009_central_network_intent"
    }
}

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .get_connection()
            .execute_unprepared(
                r#"
                CREATE TABLE networks (
                    user_id INTEGER NOT NULL,
                    id TEXT NOT NULL,
                    display_name TEXT NOT NULL,
                    network_name TEXT NOT NULL,
                    network_secret TEXT NOT NULL,
                    networking_method TEXT NOT NULL
                        CHECK (networking_method IN (
                            'PublicServer', 'Manual', 'Standalone', 'Gateway'
                        )),
                    public_server_url TEXT,
                    peer_urls TEXT NOT NULL DEFAULT '[]',
                    virtual_cidr TEXT,
                    secure_mode INTEGER NOT NULL DEFAULT 0
                        CHECK (secure_mode IN (0, 1)),
                    acl_policy TEXT,
                    create_time TEXT NOT NULL,
                    update_time TEXT NOT NULL,
                    PRIMARY KEY (user_id, id),
                    CONSTRAINT uq_networks_tenant_name
                        UNIQUE (user_id, network_name),
                    CONSTRAINT fk_networks_user_id_to_users_id
                        FOREIGN KEY (user_id) REFERENCES users(id)
                        ON DELETE CASCADE
                        ON UPDATE CASCADE
                );

                CREATE UNIQUE INDEX idx_networks_gateway_name
                    ON networks(network_name)
                    WHERE networking_method = 'Gateway';

                CREATE TABLE network_credentials (
                    user_id INTEGER NOT NULL,
                    network_id TEXT NOT NULL,
                    credential_id TEXT NOT NULL,
                    credential_secret TEXT NOT NULL,
                    expiry_unix INTEGER NOT NULL,
                    acl_groups TEXT NOT NULL DEFAULT '[]',
                    allow_relay INTEGER NOT NULL DEFAULT 0
                        CHECK (allow_relay IN (0, 1)),
                    allowed_proxy_cidrs TEXT NOT NULL DEFAULT '[]',
                    reusable INTEGER NOT NULL DEFAULT 0
                        CHECK (reusable IN (0, 1)),
                    create_time TEXT NOT NULL,
                    update_time TEXT NOT NULL,
                    PRIMARY KEY (user_id, network_id, credential_id),
                    CONSTRAINT fk_network_credentials_tenant_network
                        FOREIGN KEY (user_id, network_id)
                        REFERENCES networks(user_id, id)
                        ON DELETE CASCADE
                        ON UPDATE CASCADE
                );

                CREATE TABLE network_members (
                    user_id INTEGER NOT NULL,
                    network_id TEXT NOT NULL,
                    id TEXT NOT NULL,
                    device_id TEXT NOT NULL,
                    hostname_override TEXT,
                    virtual_ipv4 TEXT,
                    override_config TEXT,
                    credential_id TEXT,
                    acl_group_secret TEXT,
                    create_time TEXT NOT NULL,
                    update_time TEXT NOT NULL,
                    PRIMARY KEY (user_id, network_id, id),
                    CONSTRAINT uq_network_members_tenant_device
                        UNIQUE (user_id, network_id, device_id),
                    CONSTRAINT fk_network_members_tenant_network
                        FOREIGN KEY (user_id, network_id)
                        REFERENCES networks(user_id, id)
                        ON DELETE CASCADE
                        ON UPDATE CASCADE,
                    CONSTRAINT fk_network_members_tenant_device
                        FOREIGN KEY (user_id, device_id)
                        REFERENCES devices(user_id, machine_id)
                        ON DELETE CASCADE
                        ON UPDATE CASCADE,
                    CONSTRAINT fk_network_members_tenant_credential
                        FOREIGN KEY (user_id, network_id, credential_id)
                        REFERENCES network_credentials(
                            user_id, network_id, credential_id
                        )
                        ON DELETE RESTRICT
                        ON UPDATE CASCADE,
                    CONSTRAINT ck_network_members_temporary_secret
                        CHECK (
                            credential_id IS NULL
                            OR acl_group_secret IS NULL
                        )
                );

                CREATE UNIQUE INDEX idx_network_members_dedicated_credential
                    ON network_members(user_id, network_id, credential_id)
                    WHERE credential_id IS NOT NULL;
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
                DROP TABLE network_members;
                DROP TABLE network_credentials;
                DROP TABLE networks;
                "#,
            )
            .await?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use sea_orm::{ConnectionTrait as _, Database};
    use sea_orm_migration::MigratorTrait as _;

    #[tokio::test]
    async fn tenant_scope_is_part_of_every_intent_foreign_key() {
        let db = Database::connect("sqlite::memory:").await.unwrap();
        crate::migrator::Migrator::up(&db, None).await.unwrap();
        db.execute_unprepared(
            r#"
            INSERT INTO networks (
                user_id, id, display_name, network_name, network_secret,
                networking_method, create_time, update_time
            ) VALUES
                (1, 'same-id', 'one', 'one', 'secret', 'Standalone', 'now', 'now'),
                (2, 'same-id', 'two', 'two', 'secret', 'Standalone', 'now', 'now');
            INSERT INTO network_credentials (
                user_id, network_id, credential_id, credential_secret,
                expiry_unix, create_time, update_time
            ) VALUES
                (1, 'same-id', 'only-user-one', 'secret', 2000000000, 'now', 'now');
            INSERT INTO devices (
                user_id, machine_id, first_seen_time, last_seen_time
            ) VALUES
                (1, 'device-one', 'now', 'now'),
                (2, 'device-two', 'now', 'now');
            "#,
        )
        .await
        .unwrap();

        let cross_tenant_credential = db
            .execute_unprepared(
                r#"
                INSERT INTO network_members (
                    user_id, network_id, id, device_id, credential_id,
                    create_time, update_time
                ) VALUES (
                    2, 'same-id', 'member', 'device-two', 'only-user-one',
                    'now', 'now'
                );
                "#,
            )
            .await;
        assert!(cross_tenant_credential.is_err());

        let cross_tenant_device = db
            .execute_unprepared(
                r#"
                INSERT INTO network_members (
                    user_id, network_id, id, device_id,
                    create_time, update_time
                ) VALUES (
                    2, 'same-id', 'member', 'device-one',
                    'now', 'now'
                );
                "#,
            )
            .await;
        assert!(cross_tenant_device.is_err());

        let missing_tenant_network = db
            .execute_unprepared(
                r#"
                INSERT INTO network_credentials (
                    user_id, network_id, credential_id, credential_secret,
                    expiry_unix, create_time, update_time
                ) VALUES (
                    2, 'user-one-only-network', 'credential', 'secret',
                    2000000000, 'now', 'now'
                );
                "#,
            )
            .await;
        assert!(missing_tenant_network.is_err());
    }

    #[tokio::test]
    async fn gateway_names_are_globally_unique() {
        let db = Database::connect("sqlite::memory:").await.unwrap();
        crate::migrator::Migrator::up(&db, None).await.unwrap();
        db.execute_unprepared(
            r#"
            INSERT INTO networks (
                user_id, id, display_name, network_name, network_secret,
                networking_method, create_time, update_time
            ) VALUES (
                1, 'gateway-one', 'gateway', 'shared-name', 'secret',
                'Gateway', 'now', 'now'
            );
            "#,
        )
        .await
        .unwrap();

        let duplicate = db
            .execute_unprepared(
                r#"
                INSERT INTO networks (
                    user_id, id, display_name, network_name, network_secret,
                    networking_method, create_time, update_time
                ) VALUES (
                    2, 'gateway-two', 'gateway', 'shared-name', 'secret',
                    'Gateway', 'now', 'now'
                );
                "#,
            )
            .await;
        assert!(duplicate.is_err());
    }

    #[tokio::test]
    async fn temporary_member_cannot_store_an_acl_group_secret() {
        let db = Database::connect("sqlite::memory:").await.unwrap();
        crate::migrator::Migrator::up(&db, None).await.unwrap();
        db.execute_unprepared(
            r#"
            INSERT INTO networks (
                user_id, id, display_name, network_name, network_secret,
                networking_method, create_time, update_time
            ) VALUES (
                1, 'network', 'network', 'network', 'secret',
                'Standalone', 'now', 'now'
            );
            INSERT INTO network_credentials (
                user_id, network_id, credential_id, credential_secret,
                expiry_unix, acl_groups, reusable, create_time, update_time
            ) VALUES (
                1, 'network', 'temporary', 'secret', 2000000000,
                '["member:1"]', 0, 'now', 'now'
            );
            INSERT INTO devices (
                user_id, machine_id, first_seen_time, last_seen_time
            ) VALUES
                (1, 'device-one', 'now', 'now'),
                (1, 'device-two', 'now', 'now');
            "#,
        )
        .await
        .unwrap();

        let result = db
            .execute_unprepared(
                r#"
                INSERT INTO network_members (
                    user_id, network_id, id, device_id, credential_id,
                    acl_group_secret, create_time, update_time
                ) VALUES (
                    1, 'network', 'member', 'device-one', 'temporary',
                    'must-not-be-stored', 'now', 'now'
                );
                "#,
            )
            .await;
        let error = result.unwrap_err().to_string();
        assert!(
            error.contains("ck_network_members_temporary_secret"),
            "{error}"
        );

        db.execute_unprepared(
            r#"
            INSERT INTO network_members (
                user_id, network_id, id, device_id, credential_id,
                create_time, update_time
            ) VALUES (
                1, 'network', 'member-one', 'device-one', 'temporary',
                'now', 'now'
            );
            "#,
        )
        .await
        .unwrap();
        let reused = db
            .execute_unprepared(
                r#"
                INSERT INTO network_members (
                    user_id, network_id, id, device_id, credential_id,
                    create_time, update_time
                ) VALUES (
                    1, 'network', 'member-two', 'device-two', 'temporary',
                    'now', 'now'
                );
                "#,
            )
            .await;
        assert!(reused.is_err());
    }
}
