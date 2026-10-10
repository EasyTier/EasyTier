use sea_orm_migration::prelude::*;

#[derive(DeriveMigrationName)]
pub struct Migration;

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        // Older rows do not record whether virtual_ipv4 was assigned or typed
        // by the administrator. Preserve those values as explicit addresses.
        manager
            .get_connection()
            .execute_unprepared("ALTER TABLE network_members ADD COLUMN allocated_ipv4 TEXT")
            .await?;
        Ok(())
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .get_connection()
            .execute_unprepared(
                "UPDATE network_members SET virtual_ipv4 = COALESCE(virtual_ipv4, allocated_ipv4); \
                 ALTER TABLE network_members DROP COLUMN allocated_ipv4",
            )
            .await?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use sea_orm::{Database, Statement};

    #[tokio::test]
    async fn migration_preserves_addresses_without_guessing_their_origin() {
        let db = Database::connect("sqlite::memory:").await.unwrap();
        db.execute_unprepared(
            "CREATE TABLE network_members (virtual_ipv4 TEXT); \
             INSERT INTO network_members VALUES ('10.42.0.1')",
        )
        .await
        .unwrap();
        let manager = SchemaManager::new(&db);
        Migration.up(&manager).await.unwrap();
        let row = db
            .query_one(Statement::from_string(
                db.get_database_backend(),
                "SELECT virtual_ipv4, allocated_ipv4 FROM network_members".to_owned(),
            ))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(
            row.try_get::<String>("", "virtual_ipv4").unwrap(),
            "10.42.0.1"
        );
        assert!(
            row.try_get::<Option<String>>("", "allocated_ipv4")
                .unwrap()
                .is_none()
        );
        Migration.down(&manager).await.unwrap();
    }
}
