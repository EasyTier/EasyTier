use sea_orm_migration::prelude::*;

#[derive(DeriveMigrationName)]
pub struct Migration;

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        // Existing members are active; the column only records suspensions
        // issued after this migration.
        manager
            .get_connection()
            .execute_unprepared(
                "ALTER TABLE network_members ADD COLUMN enabled INTEGER NOT NULL DEFAULT 1",
            )
            .await?;
        Ok(())
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .get_connection()
            .execute_unprepared("ALTER TABLE network_members DROP COLUMN enabled")
            .await?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use sea_orm::{Database, Statement};

    #[tokio::test]
    async fn migration_defaults_existing_members_to_enabled() {
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
                "SELECT enabled FROM network_members".to_owned(),
            ))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(row.try_get::<i32>("", "enabled").unwrap(), 1);
        Migration.down(&manager).await.unwrap();
    }
}
