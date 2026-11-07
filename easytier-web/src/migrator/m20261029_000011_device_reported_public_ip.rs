use sea_orm_migration::prelude::*;

#[derive(DeriveMigrationName)]
pub struct Migration;

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        // Last public IP the node reported via STUN, kept so offline devices
        // still show it. Empty until a node that supports reporting checks in.
        manager
            .get_connection()
            .execute_unprepared(
                "ALTER TABLE devices ADD COLUMN reported_public_ip TEXT NOT NULL DEFAULT ''",
            )
            .await?;
        Ok(())
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .get_connection()
            .execute_unprepared("ALTER TABLE devices DROP COLUMN reported_public_ip")
            .await?;
        Ok(())
    }
}
