use sea_orm_migration::prelude::*;

mod m20241029_000001_init;
mod m20260403_000002_scope_network_config_unique;

pub struct Migrator;

#[async_trait::async_trait]
impl MigratorTrait for Migrator {
    fn migrations() -> Vec<Box<dyn MigrationTrait>> {
        vec![
            Box::new(m20241029_000001_init::Migration),
            Box::new(m20260403_000002_scope_network_config_unique::Migration),
        ]
    }
}
