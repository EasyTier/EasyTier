// sea-orm-cli generate entity -u sqlite:./et.db -o easytier-web/src/db/entity/ --with-serde both --with-copy-enums
#[allow(unused_imports)]
pub mod entity;

use entity::user_running_network_configs;
use sea_orm::{
    prelude::Expr, sea_query::OnConflict, ActiveModelTrait, ColumnTrait as _, DatabaseConnection,
    DbErr, EntityTrait, QueryFilter as _, SqlxSqliteConnector, TransactionTrait as _,
};
use sea_orm_migration::MigratorTrait as _;
use sqlx::{migrate::MigrateDatabase as _, types::chrono, Sqlite, SqlitePool};

use crate::migrator;

type UserIdInDb = i32;

pub enum ListNetworkProps {
    All,
    EnabledOnly,
    DisabledOnly,
}

#[derive(Debug, Clone)]
pub struct Db {
    db_path: String,
    db: SqlitePool,
    orm_db: DatabaseConnection,
}

impl Db {
    pub async fn new<T: ToString>(db_path: T) -> anyhow::Result<Self> {
        let db = Self::prepare_db(db_path.to_string().as_str()).await?;
        let orm_db = SqlxSqliteConnector::from_sqlx_sqlite_pool(db.clone());
        migrator::Migrator::up(&orm_db, None).await?;

        Ok(Self {
            db_path: db_path.to_string(),
            db,
            orm_db,
        })
    }

    pub async fn memory_db() -> Self {
        Self::new(":memory:").await.unwrap()
    }

    #[tracing::instrument(ret)]
    async fn prepare_db(db_path: &str) -> anyhow::Result<SqlitePool> {
        if !Sqlite::database_exists(db_path).await.unwrap_or(false) {
            tracing::info!("Database not found, creating a new one");
            Sqlite::create_database(db_path).await?;
        }

        let db = sqlx::pool::PoolOptions::new()
            .max_lifetime(None)
            .idle_timeout(None)
            .connect(db_path)
            .await?;

        Ok(db)
    }

    pub fn inner(&self) -> SqlitePool {
        self.db.clone()
    }

    pub fn orm_db(&self) -> &DatabaseConnection {
        &self.orm_db
    }

    pub async fn insert_or_update_user_network_config<T: ToString>(
        &self,
        user_id: UserIdInDb,
        device_id: uuid::Uuid,
        network_inst_id: uuid::Uuid,
        network_config: T,
    ) -> Result<(), DbErr> {
        let txn = self.orm_db().begin().await?;

        use entity::user_running_network_configs as urnc;

        let on_conflict = OnConflict::column(urnc::Column::NetworkInstanceId)
            .update_columns([
                urnc::Column::NetworkConfig,
                urnc::Column::Disabled,
                urnc::Column::UpdateTime,
            ])
            .to_owned();
        let insert_m = urnc::ActiveModel {
            user_id: sea_orm::Set(user_id),
            device_id: sea_orm::Set(device_id.to_string()),
            network_instance_id: sea_orm::Set(network_inst_id.to_string()),
            network_config: sea_orm::Set(network_config.to_string()),
            disabled: sea_orm::Set(false),
            create_time: sea_orm::Set(chrono::Local::now().fixed_offset()),
            update_time: sea_orm::Set(chrono::Local::now().fixed_offset()),
            ..Default::default()
        };
        urnc::Entity::insert(insert_m)
            .on_conflict(on_conflict)
            .do_nothing()
            .exec(&txn)
            .await?;

        txn.commit().await
    }

    pub async fn delete_network_config(
        &self,
        user_id: UserIdInDb,
        network_inst_id: uuid::Uuid,
    ) -> Result<(), DbErr> {
        use entity::user_running_network_configs as urnc;

        urnc::Entity::delete_many()
            .filter(urnc::Column::UserId.eq(user_id))
            .filter(urnc::Column::NetworkInstanceId.eq(network_inst_id.to_string()))
            .exec(self.orm_db())
            .await?;

        Ok(())
    }

    pub async fn update_network_config_state(
        &self,
        user_id: UserIdInDb,
        network_inst_id: uuid::Uuid,
        disabled: bool,
    ) -> Result<entity::user_running_network_configs::Model, DbErr> {
        use entity::user_running_network_configs as urnc;

        urnc::Entity::update_many()
            .filter(urnc::Column::UserId.eq(user_id))
            .filter(urnc::Column::NetworkInstanceId.eq(network_inst_id.to_string()))
            .col_expr(urnc::Column::Disabled, Expr::value(disabled))
            .col_expr(
                urnc::Column::UpdateTime,
                Expr::value(chrono::Local::now().fixed_offset()),
            )
            .exec(self.orm_db())
            .await?;

        urnc::Entity::find()
            .filter(urnc::Column::UserId.eq(user_id))
            .filter(urnc::Column::NetworkInstanceId.eq(network_inst_id.to_string()))
            .one(self.orm_db())
            .await?
            .ok_or(DbErr::RecordNotFound(format!(
                "Network config not found for user {} and network instance {}",
                user_id, network_inst_id
            )))
    }

    pub async fn list_network_configs(
        &self,
        user_id: UserIdInDb,
        device_id: Option<uuid::Uuid>,
        props: ListNetworkProps,
    ) -> Result<Vec<user_running_network_configs::Model>, DbErr> {
        use entity::user_running_network_configs as urnc;

        let configs = urnc::Entity::find().filter(urnc::Column::UserId.eq(user_id));
        let configs = if matches!(
            props,
            ListNetworkProps::EnabledOnly | ListNetworkProps::DisabledOnly
        ) {
            configs
                .filter(urnc::Column::Disabled.eq(matches!(props, ListNetworkProps::DisabledOnly)))
        } else {
            configs
        };
        let configs = if let Some(device_id) = device_id {
            configs.filter(urnc::Column::DeviceId.eq(device_id.to_string()))
        } else {
            configs
        };

        let configs = configs.all(self.orm_db()).await?;

        Ok(configs)
    }

    pub async fn get_network_config(
        &self,
        user_id: UserIdInDb,
        device_id: &uuid::Uuid,
        network_inst_id: &String,
    ) -> Result<Option<user_running_network_configs::Model>, DbErr> {
        use entity::user_running_network_configs as urnc;

        let config = urnc::Entity::find()
            .filter(urnc::Column::UserId.eq(user_id))
            .filter(urnc::Column::DeviceId.eq(device_id.to_string()))
            .filter(urnc::Column::NetworkInstanceId.eq(network_inst_id))
            .one(self.orm_db())
            .await?;

        Ok(config)
    }

    pub async fn get_user_id<T: ToString>(
        &self,
        user_name: T,
    ) -> Result<Option<UserIdInDb>, DbErr> {
        use entity::users as u;

        let user = u::Entity::find()
            .filter(u::Column::Username.eq(user_name.to_string()))
            .one(self.orm_db())
            .await?;

        Ok(user.map(|u| u.id))
    }

    // TODO: currently we don't have a token system, so we just use the user name as token
    pub async fn get_user_id_by_token<T: ToString>(
        &self,
        token: T,
    ) -> Result<Option<UserIdInDb>, DbErr> {
        self.get_user_id(token).await
    }
}

#[cfg(test)]
mod tests {
    use sea_orm::{ColumnTrait, EntityTrait, QueryFilter as _};

    use crate::db::{entity::user_running_network_configs, Db, ListNetworkProps};

    #[tokio::test]
    async fn test_user_network_config_management() {
        let db = Db::memory_db().await;
        let user_id = 1;
        let network_config = "test_config";
        let inst_id = uuid::Uuid::new_v4();
        let device_id = uuid::Uuid::new_v4();

        db.insert_or_update_user_network_config(user_id, device_id, inst_id, network_config)
            .await
            .unwrap();

        let result = user_running_network_configs::Entity::find()
            .filter(user_running_network_configs::Column::UserId.eq(user_id))
            .one(db.orm_db())
            .await
            .unwrap()
            .unwrap();
        println!("{:?}", result);
        assert_eq!(result.network_config, network_config);

        // overwrite the config
        let network_config = "test_config2";
        db.insert_or_update_user_network_config(user_id, device_id, inst_id, network_config)
            .await
            .unwrap();

        let result2 = user_running_network_configs::Entity::find()
            .filter(user_running_network_configs::Column::UserId.eq(user_id))
            .one(db.orm_db())
            .await
            .unwrap()
            .unwrap();
        println!("device: {}, {:?}", device_id, result2);
        assert_eq!(result2.network_config, network_config);

        assert_eq!(result.create_time, result2.create_time);
        assert_ne!(result.update_time, result2.update_time);

        assert_eq!(
            db.list_network_configs(user_id, Some(device_id), ListNetworkProps::All)
                .await
                .unwrap()
                .len(),
            1
        );

        db.delete_network_config(user_id, inst_id).await.unwrap();
        let result3 = user_running_network_configs::Entity::find()
            .filter(user_running_network_configs::Column::UserId.eq(user_id))
            .one(db.orm_db())
            .await
            .unwrap();
        assert!(result3.is_none());
    }
}
