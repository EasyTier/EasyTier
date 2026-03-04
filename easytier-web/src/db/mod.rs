// sea-orm-cli generate entity -u sqlite:./et.db -o easytier-web/src/db/entity/ --with-serde both --with-copy-enums
#[allow(unused_imports)]
pub mod entity;

use easytier::{
    launcher::NetworkConfig,
    rpc_service::remote_client::{ListNetworkProps, Storage},
};
use entity::user_running_network_configs;
use sea_orm::{
    prelude::Expr, sea_query::OnConflict, ColumnTrait as _, DatabaseConnection, DbErr, EntityTrait,
    QueryFilter as _, Set, SqlxSqliteConnector, TransactionTrait as _,
};
use sea_orm_migration::MigratorTrait as _;
use sqlx::{migrate::MigrateDatabase as _, types::chrono, Sqlite, SqlitePool};
use uuid::Uuid;

use crate::migrator;
use async_trait::async_trait;

pub type UserIdInDb = i32;

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

    /// `password_hash` must be pre-hashed by the caller.
    /// Creates user + joins "users" group in one transaction. Returns the created user model.
    pub async fn create_user_and_join_users_group(
        &self,
        username: &str,
        password_hash: String,
    ) -> Result<entity::users::Model, DbErr> {
        use entity::{groups, users, users_groups};

        let txn = self.orm_db().begin().await?;

        let user_active = users::ActiveModel {
            username: Set(username.to_string()),
            password: Set(password_hash),
            ..Default::default()
        };
        let insert_result = users::Entity::insert(user_active).exec(&txn).await?;

        let new_user = users::Entity::find_by_id(insert_result.last_insert_id)
            .one(&txn)
            .await?
            .ok_or_else(|| DbErr::Custom("Failed to find newly created user".to_string()))?;

        let users_group = groups::Entity::find()
            .filter(groups::Column::Name.eq("users"))
            .one(&txn)
            .await?
            .ok_or_else(|| DbErr::Custom("Users group not found".to_string()))?;

        let ug_active = users_groups::ActiveModel {
            user_id: Set(new_user.id),
            group_id: Set(users_group.id),
            ..Default::default()
        };
        users_groups::Entity::insert(ug_active).exec(&txn).await?;

        txn.commit().await?;

        Ok(new_user)
    }

    pub async fn auto_create_user(&self, username: &str) -> Result<entity::users::Model, DbErr> {
        let random_password = uuid::Uuid::new_v4().to_string();
        let hashed_password =
            tokio::task::spawn_blocking(move || password_auth::generate_hash(&random_password))
                .await
                .map_err(|e| DbErr::Custom(format!("Failed to hash password: {}", e)))?;
        self.create_user_and_join_users_group(username, hashed_password)
            .await
    }

    // TODO: currently we don't have a token system, so we just use the user name as token
    pub async fn get_user_id_by_token<T: ToString>(
        &self,
        token: T,
    ) -> Result<Option<UserIdInDb>, DbErr> {
        self.get_user_id(token).await
    }
}

#[async_trait]
impl Storage<(UserIdInDb, Uuid), user_running_network_configs::Model, DbErr> for Db {
    async fn insert_or_update_user_network_config(
        &self,
        (user_id, device_id): (UserIdInDb, Uuid),
        network_inst_id: Uuid,
        network_config: NetworkConfig,
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
            network_config: sea_orm::Set(
                serde_json::to_string(&network_config).map_err(|e| DbErr::Json(e.to_string()))?,
            ),
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

    async fn delete_network_configs(
        &self,
        (user_id, _): (UserIdInDb, Uuid),
        network_inst_ids: &[Uuid],
    ) -> Result<(), DbErr> {
        use entity::user_running_network_configs as urnc;

        urnc::Entity::delete_many()
            .filter(urnc::Column::UserId.eq(user_id))
            .filter(
                urnc::Column::NetworkInstanceId
                    .is_in(network_inst_ids.iter().map(|id| id.to_string())),
            )
            .exec(self.orm_db())
            .await?;

        Ok(())
    }

    async fn update_network_config_state(
        &self,
        (user_id, _): (UserIdInDb, Uuid),
        network_inst_id: Uuid,
        disabled: bool,
    ) -> Result<(), DbErr> {
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

        Ok(())
    }

    async fn list_network_configs(
        &self,
        (user_id, device_id): (UserIdInDb, Uuid),
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
        let configs = if !device_id.is_nil() {
            configs.filter(urnc::Column::DeviceId.eq(device_id.to_string()))
        } else {
            configs
        };

        let configs = configs.all(self.orm_db()).await?;

        Ok(configs)
    }

    async fn get_network_config(
        &self,
        (user_id, device_id): (UserIdInDb, Uuid),
        network_inst_id: &str,
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
}

#[cfg(test)]
mod tests {
    use easytier::{proto::api::manage::NetworkConfig, rpc_service::remote_client::Storage};
    use sea_orm::{ColumnTrait, EntityTrait, QueryFilter as _};

    use crate::db::{entity::user_running_network_configs, Db, ListNetworkProps};

    #[tokio::test]
    async fn test_user_network_config_management() {
        let db = Db::memory_db().await;
        let user_id = 1;
        let network_config = NetworkConfig {
            network_name: Some("test_config".to_string()),
            ..Default::default()
        };
        let network_config_json = serde_json::to_string(&network_config).unwrap();
        let inst_id = uuid::Uuid::new_v4();
        let device_id = uuid::Uuid::new_v4();

        db.insert_or_update_user_network_config((user_id, device_id), inst_id, network_config)
            .await
            .unwrap();

        let result = user_running_network_configs::Entity::find()
            .filter(user_running_network_configs::Column::UserId.eq(user_id))
            .one(db.orm_db())
            .await
            .unwrap()
            .unwrap();
        println!("{:?}", result);
        assert_eq!(result.network_config, network_config_json);

        // overwrite the config
        let network_config = NetworkConfig {
            network_name: Some("test_config2".to_string()),
            ..Default::default()
        };
        let network_config_json = serde_json::to_string(&network_config).unwrap();
        db.insert_or_update_user_network_config((user_id, device_id), inst_id, network_config)
            .await
            .unwrap();

        let result2 = user_running_network_configs::Entity::find()
            .filter(user_running_network_configs::Column::UserId.eq(user_id))
            .one(db.orm_db())
            .await
            .unwrap()
            .unwrap();
        println!("device: {}, {:?}", device_id, result2);
        assert_eq!(result2.network_config, network_config_json);

        assert_eq!(result.create_time, result2.create_time);
        assert_ne!(result.update_time, result2.update_time);

        assert_eq!(
            db.list_network_configs((user_id, device_id), ListNetworkProps::All)
                .await
                .unwrap()
                .len(),
            1
        );

        db.delete_network_configs((user_id, device_id), &[inst_id])
            .await
            .unwrap();
        let result3 = user_running_network_configs::Entity::find()
            .filter(user_running_network_configs::Column::UserId.eq(user_id))
            .one(db.orm_db())
            .await
            .unwrap();
        assert!(result3.is_none());
    }
}
