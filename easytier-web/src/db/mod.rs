// sea-orm-cli generate entity -u sqlite:./et.db -o easytier-web/src/db/entity/ --with-serde both --with-copy-enums
#[allow(unused_imports)]
pub mod entity;

use easytier::common::config::{ConfigSource, NetworkConfig};
use easytier_core::management::remote_client::{ListNetworkProps, Storage};
use entity::user_running_network_configs;
use sea_orm::{
    ColumnTrait as _, DatabaseConnection, DbErr, EntityTrait, QueryFilter as _, Set,
    SqlxSqliteConnector, TransactionTrait as _, sea_query::OnConflict,
};
use sea_orm_migration::MigratorTrait as _;
use sqlx::{Sqlite, SqlitePool, migrate::MigrateDatabase as _, types::chrono};
use std::collections::{HashMap, HashSet};
#[cfg(unix)]
use std::os::unix::fs::PermissionsExt as _;
use uuid::Uuid;

use crate::migrator;
use async_trait::async_trait;

pub type UserIdInDb = i32;

#[derive(Debug)]
pub(crate) struct ManagedConfigUpsert {
    pub instance_id: Uuid,
    pub network_config: NetworkConfig,
}

#[derive(Debug, Clone)]
pub(crate) enum ManagedConfigExpectedRevision {
    Any,
    Exact(Option<String>),
}

#[derive(Debug)]
pub(crate) enum ManagedConfigUpdate {
    Full {
        upserts: Vec<ManagedConfigUpsert>,
        target_revision: Option<String>,
        expected_revision: ManagedConfigExpectedRevision,
    },
    Patch {
        upserts: Vec<ManagedConfigUpsert>,
        delete_instance_ids: Vec<Uuid>,
        target_revision: String,
        expected_revision: String,
    },
}

#[derive(Debug, PartialEq, Eq)]
pub(crate) enum ManagedConfigApplyResult {
    Applied,
    AlreadyApplied,
    RevisionConflict {
        expected: Option<String>,
        current: Option<String>,
    },
    OwnershipConflict {
        instance_id: Uuid,
    },
}

fn sqlx_db_error(error: sqlx::Error) -> DbErr {
    DbErr::Custom(error.to_string())
}

async fn read_managed_config_revision(
    transaction: &mut sqlx::Transaction<'_, Sqlite>,
    user_id: UserIdInDb,
    device_id: Uuid,
) -> Result<Option<String>, DbErr> {
    sqlx::query_scalar(
        r#"
        SELECT config_revision
        FROM managed_config_revisions
        WHERE user_id = ? AND device_id = ?
        "#,
    )
    .bind(user_id)
    .bind(device_id.to_string())
    .fetch_optional(&mut **transaction)
    .await
    .map_err(sqlx_db_error)
}

async fn clear_managed_config_revision(
    transaction: &mut sqlx::Transaction<'_, Sqlite>,
    user_id: UserIdInDb,
    device_id: Uuid,
) -> Result<(), DbErr> {
    sqlx::query(
        r#"
        DELETE FROM managed_config_revisions
        WHERE user_id = ? AND device_id = ?
        "#,
    )
    .bind(user_id)
    .bind(device_id.to_string())
    .execute(&mut **transaction)
    .await
    .map_err(sqlx_db_error)?;
    Ok(())
}

async fn write_managed_config_revision(
    transaction: &mut sqlx::Transaction<'_, Sqlite>,
    user_id: UserIdInDb,
    device_id: Uuid,
    config_revision: &str,
) -> Result<(), DbErr> {
    let now = chrono::Local::now().fixed_offset();
    sqlx::query(
        r#"
        INSERT INTO managed_config_revisions (
            user_id, device_id, config_revision, create_time, update_time
        ) VALUES (?, ?, ?, ?, ?)
        ON CONFLICT(user_id, device_id) DO UPDATE SET
            config_revision = excluded.config_revision,
            update_time = excluded.update_time
        "#,
    )
    .bind(user_id)
    .bind(device_id.to_string())
    .bind(config_revision)
    .bind(now)
    .bind(now)
    .execute(&mut **transaction)
    .await
    .map_err(sqlx_db_error)?;
    Ok(())
}

async fn read_config_source(
    transaction: &mut sqlx::Transaction<'_, Sqlite>,
    user_id: UserIdInDb,
    device_id: Uuid,
    instance_id: Uuid,
) -> Result<Option<String>, DbErr> {
    sqlx::query_scalar(
        r#"
        SELECT source
        FROM user_running_network_configs
        WHERE user_id = ? AND device_id = ? AND network_instance_id = ?
        "#,
    )
    .bind(user_id)
    .bind(device_id.to_string())
    .bind(instance_id.to_string())
    .fetch_optional(&mut **transaction)
    .await
    .map_err(sqlx_db_error)
}

async fn upsert_network_config(
    transaction: &mut sqlx::Transaction<'_, Sqlite>,
    user_id: UserIdInDb,
    device_id: Uuid,
    instance_id: Uuid,
    network_config: &str,
    source: ConfigSource,
    web_only_update: bool,
) -> Result<bool, DbErr> {
    let now = chrono::Local::now().fixed_offset();
    let mut query = r#"
        INSERT INTO user_running_network_configs (
            user_id, device_id, network_instance_id, network_config,
            source, disabled, create_time, update_time
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        ON CONFLICT(user_id, device_id, network_instance_id) DO UPDATE SET
            network_config = excluded.network_config,
            source = excluded.source,
            disabled = excluded.disabled,
            update_time = excluded.update_time
    "#
    .to_string();
    if web_only_update {
        query.push_str(" WHERE user_running_network_configs.source = 'web'");
    }
    let result = sqlx::query(&query)
        .bind(user_id)
        .bind(device_id.to_string())
        .bind(instance_id.to_string())
        .bind(network_config)
        .bind(source.as_str())
        .bind(false)
        .bind(now)
        .bind(now)
        .execute(&mut **transaction)
        .await
        .map_err(sqlx_db_error)?;
    Ok(result.rows_affected() > 0)
}

#[cfg(unix)]
fn restrict_database_file_permissions(db_path: &str) -> anyhow::Result<()> {
    if db_path.ends_with(":memory:") || db_path.contains("mode=memory") {
        return Ok(());
    }
    let path = db_path
        .strip_prefix("sqlite://")
        .or_else(|| db_path.strip_prefix("sqlite:"))
        .unwrap_or(db_path);
    let path = path
        .strip_prefix("file:")
        .unwrap_or(path)
        .split('?')
        .next()
        .filter(|path| !path.is_empty());
    let Some(path) = path else {
        return Ok(());
    };
    let mut permissions = std::fs::metadata(path)?.permissions();
    permissions.set_mode(0o600);
    std::fs::set_permissions(path, permissions)?;
    Ok(())
}

#[cfg(not(unix))]
fn restrict_database_file_permissions(_db_path: &str) -> anyhow::Result<()> {
    Ok(())
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
        restrict_database_file_permissions(db_path)?;

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

    pub async fn get_managed_config_revision(
        &self,
        (user_id, device_id): (UserIdInDb, Uuid),
    ) -> Result<Option<String>, DbErr> {
        use entity::managed_config_revisions as mcr;

        let revision = mcr::Entity::find()
            .filter(mcr::Column::UserId.eq(user_id))
            .filter(mcr::Column::DeviceId.eq(device_id.to_string()))
            .one(self.orm_db())
            .await?;

        Ok(revision.map(|row| row.config_revision))
    }

    pub async fn set_managed_config_revision(
        &self,
        (user_id, device_id): (UserIdInDb, Uuid),
        config_revision: &str,
    ) -> Result<(), DbErr> {
        use entity::managed_config_revisions as mcr;

        let now = chrono::Local::now().fixed_offset();
        let on_conflict = OnConflict::columns([mcr::Column::UserId, mcr::Column::DeviceId])
            .update_columns([mcr::Column::ConfigRevision, mcr::Column::UpdateTime])
            .to_owned();
        let insert_m = mcr::ActiveModel {
            user_id: Set(user_id),
            device_id: Set(device_id.to_string()),
            config_revision: Set(config_revision.to_string()),
            create_time: Set(now),
            update_time: Set(now),
            ..Default::default()
        };

        mcr::Entity::insert(insert_m)
            .on_conflict(on_conflict)
            .do_nothing()
            .exec(self.orm_db())
            .await?;
        Ok(())
    }

    pub(crate) async fn apply_managed_config_update(
        &self,
        (user_id, device_id): (UserIdInDb, Uuid),
        update: ManagedConfigUpdate,
    ) -> Result<ManagedConfigApplyResult, DbErr> {
        let (upserts, target_revision, expected_revision) = match &update {
            ManagedConfigUpdate::Full {
                upserts,
                target_revision,
                expected_revision,
            } => (
                upserts,
                target_revision.as_deref(),
                expected_revision.clone(),
            ),
            ManagedConfigUpdate::Patch {
                upserts,
                target_revision,
                expected_revision,
                ..
            } => (
                upserts,
                Some(target_revision.as_str()),
                ManagedConfigExpectedRevision::Exact(Some(expected_revision.clone())),
            ),
        };
        let serialized_upserts = upserts
            .iter()
            .map(|upsert| {
                serde_json::to_string(&upsert.network_config)
                    .map(|config| (upsert.instance_id, config))
                    .map_err(|error| DbErr::Json(error.to_string()))
            })
            .collect::<Result<Vec<_>, _>>()?;

        let mut transaction = self
            .db
            .begin_with("BEGIN IMMEDIATE")
            .await
            .map_err(sqlx_db_error)?;
        let current_revision =
            read_managed_config_revision(&mut transaction, user_id, device_id).await?;
        if target_revision.is_some() && current_revision.as_deref() == target_revision {
            transaction.commit().await.map_err(sqlx_db_error)?;
            return Ok(ManagedConfigApplyResult::AlreadyApplied);
        }
        if let ManagedConfigExpectedRevision::Exact(expected) = &expected_revision
            && current_revision.as_ref() != expected.as_ref()
        {
            let result = ManagedConfigApplyResult::RevisionConflict {
                expected: expected.clone(),
                current: current_revision,
            };
            transaction.commit().await.map_err(sqlx_db_error)?;
            return Ok(result);
        }

        let mut existing_sources = HashMap::new();
        match &update {
            ManagedConfigUpdate::Full { .. } => {
                let rows = sqlx::query_as::<_, (String, String)>(
                    r#"
                    SELECT network_instance_id, source
                    FROM user_running_network_configs
                    WHERE user_id = ? AND device_id = ?
                    "#,
                )
                .bind(user_id)
                .bind(device_id.to_string())
                .fetch_all(&mut *transaction)
                .await
                .map_err(sqlx_db_error)?;
                for (instance_id, source) in rows {
                    if let Ok(instance_id) = Uuid::parse_str(&instance_id) {
                        existing_sources.insert(instance_id, source);
                    }
                }
            }
            ManagedConfigUpdate::Patch {
                delete_instance_ids,
                ..
            } => {
                for instance_id in upserts
                    .iter()
                    .map(|upsert| upsert.instance_id)
                    .chain(delete_instance_ids.iter().copied())
                {
                    if let Some(source) =
                        read_config_source(&mut transaction, user_id, device_id, instance_id)
                            .await?
                    {
                        existing_sources.insert(instance_id, source);
                    }
                }
            }
        }

        let strict_ownership = target_revision.is_some();
        if strict_ownership
            && let Some(instance_id) = serialized_upserts
                .iter()
                .map(|(instance_id, _)| *instance_id)
                .chain(match &update {
                    ManagedConfigUpdate::Patch {
                        delete_instance_ids,
                        ..
                    } => delete_instance_ids.iter().copied(),
                    ManagedConfigUpdate::Full { .. } => [].iter().copied(),
                })
                .find(|instance_id| {
                    existing_sources
                        .get(instance_id)
                        .is_some_and(|source| source != ConfigSource::Web.as_str())
                })
        {
            transaction.commit().await.map_err(sqlx_db_error)?;
            return Ok(ManagedConfigApplyResult::OwnershipConflict { instance_id });
        }

        let desired_ids = serialized_upserts
            .iter()
            .map(|(instance_id, _)| *instance_id)
            .collect::<HashSet<_>>();
        for (instance_id, network_config) in &serialized_upserts {
            if !strict_ownership
                && existing_sources
                    .get(instance_id)
                    .is_some_and(|source| source != ConfigSource::Web.as_str())
            {
                continue;
            }
            let updated = upsert_network_config(
                &mut transaction,
                user_id,
                device_id,
                *instance_id,
                network_config,
                ConfigSource::Web,
                true,
            )
            .await?;
            if !updated {
                transaction.rollback().await.map_err(sqlx_db_error)?;
                return Ok(ManagedConfigApplyResult::OwnershipConflict {
                    instance_id: *instance_id,
                });
            }
        }

        let delete_instance_ids = match &update {
            ManagedConfigUpdate::Full { .. } => existing_sources
                .iter()
                .filter_map(|(instance_id, source)| {
                    (source == ConfigSource::Web.as_str() && !desired_ids.contains(instance_id))
                        .then_some(*instance_id)
                })
                .collect::<Vec<_>>(),
            ManagedConfigUpdate::Patch {
                delete_instance_ids,
                ..
            } => delete_instance_ids.clone(),
        };
        for instance_id in delete_instance_ids {
            sqlx::query(
                r#"
                DELETE FROM user_running_network_configs
                WHERE user_id = ? AND device_id = ? AND network_instance_id = ?
                    AND source = 'web'
                "#,
            )
            .bind(user_id)
            .bind(device_id.to_string())
            .bind(instance_id.to_string())
            .execute(&mut *transaction)
            .await
            .map_err(sqlx_db_error)?;
        }

        match target_revision {
            Some(revision) => {
                write_managed_config_revision(&mut transaction, user_id, device_id, revision)
                    .await?;
            }
            None => {
                clear_managed_config_revision(&mut transaction, user_id, device_id).await?;
            }
        }
        transaction.commit().await.map_err(sqlx_db_error)?;
        Ok(ManagedConfigApplyResult::Applied)
    }

    pub async fn delete_web_network_configs(
        &self,
        (user_id, device_id): (UserIdInDb, Uuid),
        network_inst_ids: &[Uuid],
    ) -> Result<(), DbErr> {
        let mut transaction = self
            .db
            .begin_with("BEGIN IMMEDIATE")
            .await
            .map_err(sqlx_db_error)?;
        let mut deleted = false;
        for instance_id in network_inst_ids {
            let result = sqlx::query(
                r#"
                DELETE FROM user_running_network_configs
                WHERE user_id = ? AND device_id = ? AND network_instance_id = ?
                    AND source = 'web'
                "#,
            )
            .bind(user_id)
            .bind(device_id.to_string())
            .bind(instance_id.to_string())
            .execute(&mut *transaction)
            .await
            .map_err(sqlx_db_error)?;
            deleted |= result.rows_affected() > 0;
        }
        if deleted {
            clear_managed_config_revision(&mut transaction, user_id, device_id).await?;
        }
        transaction.commit().await.map_err(sqlx_db_error)?;
        Ok(())
    }
}

#[async_trait]
impl Storage<(UserIdInDb, Uuid), user_running_network_configs::Model, DbErr> for Db {
    async fn insert_or_update_user_network_config(
        &self,
        (user_id, device_id): (UserIdInDb, Uuid),
        network_inst_id: Uuid,
        network_config: NetworkConfig,
        source: ConfigSource,
    ) -> Result<(), DbErr> {
        let network_config =
            serde_json::to_string(&network_config).map_err(|e| DbErr::Json(e.to_string()))?;
        let mut transaction = self
            .db
            .begin_with("BEGIN IMMEDIATE")
            .await
            .map_err(sqlx_db_error)?;
        let previous_source =
            read_config_source(&mut transaction, user_id, device_id, network_inst_id).await?;
        upsert_network_config(
            &mut transaction,
            user_id,
            device_id,
            network_inst_id,
            &network_config,
            source,
            false,
        )
        .await?;
        if source == ConfigSource::Web
            || previous_source.as_deref() == Some(ConfigSource::Web.as_str())
        {
            clear_managed_config_revision(&mut transaction, user_id, device_id).await?;
        }
        transaction.commit().await.map_err(sqlx_db_error)
    }

    async fn delete_network_configs(
        &self,
        (user_id, device_id): (UserIdInDb, Uuid),
        network_inst_ids: &[Uuid],
    ) -> Result<(), DbErr> {
        let mut transaction = self
            .db
            .begin_with("BEGIN IMMEDIATE")
            .await
            .map_err(sqlx_db_error)?;
        let mut deleted_web_config = false;
        for instance_id in network_inst_ids {
            deleted_web_config |=
                read_config_source(&mut transaction, user_id, device_id, *instance_id)
                    .await?
                    .as_deref()
                    == Some(ConfigSource::Web.as_str());
            sqlx::query(
                r#"
                DELETE FROM user_running_network_configs
                WHERE user_id = ? AND device_id = ? AND network_instance_id = ?
                "#,
            )
            .bind(user_id)
            .bind(device_id.to_string())
            .bind(instance_id.to_string())
            .execute(&mut *transaction)
            .await
            .map_err(sqlx_db_error)?;
        }
        if deleted_web_config {
            clear_managed_config_revision(&mut transaction, user_id, device_id).await?;
        }
        transaction.commit().await.map_err(sqlx_db_error)?;
        Ok(())
    }

    async fn update_network_config_state(
        &self,
        (user_id, device_id): (UserIdInDb, Uuid),
        network_inst_id: Uuid,
        disabled: bool,
    ) -> Result<(), DbErr> {
        let mut transaction = self
            .db
            .begin_with("BEGIN IMMEDIATE")
            .await
            .map_err(sqlx_db_error)?;
        let source =
            read_config_source(&mut transaction, user_id, device_id, network_inst_id).await?;
        let result = sqlx::query(
            r#"
            UPDATE user_running_network_configs
            SET disabled = ?, update_time = ?
            WHERE user_id = ? AND device_id = ? AND network_instance_id = ?
            "#,
        )
        .bind(disabled)
        .bind(chrono::Local::now().fixed_offset())
        .bind(user_id)
        .bind(device_id.to_string())
        .bind(network_inst_id.to_string())
        .execute(&mut *transaction)
        .await
        .map_err(sqlx_db_error)?;
        if result.rows_affected() > 0 && source.as_deref() == Some(ConfigSource::Web.as_str()) {
            clear_managed_config_revision(&mut transaction, user_id, device_id).await?;
        }
        transaction.commit().await.map_err(sqlx_db_error)?;
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
    use easytier::{common::config::ConfigSource, proto::api::manage::NetworkConfig};
    use easytier_core::management::remote_client::{PersistentConfig, Storage};
    use sea_orm::{ActiveModelTrait, ColumnTrait, EntityTrait, QueryFilter as _, Set};

    use crate::db::{Db, ListNetworkProps, entity::user_running_network_configs};

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

        db.insert_or_update_user_network_config(
            (user_id, device_id),
            inst_id,
            network_config,
            ConfigSource::User,
        )
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
        assert_eq!(result.get_network_config_source(), ConfigSource::User);

        // overwrite the config
        let network_config = NetworkConfig {
            network_name: Some("test_config2".to_string()),
            ..Default::default()
        };
        let network_config_json = serde_json::to_string(&network_config).unwrap();
        db.insert_or_update_user_network_config(
            (user_id, device_id),
            inst_id,
            network_config,
            ConfigSource::Web,
        )
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
        assert_eq!(result2.get_network_config_source(), ConfigSource::Web);
        assert_eq!(
            result2.get_runtime_network_config_source(),
            ConfigSource::Web
        );

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

    #[tokio::test]
    async fn test_unknown_network_config_source_defaults_to_user_runtime_source() {
        let db = Db::memory_db().await;
        let user_id = 1;
        let inst_id = uuid::Uuid::new_v4();
        let device_id = uuid::Uuid::new_v4();

        user_running_network_configs::ActiveModel {
            user_id: Set(user_id),
            device_id: Set(device_id.to_string()),
            network_instance_id: Set(inst_id.to_string()),
            network_config: Set(serde_json::to_string(&NetworkConfig {
                network_name: Some("unknown-source".to_string()),
                ..Default::default()
            })
            .unwrap()),
            source: Set("unknown".to_string()),
            disabled: Set(false),
            create_time: Set(sqlx::types::chrono::Local::now().fixed_offset()),
            update_time: Set(sqlx::types::chrono::Local::now().fixed_offset()),
            ..Default::default()
        }
        .insert(db.orm_db())
        .await
        .unwrap();

        let result = user_running_network_configs::Entity::find()
            .filter(user_running_network_configs::Column::UserId.eq(user_id))
            .one(db.orm_db())
            .await
            .unwrap()
            .unwrap();
        assert_eq!(result.get_network_config_source(), ConfigSource::User);
        assert_eq!(
            result.get_runtime_network_config_source(),
            ConfigSource::User
        );
    }

    #[tokio::test]
    async fn test_user_network_config_same_instance_id_is_scoped_by_device() {
        let db = Db::memory_db().await;
        let user_id = db.auto_create_user("user-1").await.unwrap().id;
        let device1 = uuid::Uuid::new_v4();
        let device2 = uuid::Uuid::new_v4();
        let inst_id = uuid::Uuid::new_v4();

        db.insert_or_update_user_network_config(
            (user_id, device1),
            inst_id,
            NetworkConfig {
                network_name: Some("cfg-1".to_string()),
                ..Default::default()
            },
            ConfigSource::User,
        )
        .await
        .unwrap();
        db.insert_or_update_user_network_config(
            (user_id, device2),
            inst_id,
            NetworkConfig {
                network_name: Some("cfg-2".to_string()),
                ..Default::default()
            },
            ConfigSource::User,
        )
        .await
        .unwrap();

        let first = db
            .get_network_config((user_id, device1), &inst_id.to_string())
            .await
            .unwrap()
            .unwrap();
        let second = db
            .get_network_config((user_id, device2), &inst_id.to_string())
            .await
            .unwrap()
            .unwrap();
        assert_eq!(first.user_id, user_id);
        assert_eq!(first.device_id, device1.to_string());
        assert_eq!(second.user_id, user_id);
        assert_eq!(second.device_id, device2.to_string());

        let device1_configs = db
            .list_network_configs((user_id, device1), ListNetworkProps::All)
            .await
            .unwrap();
        let device2_configs = db
            .list_network_configs((user_id, device2), ListNetworkProps::All)
            .await
            .unwrap();
        assert_eq!(device1_configs.len(), 1);
        assert_eq!(device2_configs.len(), 1);
    }

    #[tokio::test]
    async fn web_owned_mutations_invalidate_managed_revision() {
        let db = Db::memory_db().await;
        let user_id = db
            .auto_create_user("managed-revision-invalidation")
            .await
            .unwrap()
            .id;
        let device_id = uuid::Uuid::new_v4();
        let inst_id = uuid::Uuid::new_v4();
        db.insert_or_update_user_network_config(
            (user_id, device_id),
            inst_id,
            NetworkConfig {
                network_name: Some("managed".to_string()),
                ..Default::default()
            },
            ConfigSource::Web,
        )
        .await
        .unwrap();

        db.set_managed_config_revision((user_id, device_id), "rev-before-disable")
            .await
            .unwrap();
        db.update_network_config_state((user_id, device_id), inst_id, true)
            .await
            .unwrap();
        assert!(
            db.get_managed_config_revision((user_id, device_id))
                .await
                .unwrap()
                .is_none()
        );

        db.set_managed_config_revision((user_id, device_id), "rev-before-delete")
            .await
            .unwrap();
        db.delete_network_configs((user_id, device_id), &[inst_id])
            .await
            .unwrap();
        assert!(
            db.get_managed_config_revision((user_id, device_id))
                .await
                .unwrap()
                .is_none()
        );
    }

    #[tokio::test]
    async fn user_owned_mutation_preserves_managed_revision() {
        let db = Db::memory_db().await;
        let user_id = db
            .auto_create_user("user-revision-preserved")
            .await
            .unwrap()
            .id;
        let device_id = uuid::Uuid::new_v4();
        let inst_id = uuid::Uuid::new_v4();
        db.set_managed_config_revision((user_id, device_id), "rev-user")
            .await
            .unwrap();

        db.insert_or_update_user_network_config(
            (user_id, device_id),
            inst_id,
            NetworkConfig {
                network_name: Some("user".to_string()),
                ..Default::default()
            },
            ConfigSource::User,
        )
        .await
        .unwrap();

        assert_eq!(
            db.get_managed_config_revision((user_id, device_id))
                .await
                .unwrap()
                .as_deref(),
            Some("rev-user")
        );
    }
}
