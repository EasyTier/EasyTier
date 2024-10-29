use sqlx::{migrate::MigrateDatabase as _, Sqlite, SqlitePool};

#[derive(Debug, Clone)]
pub struct Db {
    db_path: String,
    db: SqlitePool,
}

impl Db {
    pub async fn new<T: ToString>(db_path: T) -> anyhow::Result<Self> {
        Ok(Self {
            db_path: db_path.to_string(),
            db: Self::prepare_db(db_path.to_string().as_str()).await?,
        })
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

        sqlx::migrate!().run(&db).await?;
        Ok(db)
    }

    pub fn inner(&self) -> SqlitePool {
        self.db.clone()
    }
}
