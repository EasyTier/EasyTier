use sea_orm_migration::prelude::*;

pub struct Migration;

const DEFAULT_USER_PASSWORD_HASH: &str =
    "$argon2i$v=19$m=16,t=2,p=1$aGVyRDBrcnRycnlaMDhkbw$449SEcv/qXf+0fnI9+fYVQ";
const DEFAULT_ADMIN_PASSWORD_HASH: &str =
    "$argon2i$v=19$m=16,t=2,p=1$bW5idXl0cmY$61n+JxL4r3dwLPAEDlDdtg";

#[derive(DeriveIden)]
enum Users {
    Table,
    Username,
    Password,
    MustChangePassword,
}

impl MigrationName for Migration {
    fn name(&self) -> &str {
        "m20260405_000003_add_must_change_password"
    }
}

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .alter_table(
                Table::alter()
                    .table(Users::Table)
                    .add_column(
                        ColumnDef::new(Users::MustChangePassword)
                            .boolean()
                            .not_null()
                            .default(false),
                    )
                    .to_owned(),
            )
            .await?;

        manager
            .exec_stmt(
                Query::update()
                    .table(Users::Table)
                    .value(Users::MustChangePassword, true)
                    .cond_where(any![
                        Expr::col(Users::Username)
                            .eq("admin")
                            .and(Expr::col(Users::Password).eq(DEFAULT_ADMIN_PASSWORD_HASH)),
                        Expr::col(Users::Username)
                            .eq("user")
                            .and(Expr::col(Users::Password).eq(DEFAULT_USER_PASSWORD_HASH)),
                    ])
                    .to_owned(),
            )
            .await?;

        Ok(())
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .alter_table(
                Table::alter()
                    .table(Users::Table)
                    .drop_column(Users::MustChangePassword)
                    .to_owned(),
            )
            .await?;

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use sea_orm::{ColumnTrait, EntityTrait, QueryFilter as _, SqlxSqliteConnector};
    use sea_orm_migration::prelude::SchemaManager;
    use sqlx::sqlite::SqlitePoolOptions;

    use super::{Migration, MigrationTrait, DEFAULT_USER_PASSWORD_HASH};
    use crate::db::entity::users;

    async fn find_user(db: &sea_orm::DatabaseConnection, username: &str) -> users::Model {
        users::Entity::find()
            .filter(users::Column::Username.eq(username))
            .one(db)
            .await
            .unwrap()
            .unwrap()
    }

    #[tokio::test]
    async fn migration_only_marks_seeded_accounts_still_using_default_passwords() {
        let pool = SqlitePoolOptions::new()
            .max_connections(1)
            .connect("sqlite::memory:")
            .await
            .unwrap();

        sqlx::query(
            "CREATE TABLE users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT NOT NULL UNIQUE,
                password TEXT NOT NULL
            )",
        )
        .execute(&pool)
        .await
        .unwrap();

        let changed_admin_password = password_auth::generate_hash("already-changed");

        sqlx::query("INSERT INTO users (username, password) VALUES (?, ?), (?, ?)")
            .bind("admin")
            .bind(changed_admin_password)
            .bind("user")
            .bind(DEFAULT_USER_PASSWORD_HASH)
            .execute(&pool)
            .await
            .unwrap();

        let db = SqlxSqliteConnector::from_sqlx_sqlite_pool(pool);
        Migration.up(&SchemaManager::new(&db)).await.unwrap();

        assert!(!find_user(&db, "admin").await.must_change_password);
        assert!(find_user(&db, "user").await.must_change_password);
    }
}
