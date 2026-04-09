use std::collections::HashSet;

use async_trait::async_trait;
use axum_login::{AuthUser, AuthnBackend, AuthzBackend, UserId};
use password_auth::verify_password;
use sea_orm::{
    ColumnTrait, EntityTrait, FromQueryResult, IntoActiveModel, JoinType, QueryFilter,
    QuerySelect as _, RelationTrait, Set,
};
use serde::{Deserialize, Serialize};
use tokio::task;

use crate::db::{self, entity};

const EMPTY_PASSWORD_MD5: &str = "d41d8cd98f00b204e9800998ecf8427e";

#[derive(Clone, Serialize, Deserialize)]
pub struct User {
    pub(crate) db_user: entity::users::Model,
    pub tokens: Vec<String>,
}

// Here we've implemented `Debug` manually to avoid accidentally logging the
// password hash.
impl std::fmt::Debug for User {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("User")
            .field("id", &self.db_user.id)
            .field("username", &self.db_user.username)
            .field("password", &"[redacted]")
            .finish()
    }
}

impl AuthUser for User {
    type Id = i32;

    fn id(&self) -> Self::Id {
        self.db_user.id
    }

    fn session_auth_hash(&self) -> &[u8] {
        self.db_user.password.as_bytes() // We use the password hash as the auth
                                         // hash--what this means
                                         // is when the user changes their password the
                                         // auth session becomes invalid.
    }
}

// This allows us to extract the authentication fields from forms. We use this
// to authenticate requests with the backend.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct Credentials {
    pub username: String,
    pub password: String,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct RegisterNewUser {
    pub credentials: Credentials,
    pub captcha: String,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct ChangePassword {
    pub new_password: String,
}

#[derive(Debug, thiserror::Error)]
pub enum ChangePasswordError {
    #[error("Password cannot be empty")]
    EmptyPassword,

    #[error("User not found")]
    UserNotFound,

    #[error(transparent)]
    Db(#[from] sea_orm::DbErr),
}

#[derive(Debug, Clone)]
pub struct Backend {
    db: db::Db,
}

impl Backend {
    pub fn new(db: db::Db) -> Self {
        Self { db }
    }

    pub fn db(&self) -> &db::Db {
        &self.db
    }

    pub async fn register_new_user(&self, new_user: &RegisterNewUser) -> anyhow::Result<()> {
        let hashed_password = password_auth::generate_hash(new_user.credentials.password.as_str());
        self.db
            .create_user_and_join_users_group(&new_user.credentials.username, hashed_password)
            .await?;
        Ok(())
    }

    /// Find a user by username, or auto-create one for OIDC-authenticated users.
    ///
    /// Unlike the heartbeat auto-creation path (controlled by `allow_auto_create_user`),
    /// OIDC users are always provisioned automatically because their identity has already
    /// been verified by a trusted external Identity Provider (IdP).
    pub async fn find_or_create_oidc_user(&self, username: &str) -> anyhow::Result<User> {
        use entity::users;

        // Try to find an existing user first.
        if let Some(db_user) = users::Entity::find()
            .filter(users::Column::Username.eq(username))
            .one(self.db.orm_db())
            .await?
        {
            return Ok(User {
                tokens: vec![db_user.username.clone()],
                db_user,
            });
        }

        // User not found – auto-provision a local account backed by the IdP identity.
        let db_user = self.db.auto_create_user(username).await?;
        tracing::info!("Auto-provisioned OIDC user '{username}'");
        Ok(User {
            tokens: vec![db_user.username.clone()],
            db_user,
        })
    }

    pub async fn change_password(
        &self,
        id: <User as AuthUser>::Id,
        req: &ChangePassword,
    ) -> Result<(), ChangePasswordError> {
        // With the existing pre-hashed protocol the backend can only reject the
        // exact empty-string digest; whitespace-only passwords must be blocked
        // on the client before hashing.
        if req.new_password == EMPTY_PASSWORD_MD5 {
            return Err(ChangePasswordError::EmptyPassword);
        }

        let hashed_password = password_auth::generate_hash(req.new_password.as_str());

        use entity::users;

        let mut user = users::Entity::find_by_id(id)
            .one(self.db.orm_db())
            .await?
            .ok_or(ChangePasswordError::UserNotFound)?
            .into_active_model();
        user.password = Set(hashed_password.clone());
        user.must_change_password = Set(false);

        entity::users::Entity::update(user)
            .exec(self.db.orm_db())
            .await?;

        Ok(())
    }
}

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error(transparent)]
    Sqlx(#[from] sea_orm::DbErr),

    #[error(transparent)]
    TaskJoin(#[from] task::JoinError),
}

#[async_trait]
impl AuthnBackend for Backend {
    type User = User;
    type Credentials = Credentials;
    type Error = Error;

    async fn authenticate(
        &self,
        creds: Self::Credentials,
    ) -> Result<Option<Self::User>, Self::Error> {
        let user = entity::users::Entity::find()
            .filter(entity::users::Column::Username.eq(creds.username))
            .one(self.db.orm_db())
            .await?;
        task::spawn_blocking(|| {
            // We're using password-based authentication--this works by comparing our form
            // input with an argon2 password hash.
            Ok(user
                .filter(|user| verify_password(creds.password, &user.password).is_ok())
                .map(|user| User {
                    db_user: user.clone(),
                    tokens: vec![user.username.clone()],
                }))
        })
        .await?
    }

    async fn get_user(&self, user_id: &UserId<Self>) -> Result<Option<Self::User>, Self::Error> {
        let mut user = entity::users::Entity::find()
            .filter(entity::users::Column::Id.eq(*user_id))
            .one(self.db.orm_db())
            .await?;

        if let Some(u) = &mut user {
            let mut user = User {
                db_user: u.clone(),
                tokens: vec![],
            };
            // username is a token
            user.tokens.push(u.username.clone());
            Ok(Some(user))
        } else {
            Ok(None)
        }
    }
}

#[derive(Debug, Clone, Eq, PartialEq, Hash, FromQueryResult)]
pub struct Permission {
    pub name: String,
}

impl From<&str> for Permission {
    fn from(name: &str) -> Self {
        Permission {
            name: name.to_string(),
        }
    }
}

#[async_trait]
impl AuthzBackend for Backend {
    type Permission = Permission;

    async fn get_group_permissions(
        &self,
        _user: &Self::User,
    ) -> Result<HashSet<Self::Permission>, Self::Error> {
        let permissions = entity::users::Entity::find()
            .column_as(entity::permissions::Column::Name, "name")
            .join(
                JoinType::LeftJoin,
                entity::users::Relation::UsersGroups.def(),
            )
            .join(
                JoinType::LeftJoin,
                entity::users_groups::Relation::Groups.def(),
            )
            .join(
                JoinType::LeftJoin,
                entity::groups::Relation::GroupsPermissions.def(),
            )
            .join(
                JoinType::LeftJoin,
                entity::groups_permissions::Relation::Permissions.def(),
            )
            .into_model::<Self::Permission>()
            .all(self.db.orm_db())
            .await?;

        Ok(permissions.into_iter().collect())
    }
}

#[cfg(test)]
mod tests {
    use axum_login::AuthnBackend;
    use sea_orm::{ColumnTrait, EntityTrait, QueryFilter as _};

    use super::{Backend, ChangePassword, ChangePasswordError, EMPTY_PASSWORD_MD5};
    use crate::db::{entity::users, Db};

    async fn find_user(db: &Db, username: &str) -> users::Model {
        users::Entity::find()
            .filter(users::Column::Username.eq(username))
            .one(db.orm_db())
            .await
            .unwrap()
            .unwrap()
    }

    #[tokio::test]
    async fn seeded_default_users_require_password_change() {
        let db = Db::memory_db().await;

        assert!(find_user(&db, "admin").await.must_change_password);
        assert!(find_user(&db, "user").await.must_change_password);
    }

    #[tokio::test]
    async fn auto_created_user_does_not_require_password_change() {
        let db = Db::memory_db().await;

        db.auto_create_user("oidc-user").await.unwrap();

        assert!(!find_user(&db, "oidc-user").await.must_change_password);
    }

    #[tokio::test]
    async fn change_password_clears_must_change_password_flag() {
        let db = Db::memory_db().await;
        let backend = Backend::new(db.clone());
        let admin = find_user(&db, "admin").await;

        backend
            .change_password(
                admin.id,
                &ChangePassword {
                    new_password: "f1086f68460b65771de50a970cd1242d".to_string(),
                },
            )
            .await
            .unwrap();

        assert!(!find_user(&db, "admin").await.must_change_password);
    }

    #[tokio::test]
    async fn change_password_rejects_empty_password_digest() {
        let db = Db::memory_db().await;
        let backend = Backend::new(db.clone());
        let admin = find_user(&db, "admin").await;

        let error = backend
            .change_password(
                admin.id,
                &ChangePassword {
                    new_password: EMPTY_PASSWORD_MD5.to_string(),
                },
            )
            .await
            .unwrap_err();

        assert!(matches!(error, ChangePasswordError::EmptyPassword));
        assert!(find_user(&db, "admin").await.must_change_password);
    }

    #[tokio::test]
    async fn can_authenticate_with_new_password_after_change() {
        let db = Db::memory_db().await;
        let backend = Backend::new(db.clone());
        let admin = find_user(&db, "admin").await;

        backend
            .change_password(
                admin.id,
                &ChangePassword {
                    new_password: "f1086f68460b65771de50a970cd1242d".to_string(),
                },
            )
            .await
            .unwrap();

        let authenticated = backend
            .authenticate(super::Credentials {
                username: "admin".to_string(),
                password: "f1086f68460b65771de50a970cd1242d".to_string(),
            })
            .await
            .unwrap();

        assert!(authenticated.is_some());
    }
}

// We use a type alias for convenience.
//
// Note that we've supplied our concrete backend here.
pub type AuthSession = axum_login::AuthSession<Backend>;
