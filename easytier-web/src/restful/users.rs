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
    ) -> anyhow::Result<()> {
        let hashed_password = password_auth::generate_hash(req.new_password.as_str());

        use entity::users;

        let mut user = users::Entity::find_by_id(id)
            .one(self.db.orm_db())
            .await?
            .ok_or(anyhow::anyhow!("User not found"))?
            .into_active_model();
        user.password = Set(hashed_password.clone());

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

// We use a type alias for convenience.
//
// Note that we've supplied our concrete backend here.
pub type AuthSession = axum_login::AuthSession<Backend>;
