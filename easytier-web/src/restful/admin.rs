use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use axum::{
    Json, Router,
    extract::Extension,
    http::StatusCode,
    routing::{get, put},
};
use axum_login::{login_required, AuthzBackend};
use sea_orm::{
    EntityTrait,
};

use crate::db::{Db, entity};
use crate::restful::users::Backend;

use super::{
    AppStateInner,
    HttpHandleError,
    other_error,
    users::AuthSession,
};

/// Runtime toggle for registration.
/// This wraps an AtomicBool so it can be toggled at runtime without restart.
#[derive(Clone)]
pub struct RegistrationToggle {
    pub disabled: Arc<AtomicBool>,
}

impl RegistrationToggle {
    pub fn new(initial_disabled: bool) -> Self {
        Self {
            disabled: Arc::new(AtomicBool::new(initial_disabled)),
        }
    }

    pub fn is_disabled(&self) -> bool {
        self.disabled.load(Ordering::Relaxed)
    }

    pub fn set_disabled(&self, disabled: bool) {
        self.disabled.store(disabled, Ordering::Relaxed);
    }
}

/// Check if the current user has the `manage_user` permission (i.e. is admin).
async fn check_admin(auth_session: &AuthSession) -> Result<(), HttpHandleError> {
    let user = auth_session
        .user
        .as_ref()
        .ok_or((StatusCode::UNAUTHORIZED, other_error("Not logged in").into()))?;

    let permissions = auth_session
        .backend
        .get_all_permissions(user)
        .await
        .map_err(|e| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                other_error(format!("Failed to get permissions: {:?}", e)).into(),
            )
        })?;

    let has_manage_user = permissions
        .iter()
        .any(|p| p.name == "manage_user");

    if !has_manage_user {
        return Err((
            StatusCode::FORBIDDEN,
            other_error("Admin privileges required").into(),
        ));
    }

    Ok(())
}

/// Response for listing all users.
#[derive(Debug, serde::Serialize)]
pub struct UserInfo {
    pub id: i32,
    pub username: String,
}

/// List all registered users (admin only).
async fn handle_list_users(
    auth_session: AuthSession,
    Extension(db): Extension<Db>,
) -> Result<Json<Vec<UserInfo>>, HttpHandleError> {
    check_admin(&auth_session).await?;

    let users = entity::users::Entity::find()
        .all(db.orm_db())
        .await
        .map_err(convert_error)?;

    let user_list: Vec<UserInfo> = users
        .into_iter()
        .map(|u| UserInfo {
            id: u.id,
            username: u.username,
        })
        .collect();

    Ok(Json(user_list))
}

/// Delete a user by ID (admin only). Prevent deleting the admin user itself.
async fn handle_delete_user(
    auth_session: AuthSession,
    Extension(db): Extension<Db>,
    axum::extract::Path(user_id): axum::extract::Path<i32>,
) -> Result<StatusCode, HttpHandleError> {
    check_admin(&auth_session).await?;

    let user = entity::users::Entity::find_by_id(user_id)
        .one(db.orm_db())
        .await
        .map_err(convert_error)?
        .ok_or((
            StatusCode::NOT_FOUND,
            other_error("User not found").into(),
        ))?;

    if user.username == "admin" {
        return Err((
            StatusCode::FORBIDDEN,
            other_error("Cannot delete the admin user").into(),
        ));
    }

    entity::users::Entity::delete_by_id(user_id)
        .exec(db.orm_db())
        .await
        .map_err(convert_error)?;

    Ok(StatusCode::NO_CONTENT)
}

/// Get current registration toggle status.
async fn handle_get_registration_status(
    auth_session: AuthSession,
    Extension(toggle): Extension<RegistrationToggle>,
) -> Result<Json<bool>, HttpHandleError> {
    check_admin(&auth_session).await?;
    Ok(Json(!toggle.is_disabled()))
}

/// Toggle registration enabled/disabled (admin only).
/// `true` = registration enabled, `false` = registration disabled.
async fn handle_toggle_registration(
    auth_session: AuthSession,
    Extension(toggle): Extension<RegistrationToggle>,
    Json(enabled): Json<bool>,
) -> Result<Json<bool>, HttpHandleError> {
    check_admin(&auth_session).await?;
    toggle.set_disabled(!enabled);
    Ok(Json(enabled))
}

fn convert_error(e: sea_orm::DbErr) -> HttpHandleError {
    (
        StatusCode::INTERNAL_SERVER_ERROR,
        other_error(format!("DB Error: {:#}", e)).into(),
    )
}

/// Build the admin router. All routes require login + manage_user permission.
pub fn router() -> Router<AppStateInner> {
    Router::new()
        .route("/api/v1/admin/users", get(handle_list_users))
        .route("/api/v1/admin/users/:user_id", axum::routing::delete(handle_delete_user))
        .route("/api/v1/admin/registration", get(handle_get_registration_status))
        .route("/api/v1/admin/registration", put(handle_toggle_registration))
        .route_layer(login_required!(Backend))
}