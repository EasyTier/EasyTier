use axum::{
    http::StatusCode,
    response::{IntoResponse, Redirect},
    routing::{get, post},
    Router,
};
use axum_messages::{Message, Messages};
use serde::{Deserialize, Serialize};

use super::users::{AuthSession, Credentials};

#[derive(Debug, Deserialize, Serialize)]
pub struct LoginResult {
    messages: Vec<Message>,
}

pub fn router() -> Router<()> {
    Router::new()
        .route(
            "/api/v1/auth/login",
            post(self::post::login).get(self::get::login),
        )
        .route("/api/v1/auth/logout", get(self::get::logout))
}

mod post {
    use axum::{body::Body, Json};

    use super::*;

    pub async fn login(
        mut auth_session: AuthSession,
        messages: Messages,
        Json(creds): Json<Credentials>,
    ) -> impl IntoResponse {
        let user = match auth_session.authenticate(creds.clone()).await {
            Ok(Some(user)) => user,
            Ok(None) => {
                messages.error("Invalid credentials");
                return StatusCode::UNAUTHORIZED.into_response();
            }
            Err(_) => return StatusCode::INTERNAL_SERVER_ERROR.into_response(),
        };

        if auth_session.login(&user).await.is_err() {
            return StatusCode::INTERNAL_SERVER_ERROR.into_response();
        }

        messages.success(format!("Successfully logged in as {}", user.username));

        Body::empty().into_response()
    }
}

mod get {
    use axum::Json;

    use super::*;

    pub async fn login(messages: Messages) -> Json<LoginResult> {
        LoginResult {
            messages: messages.into_iter().collect(),
        }
        .into()
    }

    pub async fn logout(mut auth_session: AuthSession) -> impl IntoResponse {
        match auth_session.logout().await {
            Ok(_) => StatusCode::OK.into_response(),
            Err(_) => StatusCode::INTERNAL_SERVER_ERROR.into_response(),
        }
    }
}
