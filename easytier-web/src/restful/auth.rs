use axum::{
    http::StatusCode,
    response::IntoResponse,
    routing::{get, post},
    Router,
};
use axum_messages::{Message, Messages};
use serde::{Deserialize, Serialize};

use super::{
    users::{AuthSession, Credentials},
    AppStateInner,
};

#[derive(Debug, Deserialize, Serialize)]
pub struct LoginResult {
    messages: Vec<Message>,
}

pub fn router() -> Router<AppStateInner> {
    Router::new()
        .route(
            "/api/v1/auth/login",
            post(self::post::login).get(self::get::login),
        )
        .route("/api/v1/auth/logout", get(self::get::logout))
        .route("/api/v1/auth/captcha", get(self::get::get_captcha))
        .route("/api/v1/auth/register", post(self::post::register))
}

mod post {
    use axum::{body::Body, Json};

    use crate::restful::{
        captcha::extension::{axum_tower_sessions::CaptchaAxumTowerSessionStaticExt, CaptchaUtil},
        users::RegisterNewUser,
    };

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

    pub async fn register(
        auth_session: AuthSession,
        captcha_session: tower_sessions::Session,
        Json(req): Json<RegisterNewUser>,
    ) -> impl IntoResponse {
        // 调用CaptchaUtil的静态方法验证验证码是否正确
        if !CaptchaUtil::ver(&req.captcha, &captcha_session).await {
            return (
                StatusCode::BAD_REQUEST,
                format!("captcha verify error, input: {}", req.captcha),
            )
                .into_response();
        }

        if let Err(e) = auth_session.backend.register_new_user(&req).await {
            tracing::error!("Failed to register new user: {:?}", e);
            return (StatusCode::BAD_REQUEST, format!("{:?}", e)).into_response();
        }

        StatusCode::OK.into_response()
    }
}

mod get {
    use crate::restful::captcha::{
        captcha::spec::SpecCaptcha,
        extension::{axum_tower_sessions::CaptchaAxumTowerSessionExt as _, CaptchaUtil},
        NewCaptcha as _,
    };
    use axum::{response::Response, Json};
    use tower_sessions::Session;

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

    pub async fn get_captcha(session: Session) -> Result<Response, StatusCode> {
        let mut captcha: CaptchaUtil<SpecCaptcha> = CaptchaUtil::with_size_and_len(127, 48, 4);
        match captcha.out(&session).await {
            Ok(response) => Ok(response),
            Err(_) => Err(StatusCode::INTERNAL_SERVER_ERROR),
        }
    }
}
