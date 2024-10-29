use axum::{
    http::StatusCode,
    routing::{get, post},
    Router,
};
use axum_messages::Message;
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
        .route("/api/v1/auth/login", post(self::post::login))
        .route("/api/v1/auth/logout", get(self::get::logout))
        .route("/api/v1/auth/captcha", get(self::get::get_captcha))
        .route("/api/v1/auth/register", post(self::post::register))
}

mod post {
    use axum::Json;
    use easytier::proto::common::Void;

    use crate::restful::{
        captcha::extension::{axum_tower_sessions::CaptchaAxumTowerSessionStaticExt, CaptchaUtil},
        other_error,
        users::RegisterNewUser,
        HttpHandleError,
    };

    use super::*;

    pub async fn login(
        mut auth_session: AuthSession,
        Json(creds): Json<Credentials>,
    ) -> Result<Json<Void>, HttpHandleError> {
        let user = match auth_session.authenticate(creds.clone()).await {
            Ok(Some(user)) => user,
            Ok(None) => {
                return Err((
                    StatusCode::UNAUTHORIZED,
                    Json::from(other_error("Invalid credentials")),
                ));
            }
            Err(e) => {
                return Err((
                    StatusCode::INTERNAL_SERVER_ERROR,
                    Json::from(other_error(format!("{:?}", e))),
                ))
            }
        };

        if let Err(e) = auth_session.login(&user).await {
            return Err((
                StatusCode::INTERNAL_SERVER_ERROR,
                Json::from(other_error(format!("{:?}", e))),
            ));
        }

        Ok(Void::default().into())
    }

    pub async fn register(
        auth_session: AuthSession,
        captcha_session: tower_sessions::Session,
        Json(req): Json<RegisterNewUser>,
    ) -> Result<Json<Void>, HttpHandleError> {
        // 调用CaptchaUtil的静态方法验证验证码是否正确
        if !CaptchaUtil::ver(&req.captcha, &captcha_session).await {
            return Err((
                StatusCode::BAD_REQUEST,
                other_error(format!("captcha verify error, input: {}", req.captcha)).into(),
            ));
        }

        if let Err(e) = auth_session.backend.register_new_user(&req).await {
            tracing::error!("Failed to register new user: {:?}", e);
            return Err((
                StatusCode::BAD_REQUEST,
                other_error(format!("{:?}", e)).into(),
            ));
        }

        Ok(Void::default().into())
    }
}

mod get {
    use crate::restful::{
        captcha::{
            captcha::spec::SpecCaptcha,
            extension::{axum_tower_sessions::CaptchaAxumTowerSessionExt as _, CaptchaUtil},
            NewCaptcha as _,
        },
        other_error, HttpHandleError,
    };
    use axum::{response::Response, Json};
    use easytier::proto::common::Void;
    use tower_sessions::Session;

    use super::*;

    pub async fn logout(mut auth_session: AuthSession) -> Result<Json<Void>, HttpHandleError> {
        match auth_session.logout().await {
            Ok(_) => Ok(Json(Void::default())),
            Err(e) => {
                tracing::error!("Failed to logout: {:?}", e);
                Err((
                    StatusCode::INTERNAL_SERVER_ERROR,
                    Json::from(other_error(format!("{:?}", e))),
                ))
            }
        }
    }

    pub async fn get_captcha(session: Session) -> Result<Response, HttpHandleError> {
        let mut captcha: CaptchaUtil<SpecCaptcha> = CaptchaUtil::with_size_and_len(127, 48, 4);
        match captcha.out(&session).await {
            Ok(response) => Ok(response),
            Err(e) => Err((
                StatusCode::INTERNAL_SERVER_ERROR,
                Json::from(other_error(format!("{:?}", e))),
            )),
        }
    }
}
