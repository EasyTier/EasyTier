use axum::{
    Router,
    http::StatusCode,
    routing::{get, post, put},
};
use serde::{Deserialize, Serialize};

use std::sync::Arc;

use crate::FeatureFlags;

use super::{
    AppStateInner,
    auth_state::{BearerTokenStore, CaptchaChallengeStore, CaptchaChallengeVerifyFailure},
    bearer_auth::{self, BearerAuth},
    users::Credentials,
};

#[derive(Debug, Deserialize, Serialize)]
pub struct LoginResult {
    token: String,
    expires_at: String,
}

pub fn router() -> Router<AppStateInner> {
    let protected_routes = bearer_auth::require_auth(
        Router::new()
            .route("/api/v1/auth/password", put(self::put::change_password))
            .route(
                "/api/v1/auth/check_login_status",
                get(self::get::check_login_status),
            )
            .route("/api/v1/auth/logout", get(self::get::logout)),
    );

    Router::new()
        .merge(protected_routes)
        .route("/api/v1/auth/login", post(self::post::login))
        .route("/api/v1/auth/captcha", get(self::get::get_captcha))
        .route("/api/v1/auth/register", post(self::post::register))
}

fn instant_to_rfc3339(expires_at: std::time::Instant) -> String {
    let remaining = expires_at.saturating_duration_since(std::time::Instant::now());
    let datetime: chrono::DateTime<chrono::Utc> = (std::time::SystemTime::now()
        .checked_add(remaining)
        .unwrap_or_else(std::time::SystemTime::now))
    .into();
    datetime.to_rfc3339()
}

const CAPTCHA_CHALLENGE_INVALID_MESSAGE: &str =
    "captcha challenge missing, expired, or already used";
const CAPTCHA_ANSWER_INCORRECT_MESSAGE: &str = "captcha answer is incorrect";

mod put {
    use axum::{Extension, Json};
    use easytier::proto::common::Void;

    use crate::restful::{HttpHandleError, other_error, users::ChangePassword};

    use super::*;

    pub async fn change_password(
        auth: BearerAuth,
        Extension(token_store): Extension<Arc<BearerTokenStore>>,
        Json(req): Json<ChangePassword>,
    ) -> Result<Json<Void>, HttpHandleError> {
        let user_id = auth.user_id();

        if let Err(e) = token_store.backend().change_password(user_id, &req).await {
            tracing::error!("Failed to change password: {:?}", e);
            return Err((
                StatusCode::INTERNAL_SERVER_ERROR,
                Json::from(other_error(format!("{:?}", e))),
            ));
        }

        token_store.revoke_all_tokens_for_user(user_id);

        Ok(Void::default().into())
    }
}

mod post {
    use axum::{Json, extract::Extension};
    use easytier::proto::common::Void;

    use crate::restful::{HttpHandleError, other_error, users::RegisterNewUser};

    use super::*;

    pub async fn login(
        Extension(token_store): Extension<Arc<BearerTokenStore>>,
        Json(creds): Json<Credentials>,
    ) -> Result<Json<LoginResult>, HttpHandleError> {
        let backend = token_store.backend();
        let user = match backend
            .authenticate_credentials(&creds.username, &creds.password)
            .await
        {
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
                ));
            }
        };

        let token = token_store.issue_token(user.id());
        let expires_at = token_store
            .get(&token)
            .map(|context| instant_to_rfc3339(context.expires_at))
            .ok_or_else(|| {
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    Json::from(other_error("Failed to issue bearer token")),
                )
            })?;

        Ok(Json(LoginResult { token, expires_at }))
    }

    pub async fn register(
        Extension(token_store): Extension<Arc<BearerTokenStore>>,
        Extension(captcha_challenge_store): Extension<Arc<CaptchaChallengeStore>>,
        Extension(feature_flags): Extension<Arc<FeatureFlags>>,
        Json(req): Json<RegisterNewUser>,
    ) -> Result<Json<Void>, HttpHandleError> {
        // Check if registration is disabled
        if feature_flags.disable_registration {
            tracing::warn!("Registration attempt blocked: registration is disabled");
            return Err((
                StatusCode::FORBIDDEN,
                other_error("Registration is disabled").into(),
            ));
        }

        match captcha_challenge_store.verify_and_consume_detailed(&req.captcha_id, &req.captcha) {
            Ok(_) => {}
            Err(CaptchaChallengeVerifyFailure::Incorrect) => {
                return Err((
                    StatusCode::BAD_REQUEST,
                    other_error(CAPTCHA_ANSWER_INCORRECT_MESSAGE).into(),
                ));
            }
            Err(
                CaptchaChallengeVerifyFailure::Missing
                | CaptchaChallengeVerifyFailure::Expired
                | CaptchaChallengeVerifyFailure::Consumed,
            ) => {
                return Err((
                    StatusCode::BAD_REQUEST,
                    other_error(CAPTCHA_CHALLENGE_INVALID_MESSAGE).into(),
                ));
            }
        }

        if let Err(e) = token_store.backend().register_new_user(&req).await {
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
        HttpHandleError,
        captcha::{
            NewCaptcha as _,
            builder::spec::SpecCaptcha,
            extension::{CaptchaUtil, axum_tower_sessions::CaptchaAxumChallengeStoreExt as _},
        },
        other_error,
    };
    use axum::{Extension, Json, response::Response};
    use easytier::proto::common::Void;

    use super::*;

    pub async fn logout(
        auth: BearerAuth,
        Extension(token_store): Extension<Arc<BearerTokenStore>>,
    ) -> Result<Json<Void>, HttpHandleError> {
        token_store.revoke_token(&auth.token);
        Ok(Json(Void::default()))
    }

    pub async fn get_captcha(
        Extension(captcha_challenge_store): Extension<Arc<CaptchaChallengeStore>>,
    ) -> Result<Response, HttpHandleError> {
        let mut captcha: CaptchaUtil<SpecCaptcha> = CaptchaUtil::with_size_and_len(127, 48, 4);
        match captcha
            .out_with_challenge_store(&captcha_challenge_store)
            .await
        {
            Ok(response) => Ok(response),
            Err(e) => Err((
                StatusCode::INTERNAL_SERVER_ERROR,
                Json::from(other_error(format!("{:?}", e))),
            )),
        }
    }

    pub async fn check_login_status(_auth: BearerAuth) -> Result<Json<Void>, HttpHandleError> {
        Ok(Json(Void::default()))
    }
}

#[cfg(test)]
mod tests {
    use std::{
        sync::Arc,
        time::{Duration, SystemTime, UNIX_EPOCH},
    };

    use axum::{
        Extension, Router,
        body::{Body, to_bytes},
        http::{Method, Request, StatusCode, header},
        routing::{get, post, put as route_put},
    };
    use serde_json::{Value, json};
    use tower::ServiceExt as _;

    use super::*;
    use crate::restful::{
        captcha::extension::axum_tower_sessions::CAPTCHA_ID_HEADER,
        users::{Backend, ChangePassword},
    };

    async fn make_backend() -> Backend {
        Backend::new(crate::db::Db::memory_db().await)
    }

    async fn create_user(backend: &Backend, username: &str) {
        backend
            .db()
            .create_user_and_join_users_group(
                username,
                password_auth::generate_hash("password-for-tests"),
            )
            .await
            .unwrap();
    }

    fn make_router(token_store: Arc<BearerTokenStore>) -> Router {
        let protected = bearer_auth::require_auth(
            Router::new()
                .route(
                    "/api/v1/auth/password",
                    route_put(super::put::change_password),
                )
                .route(
                    "/api/v1/auth/check_login_status",
                    get(super::get::check_login_status),
                )
                .route("/api/v1/auth/logout", get(super::get::logout)),
        );

        Router::new()
            .merge(protected)
            .route("/api/v1/auth/login", post(super::post::login))
            .layer(Extension(token_store))
    }

    fn make_captcha_router(
        feature_flags: Arc<FeatureFlags>,
        token_store: Arc<BearerTokenStore>,
        captcha_store: Arc<CaptchaChallengeStore>,
    ) -> Router {
        Router::new()
            .route("/api/v1/auth/captcha", get(super::get::get_captcha))
            .route("/api/v1/auth/register", post(super::post::register))
            .layer(Extension(feature_flags))
            .layer(Extension(captcha_store))
            .layer(Extension(token_store))
    }

    fn json_request(method: Method, uri: &str, payload: Value) -> Request<Body> {
        Request::builder()
            .method(method)
            .uri(uri)
            .header(header::CONTENT_TYPE, "application/json")
            .body(Body::from(serde_json::to_vec(&payload).unwrap()))
            .unwrap()
    }

    fn bearer_request(method: Method, uri: &str, token: &str) -> Request<Body> {
        Request::builder()
            .method(method)
            .uri(uri)
            .header(header::AUTHORIZATION, format!("Bearer {token}"))
            .body(Body::empty())
            .unwrap()
    }

    fn bearer_json_request<T: serde::Serialize>(
        method: Method,
        uri: &str,
        token: &str,
        payload: &T,
    ) -> Request<Body> {
        Request::builder()
            .method(method)
            .uri(uri)
            .header(header::AUTHORIZATION, format!("Bearer {token}"))
            .header(header::CONTENT_TYPE, "application/json")
            .body(Body::from(serde_json::to_vec(payload).unwrap()))
            .unwrap()
    }

    fn empty_request(method: Method, uri: &str) -> Request<Body> {
        Request::builder()
            .method(method)
            .uri(uri)
            .body(Body::empty())
            .unwrap()
    }

    async fn read_json_body(response: axum::response::Response) -> Value {
        let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
        serde_json::from_slice(&body).unwrap()
    }

    async fn login(app: &Router, username: &str, password: &str) -> axum::response::Response {
        app.clone()
            .oneshot(json_request(
                Method::POST,
                "/api/v1/auth/login",
                json!({
                    "username": username,
                    "password": password,
                }),
            ))
            .await
            .unwrap()
    }

    async fn issue_captcha(app: &Router) -> (String, Vec<u8>) {
        let response = app
            .clone()
            .oneshot(empty_request(Method::GET, "/api/v1/auth/captcha"))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);

        let captcha_id = response
            .headers()
            .get(CAPTCHA_ID_HEADER)
            .unwrap()
            .to_str()
            .unwrap()
            .to_string();
        let content_type = response
            .headers()
            .get(header::CONTENT_TYPE)
            .unwrap()
            .to_str()
            .unwrap();
        assert!(content_type.starts_with("image/"));

        let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
        assert!(!body.is_empty());
        (captcha_id, body.to_vec())
    }

    async fn register(
        app: &Router,
        username: &str,
        password: &str,
        captcha_id: &str,
        captcha: &str,
    ) -> axum::response::Response {
        app.clone()
            .oneshot(json_request(
                Method::POST,
                "/api/v1/auth/register",
                json!({
                    "credentials": {
                        "username": username,
                        "password": password,
                    },
                    "captcha_id": captcha_id,
                    "captcha": captcha,
                }),
            ))
            .await
            .unwrap()
    }

    #[tokio::test]
    async fn token_auth_login_returns_token_and_status_passes() {
        let backend = make_backend().await;
        create_user(&backend, "token-login-user").await;
        let token_store = Arc::new(BearerTokenStore::with_ttl_and_cleanup_interval(
            backend,
            Duration::from_secs(60),
            Duration::from_millis(10),
        ));
        let app = make_router(token_store);

        let response = login(&app, "token-login-user", "password-for-tests").await;
        assert_eq!(response.status(), StatusCode::OK);

        let payload = read_json_body(response).await;
        let token = payload["token"].as_str().unwrap().to_string();
        let expires_at_str = payload["expires_at"].as_str().unwrap();
        let expires_at = chrono::DateTime::parse_from_rfc3339(expires_at_str)
            .unwrap()
            .timestamp() as u64;
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();

        assert!(!token.is_empty());
        assert!(expires_at >= now);

        let check_response = app
            .clone()
            .oneshot(bearer_request(
                Method::GET,
                "/api/v1/auth/check_login_status",
                &token,
            ))
            .await
            .unwrap();
        assert_eq!(check_response.status(), StatusCode::OK);

        let logout_response = app
            .clone()
            .oneshot(bearer_request(Method::GET, "/api/v1/auth/logout", &token))
            .await
            .unwrap();
        assert_eq!(logout_response.status(), StatusCode::OK);

        let revoked_response = app
            .oneshot(bearer_request(
                Method::GET,
                "/api/v1/auth/check_login_status",
                &token,
            ))
            .await
            .unwrap();
        assert_eq!(revoked_response.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn token_auth_login_invalid_password_returns_json_unauthorized() {
        let backend = make_backend().await;
        create_user(&backend, "token-login-invalid-user").await;
        let token_store = Arc::new(BearerTokenStore::with_ttl_and_cleanup_interval(
            backend,
            Duration::from_secs(60),
            Duration::from_millis(10),
        ));
        let app = make_router(token_store);

        let response = login(&app, "token-login-invalid-user", "wrong-password").await;
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);

        let payload = read_json_body(response).await;
        assert!(
            payload["message"]
                .as_str()
                .unwrap()
                .contains("Invalid credentials")
        );
    }

    #[tokio::test]
    async fn token_auth_password_change_revokes_all_tokens() {
        let backend = make_backend().await;
        create_user(&backend, "token-password-user").await;
        let token_store = Arc::new(BearerTokenStore::with_ttl_and_cleanup_interval(
            backend,
            Duration::from_secs(60),
            Duration::from_millis(10),
        ));
        let app = make_router(token_store);

        let first_login =
            read_json_body(login(&app, "token-password-user", "password-for-tests").await).await;
        let first_token = first_login["token"].as_str().unwrap().to_string();
        let second_login =
            read_json_body(login(&app, "token-password-user", "password-for-tests").await).await;
        let second_token = second_login["token"].as_str().unwrap().to_string();

        assert_ne!(first_token, second_token);

        let change_password_response = app
            .clone()
            .oneshot(bearer_json_request(
                Method::PUT,
                "/api/v1/auth/password",
                &first_token,
                &ChangePassword {
                    new_password: "password-for-tests-updated".to_string(),
                },
            ))
            .await
            .unwrap();
        assert_eq!(change_password_response.status(), StatusCode::OK);

        for token in [&first_token, &second_token] {
            let response = app
                .clone()
                .oneshot(bearer_request(
                    Method::GET,
                    "/api/v1/auth/check_login_status",
                    token,
                ))
                .await
                .unwrap();
            assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
        }

        let old_password_login = login(&app, "token-password-user", "password-for-tests").await;
        assert_eq!(old_password_login.status(), StatusCode::UNAUTHORIZED);

        let new_login_payload =
            read_json_body(login(&app, "token-password-user", "password-for-tests-updated").await)
                .await;
        let new_token = new_login_payload["token"].as_str().unwrap().to_string();
        assert_ne!(new_token, first_token);
        assert_ne!(new_token, second_token);

        let new_token_status = app
            .oneshot(bearer_request(
                Method::GET,
                "/api/v1/auth/check_login_status",
                &new_token,
            ))
            .await
            .unwrap();
        assert_eq!(new_token_status.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn captcha_header_issue_and_consume_once() {
        let backend = make_backend().await;
        let token_store = Arc::new(BearerTokenStore::with_ttl_and_cleanup_interval(
            backend,
            Duration::from_secs(60),
            Duration::from_millis(10),
        ));
        let captcha_store = Arc::new(CaptchaChallengeStore::with_ttl_and_cleanup_interval(
            Duration::from_secs(60),
            Duration::from_millis(10),
        ));
        let app = make_captcha_router(
            Arc::new(FeatureFlags::default()),
            token_store,
            captcha_store.clone(),
        );

        let (captcha_id, body) = issue_captcha(&app).await;
        assert!(!body.is_empty());

        let answer = captcha_store.get(&captcha_id).unwrap().answer;
        let first_response = register(
            &app,
            "captcha-header-once-user",
            "password-for-tests",
            &captcha_id,
            &answer,
        )
        .await;
        assert_eq!(first_response.status(), StatusCode::OK);
        assert!(captcha_store.get(&captcha_id).is_none());

        let second_response = register(
            &app,
            "captcha-header-twice-user",
            "password-for-tests",
            &captcha_id,
            &answer,
        )
        .await;
        assert_eq!(second_response.status(), StatusCode::BAD_REQUEST);

        let payload = read_json_body(second_response).await;
        assert_eq!(
            payload["message"].as_str().unwrap(),
            CAPTCHA_CHALLENGE_INVALID_MESSAGE
        );
    }

    #[tokio::test]
    async fn captcha_header_rejects_missing_or_expired() {
        let backend = make_backend().await;

        let missing_token_store = Arc::new(BearerTokenStore::with_ttl_and_cleanup_interval(
            backend.clone(),
            Duration::from_secs(60),
            Duration::from_millis(10),
        ));
        let missing_store = Arc::new(CaptchaChallengeStore::with_ttl_and_cleanup_interval(
            Duration::from_secs(60),
            Duration::from_millis(10),
        ));
        let missing_app = make_captcha_router(
            Arc::new(FeatureFlags::default()),
            missing_token_store,
            missing_store.clone(),
        );

        let missing_response = register(
            &missing_app,
            "captcha-header-missing-user",
            "password-for-tests",
            "missing-captcha-id",
            "abcd",
        )
        .await;
        assert_eq!(missing_response.status(), StatusCode::BAD_REQUEST);
        let missing_payload = read_json_body(missing_response).await;
        assert_eq!(
            missing_payload["message"].as_str().unwrap(),
            CAPTCHA_CHALLENGE_INVALID_MESSAGE
        );

        let wrong_token_store = Arc::new(BearerTokenStore::with_ttl_and_cleanup_interval(
            backend.clone(),
            Duration::from_secs(60),
            Duration::from_millis(10),
        ));
        let wrong_store = Arc::new(CaptchaChallengeStore::with_ttl_and_cleanup_interval(
            Duration::from_secs(60),
            Duration::from_millis(10),
        ));
        let wrong_app = make_captcha_router(
            Arc::new(FeatureFlags::default()),
            wrong_token_store,
            wrong_store.clone(),
        );

        let (wrong_captcha_id, _) = issue_captcha(&wrong_app).await;
        let wrong_response = register(
            &wrong_app,
            "captcha-header-wrong-user",
            "password-for-tests",
            &wrong_captcha_id,
            "wrong",
        )
        .await;
        assert_eq!(wrong_response.status(), StatusCode::BAD_REQUEST);
        let wrong_payload = read_json_body(wrong_response).await;
        assert_eq!(
            wrong_payload["message"].as_str().unwrap(),
            CAPTCHA_ANSWER_INCORRECT_MESSAGE
        );
        assert!(wrong_store.get(&wrong_captcha_id).is_some());

        let expired_token_store = Arc::new(BearerTokenStore::with_ttl_and_cleanup_interval(
            backend.clone(),
            Duration::from_secs(60),
            Duration::from_millis(10),
        ));
        let expired_store = Arc::new(CaptchaChallengeStore::with_ttl_and_cleanup_interval(
            Duration::from_millis(20),
            Duration::from_millis(10),
        ));
        let expired_app = make_captcha_router(
            Arc::new(FeatureFlags::default()),
            expired_token_store,
            expired_store.clone(),
        );

        let (expired_captcha_id, _) = issue_captcha(&expired_app).await;
        let expired_answer = expired_store.get(&expired_captcha_id).unwrap().answer;
        tokio::time::sleep(Duration::from_millis(30)).await;
        let expired_response = register(
            &expired_app,
            "captcha-header-expired-user",
            "password-for-tests",
            &expired_captcha_id,
            &expired_answer,
        )
        .await;
        assert_eq!(expired_response.status(), StatusCode::BAD_REQUEST);
        let expired_payload = read_json_body(expired_response).await;
        assert_eq!(
            expired_payload["message"].as_str().unwrap(),
            CAPTCHA_CHALLENGE_INVALID_MESSAGE
        );

        let before_restart_token_store = Arc::new(BearerTokenStore::with_ttl_and_cleanup_interval(
            backend.clone(),
            Duration::from_secs(60),
            Duration::from_millis(10),
        ));
        let before_restart_store = Arc::new(CaptchaChallengeStore::with_ttl_and_cleanup_interval(
            Duration::from_secs(60),
            Duration::from_millis(10),
        ));
        let before_restart_app = make_captcha_router(
            Arc::new(FeatureFlags::default()),
            before_restart_token_store,
            before_restart_store.clone(),
        );
        let (stale_captcha_id, _) = issue_captcha(&before_restart_app).await;
        let stale_answer = before_restart_store.get(&stale_captcha_id).unwrap().answer;

        let after_restart_token_store = Arc::new(BearerTokenStore::with_ttl_and_cleanup_interval(
            backend,
            Duration::from_secs(60),
            Duration::from_millis(10),
        ));
        let after_restart_store = Arc::new(CaptchaChallengeStore::with_ttl_and_cleanup_interval(
            Duration::from_secs(60),
            Duration::from_millis(10),
        ));
        let after_restart_app = make_captcha_router(
            Arc::new(FeatureFlags::default()),
            after_restart_token_store,
            after_restart_store,
        );
        let restarted_response = register(
            &after_restart_app,
            "captcha-header-restart-user",
            "password-for-tests",
            &stale_captcha_id,
            &stale_answer,
        )
        .await;
        assert_eq!(restarted_response.status(), StatusCode::BAD_REQUEST);
        let restarted_payload = read_json_body(restarted_response).await;
        assert_eq!(
            restarted_payload["message"].as_str().unwrap(),
            CAPTCHA_CHALLENGE_INVALID_MESSAGE
        );
    }
}
