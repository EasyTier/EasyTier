mod auth;
mod auth_state;
mod bearer_auth;
pub(crate) mod captcha;
mod network;
pub(crate) mod oidc;
mod rpc;
mod users;

use std::{net::SocketAddr, sync::Arc};

use axum::extract::Path;
use axum::http::{HeaderName, Request, StatusCode, header};
use axum::middleware::{self as axum_mw, Next};
use axum::response::Response;
use axum::routing::{delete, post};
use axum::{Extension, Json, Router, extract::State, routing::get};
use easytier::common::config::{ConfigLoader, TomlConfigLoader};
use easytier::common::scoped_task::ScopedTask;
use easytier::launcher::NetworkConfig;
use easytier::proto::rpc_types;
use network::NetworkApi;
use sea_orm::DbErr;
use tokio::net::TcpListener;
use tower_http::cors::{Any, CorsLayer};
use users::Backend;

use crate::FeatureFlags;
use crate::client_manager::ClientManager;
use crate::client_manager::storage::StorageToken;
use crate::db::{Db, UserIdInDb};
use crate::webhook::SharedWebhookConfig;
use auth_state::{BearerTokenStore, CaptchaChallengeStore, OidcStateStore};
use bearer_auth::BearerAuth;

/// Embed assets for web dashboard, build frontend first
#[cfg(feature = "embed")]
#[derive(rust_embed::RustEmbed, Clone)]
#[folder = "frontend/dist/"]
struct Assets;

pub struct RestfulServer {
    bind_addr: SocketAddr,
    client_mgr: Arc<ClientManager>,
    feature_flags: Arc<FeatureFlags>,
    webhook_config: SharedWebhookConfig,
    db: Db,
    oidc_config: oidc::OidcConfig,
    web_router: Option<Router>,
}

type AppStateInner = Arc<ClientManager>;
type AppState = State<AppStateInner>;

#[derive(Debug, serde::Deserialize, serde::Serialize)]
struct ListSessionJsonResp(Vec<StorageToken>);

#[derive(Debug, serde::Deserialize, serde::Serialize)]
struct GetSummaryJsonResp {
    device_count: u32,
}

#[derive(Debug, serde::Deserialize, serde::Serialize)]
struct GenerateConfigRequest {
    config: NetworkConfig,
}

#[derive(Debug, serde::Deserialize, serde::Serialize)]
struct GenerateConfigResponse {
    error: Option<String>,
    toml_config: Option<String>,
}

#[derive(Debug, serde::Deserialize, serde::Serialize)]
struct ParseConfigRequest {
    toml_config: String,
}

#[derive(Debug, serde::Deserialize, serde::Serialize)]
struct ParseConfigResponse {
    error: Option<String>,
    config: Option<NetworkConfig>,
}

#[derive(Debug, serde::Deserialize, serde::Serialize)]
pub struct Error {
    message: String,
}
type RpcError = rpc_types::error::Error;
type HttpHandleError = (StatusCode, Json<Error>);

pub fn other_error<T: ToString>(error_message: T) -> Error {
    Error {
        message: error_message.to_string(),
    }
}

pub fn convert_db_error(e: DbErr) -> HttpHandleError {
    (
        StatusCode::INTERNAL_SERVER_ERROR,
        other_error(format!("DB Error: {:#}", e)).into(),
    )
}

impl RestfulServer {
    pub async fn new(
        bind_addr: SocketAddr,
        client_mgr: Arc<ClientManager>,
        db: Db,
        web_router: Option<Router>,
        feature_flags: Arc<FeatureFlags>,
        oidc_config: oidc::OidcConfig,
        webhook_config: SharedWebhookConfig,
    ) -> anyhow::Result<Self> {
        assert!(client_mgr.is_running());

        Ok(RestfulServer {
            bind_addr,
            client_mgr,
            feature_flags,
            webhook_config,
            db,
            oidc_config,
            web_router,
        })
    }

    async fn handle_list_all_sessions(
        _auth: BearerAuth,
        State(client_mgr): AppState,
    ) -> Result<Json<ListSessionJsonResp>, HttpHandleError> {
        let ret = client_mgr.list_sessions().await;
        Ok(ListSessionJsonResp(ret).into())
    }

    async fn handle_get_summary(
        auth: BearerAuth,
        State(client_mgr): AppState,
    ) -> Result<Json<GetSummaryJsonResp>, HttpHandleError> {
        let machines = client_mgr.list_machine_by_user_id(auth.user_id()).await;

        Ok(GetSummaryJsonResp {
            device_count: machines.len() as u32,
        }
        .into())
    }

    async fn handle_generate_config(
        Json(req): Json<GenerateConfigRequest>,
    ) -> Result<Json<GenerateConfigResponse>, HttpHandleError> {
        let config = req.config.gen_config();
        match config {
            Ok(c) => Ok(GenerateConfigResponse {
                error: None,
                toml_config: Some(c.dump()),
            }
            .into()),
            Err(e) => Ok(GenerateConfigResponse {
                error: Some(format!("{:?}", e)),
                toml_config: None,
            }
            .into()),
        }
    }

    async fn handle_parse_config(
        Json(req): Json<ParseConfigRequest>,
    ) -> Result<Json<ParseConfigResponse>, HttpHandleError> {
        let config = TomlConfigLoader::new_from_str(&req.toml_config)
            .and_then(|config| NetworkConfig::new_from_config(&config));
        match config {
            Ok(c) => Ok(ParseConfigResponse {
                error: None,
                config: Some(c),
            }
            .into()),
            Err(e) => Ok(ParseConfigResponse {
                error: Some(format!("{:?}", e)),
                config: None,
            }
            .into()),
        }
    }

    #[allow(unused_mut)]
    pub async fn start(mut self) -> Result<ScopedTask<()>, anyhow::Error> {
        let listener = TcpListener::bind(self.bind_addr).await?;
        let backend = Backend::new(self.db.clone());
        let compression_layer = tower_http::compression::CompressionLayer::new()
            .br(true)
            .deflate(true)
            .gzip(true)
            .zstd(true)
            .quality(tower_http::compression::CompressionLevel::Default);
        let bearer_token_store = Arc::new(BearerTokenStore::new(backend));
        let oidc_state_store = Arc::new(OidcStateStore::new());
        let captcha_challenge_store = Arc::new(CaptchaChallengeStore::new());

        // Token-authenticated management routes that bypass session auth.
        let internal_app = if self.webhook_config.has_internal_auth() {
            let internal_token = self.webhook_config.internal_auth_token.clone().unwrap();
            let internal_routes = Router::new()
                .route(
                    "/api/internal/sessions",
                    get(Self::handle_list_all_sessions_internal),
                )
                .route(
                    "/api/internal/users/:user-id/sessions/:machine-id",
                    delete(Self::handle_disconnect_session_internal),
                )
                .merge(NetworkApi::build_route_internal())
                .merge(rpc::router_internal())
                .with_state(self.client_mgr.clone())
                .layer(axum_mw::from_fn(move |req, next| {
                    let token = internal_token.clone();
                    internal_auth_middleware(token, req, next)
                }));
            Some(internal_routes)
        } else {
            None
        };

        let cors_layer = CorsLayer::new()
            .allow_origin(Any)
            .allow_methods(Any)
            .allow_headers([header::AUTHORIZATION, header::CONTENT_TYPE, header::ACCEPT])
            .expose_headers([HeaderName::from_static("x-captcha-id")]);

        let protected_routes = bearer_auth::require_auth(
            Router::new()
                .route("/api/v1/summary", get(Self::handle_get_summary))
                .route("/api/v1/sessions", get(Self::handle_list_all_sessions))
                .merge(NetworkApi::build_route())
                .merge(rpc::router()),
        );

        let mut app = Router::new()
            .merge(protected_routes)
            .merge(auth::router().layer(Extension(self.feature_flags.clone())))
            .merge(oidc::router())
            .with_state(self.client_mgr.clone())
            .route(
                "/api/v1/generate-config",
                post(Self::handle_generate_config),
            )
            .route("/api/v1/parse-config", post(Self::handle_parse_config))
            .layer(Extension(self.oidc_config.clone()))
            .layer(cors_layer)
            .layer(compression_layer);

        if let Some(internal_routes) = internal_app {
            app = app.merge(internal_routes);
        }

        #[cfg(feature = "embed")]
        let app = if let Some(web_router) = self.web_router.take() {
            app.merge(web_router)
        } else {
            app
        };

        let app = app
            .layer(Extension(captcha_challenge_store))
            .layer(Extension(oidc_state_store))
            .layer(Extension(bearer_token_store));

        let serve_task: ScopedTask<()> = tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        })
        .into();

        Ok(serve_task)
    }

    /// Session listing endpoint for token-authenticated management clients.
    async fn handle_list_all_sessions_internal(
        State(client_mgr): AppState,
    ) -> Result<Json<ListSessionJsonResp>, HttpHandleError> {
        let ret = client_mgr.list_sessions().await;
        Ok(ListSessionJsonResp(ret).into())
    }

    async fn handle_disconnect_session_internal(
        Path((user_id, machine_id)): Path<(UserIdInDb, uuid::Uuid)>,
        State(client_mgr): AppState,
    ) -> Result<StatusCode, HttpHandleError> {
        if client_mgr
            .disconnect_session_by_machine_id(user_id, &machine_id)
            .await
        {
            Ok(StatusCode::NO_CONTENT)
        } else {
            Err((
                StatusCode::NOT_FOUND,
                other_error("session not found").into(),
            ))
        }
    }
}

/// Middleware that validates X-Internal-Auth for token-authenticated routes.
async fn internal_auth_middleware(
    expected_token: String,
    req: Request<axum::body::Body>,
    next: Next,
) -> Response {
    let auth_header = req
        .headers()
        .get("X-Internal-Auth")
        .and_then(|v| v.to_str().ok());

    match auth_header {
        Some(token) if token == expected_token => next.run(req).await,
        _ => Response::builder()
            .status(StatusCode::UNAUTHORIZED)
            .header(header::CONTENT_TYPE, "application/json")
            .body(axum::body::Body::from(
                r#"{"error":"unauthorized: invalid or missing X-Internal-Auth header"}"#,
            ))
            .unwrap(),
    }
}

#[cfg(test)]
mod tests {
    use std::{sync::Arc, time::Duration};

    use axum::{
        Extension, Router,
        body::{Body, to_bytes},
        http::{Method, Request, StatusCode, header},
        routing::{delete, get},
    };
    use easytier::proto::web::HeartbeatRequest;
    use serde_json::{Value, json};
    use tower::ServiceExt as _;

    use super::*;
    use crate::client_manager::{session::Location, storage::StorageToken};
    use crate::webhook::WebhookConfig;

    struct TestContext {
        app: Router,
        bearer_token: String,
        internal_token: String,
        machine_id: uuid::Uuid,
        user_id: UserIdInDb,
        _client_mgr: Arc<ClientManager>,
    }

    async fn create_user(backend: &Backend, username: &str) -> UserIdInDb {
        backend
            .db()
            .create_user_and_join_users_group(
                username,
                password_auth::generate_hash("password-for-tests"),
            )
            .await
            .unwrap()
            .id
    }

    fn make_router(
        client_mgr: Arc<ClientManager>,
        token_store: Arc<BearerTokenStore>,
        internal_token: String,
    ) -> Router {
        let protected_routes = bearer_auth::require_auth(
            Router::new()
                .route("/api/v1/summary", get(RestfulServer::handle_get_summary))
                .route(
                    "/api/v1/sessions",
                    get(RestfulServer::handle_list_all_sessions),
                )
                .merge(NetworkApi::build_route())
                .merge(rpc::router()),
        );

        let internal_routes = Router::new()
            .route(
                "/api/internal/sessions",
                get(RestfulServer::handle_list_all_sessions_internal),
            )
            .route(
                "/api/internal/users/:user-id/sessions/:machine-id",
                delete(RestfulServer::handle_disconnect_session_internal),
            )
            .merge(NetworkApi::build_route_internal())
            .merge(rpc::router_internal())
            .with_state(client_mgr.clone())
            .layer(axum_mw::from_fn(move |req, next| {
                let internal_token = internal_token.clone();
                internal_auth_middleware(internal_token, req, next)
            }));

        Router::new()
            .merge(protected_routes)
            .merge(auth::router().layer(Extension(Arc::new(FeatureFlags::default()))))
            .merge(internal_routes)
            .with_state(client_mgr)
            .layer(Extension(token_store))
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

    fn json_request<T: serde::Serialize>(method: Method, uri: &str, payload: &T) -> Request<Body> {
        Request::builder()
            .method(method)
            .uri(uri)
            .header(header::CONTENT_TYPE, "application/json")
            .body(Body::from(serde_json::to_vec(payload).unwrap()))
            .unwrap()
    }

    fn internal_request(method: Method, uri: &str, token: &str) -> Request<Body> {
        Request::builder()
            .method(method)
            .uri(uri)
            .header("X-Internal-Auth", token)
            .body(Body::empty())
            .unwrap()
    }

    fn internal_json_request<T: serde::Serialize>(
        method: Method,
        uri: &str,
        token: &str,
        payload: &T,
    ) -> Request<Body> {
        Request::builder()
            .method(method)
            .uri(uri)
            .header("X-Internal-Auth", token)
            .header(header::CONTENT_TYPE, "application/json")
            .body(Body::from(serde_json::to_vec(payload).unwrap()))
            .unwrap()
    }

    async fn read_json_body(response: axum::response::Response) -> Value {
        let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
        serde_json::from_slice(&body).unwrap()
    }

    async fn make_test_context() -> TestContext {
        let db = Db::memory_db().await;
        let backend = Backend::new(db.clone());
        let username = format!("token-route-user-{}", uuid::Uuid::new_v4().simple());
        let user_id = create_user(&backend, &username).await;
        let token_store = Arc::new(BearerTokenStore::with_ttl_and_cleanup_interval(
            backend,
            Duration::from_secs(60),
            Duration::from_millis(10),
        ));
        let bearer_token = token_store.issue_token(user_id);
        let internal_token = "internal-token-for-tests".to_string();

        let client_mgr = ClientManager::new(
            db,
            None,
            Arc::new(FeatureFlags::default()),
            Arc::new(WebhookConfig::new(None, None, None, None, None)),
        );
        let machine_id = uuid::Uuid::new_v4();
        let client_url = "tcp://127.0.0.1:10001".parse().unwrap();
        client_mgr
            .insert_test_session(
                StorageToken {
                    token: username.clone(),
                    client_url,
                    machine_id,
                    user_id,
                },
                Some(HeartbeatRequest {
                    machine_id: Some(machine_id.into()),
                    inst_id: Some(uuid::Uuid::new_v4().into()),
                    user_token: username.clone(),
                    easytier_version: "test-version".to_string(),
                    hostname: "test-hostname".to_string(),
                    report_time: chrono::Local::now().to_rfc3339(),
                    device_os: None,
                    running_network_instances: vec![],
                }),
                Some(Location {
                    country: "本地网络".to_string(),
                    city: Some("测试城市".to_string()),
                    region: Some("测试区域".to_string()),
                }),
            )
            .await;
        let client_mgr = Arc::new(client_mgr);

        let app = make_router(client_mgr.clone(), token_store, internal_token.clone());

        TestContext {
            app,
            bearer_token,
            internal_token,
            machine_id,
            user_id,
            _client_mgr: client_mgr,
        }
    }

    #[tokio::test]
    async fn token_auth_protected_routes_reject_missing_bearer() {
        let ctx = make_test_context().await;

        let summary = ctx
            .app
            .clone()
            .oneshot(
                Request::builder()
                    .uri("/api/v1/summary")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(summary.status(), StatusCode::UNAUTHORIZED);

        let machines = ctx
            .app
            .clone()
            .oneshot(
                Request::builder()
                    .uri("/api/v1/machines")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(machines.status(), StatusCode::UNAUTHORIZED);

        let proxy_rpc = ctx
            .app
            .clone()
            .oneshot(json_request(
                Method::POST,
                &format!("/api/v1/machines/{}/proxy-rpc", ctx.machine_id),
                &json!({
                    "service_name": "unknown.service",
                    "method_name": "noop",
                    "payload": {},
                }),
            ))
            .await
            .unwrap();
        assert_eq!(proxy_rpc.status(), StatusCode::UNAUTHORIZED);

        let password = ctx
            .app
            .clone()
            .oneshot(json_request(
                Method::PUT,
                "/api/v1/auth/password",
                &json!({ "new_password": "rotated-password" }),
            ))
            .await
            .unwrap();
        assert_eq!(password.status(), StatusCode::UNAUTHORIZED);

        let check_login_status = ctx
            .app
            .clone()
            .oneshot(
                Request::builder()
                    .uri("/api/v1/auth/check_login_status")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(check_login_status.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn token_auth_protected_routes_accept_current_user() {
        let ctx = make_test_context().await;

        let summary = ctx
            .app
            .clone()
            .oneshot(bearer_request(
                Method::GET,
                "/api/v1/summary",
                &ctx.bearer_token,
            ))
            .await
            .unwrap();
        assert_eq!(summary.status(), StatusCode::OK);
        let summary_body = read_json_body(summary).await;
        assert_eq!(summary_body["device_count"], 1);

        let machines = ctx
            .app
            .clone()
            .oneshot(bearer_request(
                Method::GET,
                "/api/v1/machines",
                &ctx.bearer_token,
            ))
            .await
            .unwrap();
        assert_eq!(machines.status(), StatusCode::OK);
        let machines_body = read_json_body(machines).await;
        assert_eq!(machines_body["machines"].as_array().unwrap().len(), 1);

        let check_login_status = ctx
            .app
            .clone()
            .oneshot(bearer_request(
                Method::GET,
                "/api/v1/auth/check_login_status",
                &ctx.bearer_token,
            ))
            .await
            .unwrap();
        assert_eq!(check_login_status.status(), StatusCode::OK);

        let proxy_rpc = ctx
            .app
            .clone()
            .oneshot(bearer_json_request(
                Method::POST,
                &format!("/api/v1/machines/{}/proxy-rpc", ctx.machine_id),
                &ctx.bearer_token,
                &json!({
                    "service_name": "unknown.service",
                    "method_name": "noop",
                    "payload": {},
                }),
            ))
            .await
            .unwrap();
        assert_eq!(proxy_rpc.status(), StatusCode::BAD_REQUEST);
        let proxy_body = read_json_body(proxy_rpc).await;
        assert!(
            proxy_body["message"]
                .as_str()
                .unwrap()
                .contains("Unknown service")
        );

        let sessions = ctx
            .app
            .clone()
            .oneshot(bearer_request(
                Method::GET,
                "/api/v1/sessions",
                &ctx.bearer_token,
            ))
            .await
            .unwrap();
        assert_eq!(sessions.status(), StatusCode::OK);
        let sessions_body = read_json_body(sessions).await;
        let sessions = sessions_body.as_array().unwrap();
        assert_eq!(sessions.len(), 1);
        assert_eq!(sessions[0]["user_id"], ctx.user_id);
        assert_eq!(sessions[0]["machine_id"], ctx.machine_id.to_string());
    }

    #[tokio::test]
    async fn token_auth_internal_routes_unchanged() {
        let ctx = make_test_context().await;

        let bearer_only = ctx
            .app
            .clone()
            .oneshot(bearer_request(
                Method::GET,
                "/api/internal/sessions",
                &ctx.bearer_token,
            ))
            .await
            .unwrap();
        assert_eq!(bearer_only.status(), StatusCode::UNAUTHORIZED);

        let sessions = ctx
            .app
            .clone()
            .oneshot(internal_request(
                Method::GET,
                "/api/internal/sessions",
                &ctx.internal_token,
            ))
            .await
            .unwrap();
        assert_eq!(sessions.status(), StatusCode::OK);
        let sessions_body = read_json_body(sessions).await;
        let sessions = sessions_body.as_array().unwrap();
        assert_eq!(sessions.len(), 1);
        assert_eq!(sessions[0]["user_id"], ctx.user_id);

        let proxy_rpc = ctx
            .app
            .clone()
            .oneshot(internal_json_request(
                Method::POST,
                &format!(
                    "/api/internal/users/{}/machines/{}/proxy-rpc",
                    ctx.user_id, ctx.machine_id
                ),
                &ctx.internal_token,
                &json!({
                    "service_name": "unknown.service",
                    "method_name": "noop",
                    "payload": {},
                }),
            ))
            .await
            .unwrap();
        assert_eq!(proxy_rpc.status(), StatusCode::BAD_REQUEST);
        let proxy_body = read_json_body(proxy_rpc).await;
        assert!(
            proxy_body["message"]
                .as_str()
                .unwrap()
                .contains("Unknown service")
        );
    }
}
