mod auth;
pub(crate) mod captcha;
mod network;
mod users;

use std::{net::SocketAddr, sync::Arc};

use axum::http::StatusCode;
use axum::routing::post;
use axum::{extract::State, routing::get, Extension, Json, Router};
use axum_login::tower_sessions::{ExpiredDeletion, SessionManagerLayer};
use axum_login::{login_required, AuthManagerLayerBuilder, AuthUser, AuthzBackend};
use axum_messages::MessagesManagerLayer;
use easytier::common::config::{ConfigLoader, TomlConfigLoader};
use easytier::common::scoped_task::ScopedTask;
use easytier::launcher::NetworkConfig;
use easytier::proto::rpc_types;
use network::NetworkApi;
use sea_orm::DbErr;
use tokio::net::TcpListener;
use tower_sessions::cookie::time::Duration;
use tower_sessions::cookie::Key;
use tower_sessions::Expiry;
use tower_sessions_sqlx_store::SqliteStore;
use users::{AuthSession, Backend};

use crate::client_manager::storage::StorageToken;
use crate::client_manager::ClientManager;
use crate::db::Db;

/// Embed assets for web dashboard, build frontend first
#[cfg(feature = "embed")]
#[derive(rust_embed::RustEmbed, Clone)]
#[folder = "frontend/dist/"]
struct Assets;

pub struct RestfulServer {
    bind_addr: SocketAddr,
    client_mgr: Arc<ClientManager>,
    registration_disabled: bool,
    db: Db,

    // serve_task: Option<ScopedTask<()>>,
    // delete_task: Option<ScopedTask<tower_sessions::session_store::Result<()>>>,
    // network_api: NetworkApi<WebClientManager>,
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
        registration_disabled: bool,
    ) -> anyhow::Result<Self> {
        assert!(client_mgr.is_running());

        // let network_api = NetworkApi::new();

        Ok(RestfulServer {
            bind_addr,
            client_mgr,
            registration_disabled,
            db,
            // serve_task: None,
            // delete_task: None,
            // network_api,
            web_router,
        })
    }

    async fn handle_list_all_sessions(
        auth_session: AuthSession,
        State(client_mgr): AppState,
    ) -> Result<Json<ListSessionJsonResp>, HttpHandleError> {
        let perms = auth_session
            .backend
            .get_group_permissions(auth_session.user.as_ref().unwrap())
            .await
            .unwrap();
        println!("{:?}", perms);
        let ret = client_mgr.list_sessions().await;
        Ok(ListSessionJsonResp(ret).into())
    }

    async fn handle_get_summary(
        auth_session: AuthSession,
        State(client_mgr): AppState,
    ) -> Result<Json<GetSummaryJsonResp>, HttpHandleError> {
        let Some(user) = auth_session.user else {
            return Err((StatusCode::UNAUTHORIZED, other_error("No such user").into()));
        };

        let machines = client_mgr.list_machine_by_user_id(user.id()).await;

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
    pub async fn start(
        mut self,
    ) -> Result<
        (
            ScopedTask<()>,
            ScopedTask<tower_sessions::session_store::Result<()>>,
        ),
        anyhow::Error,
    > {
        let listener = TcpListener::bind(self.bind_addr).await?;

        // Session layer.
        //
        // This uses `tower-sessions` to establish a layer that will provide the session
        // as a request extension.
        let session_store = SqliteStore::new(self.db.inner());
        session_store.migrate().await?;

        let delete_task: ScopedTask<tower_sessions::session_store::Result<()>> =
            tokio::task::spawn(
                session_store
                    .clone()
                    .continuously_delete_expired(tokio::time::Duration::from_secs(60)),
            )
            .into();

        // Generate a cryptographic key to sign the session cookie.
        let key = Key::generate();

        let session_layer = SessionManagerLayer::new(session_store)
            .with_secure(false)
            .with_expiry(Expiry::OnInactivity(Duration::days(1)))
            .with_signed(key);

        // Auth service.
        //
        // This combines the session layer with our backend to establish the auth
        // service which will provide the auth session as a request extension.
        let backend = Backend::new(self.db.clone());
        let auth_layer = AuthManagerLayerBuilder::new(backend, session_layer).build();
        let compression_layer = tower_http::compression::CompressionLayer::new()
            .br(true)
            .deflate(true)
            .gzip(true)
            .zstd(true)
            .quality(tower_http::compression::CompressionLevel::Default);

        let app = Router::new()
            .route("/api/v1/summary", get(Self::handle_get_summary))
            .route("/api/v1/sessions", get(Self::handle_list_all_sessions))
            .merge(NetworkApi::build_route())
            .route_layer(login_required!(Backend))
            .merge(auth::router().layer(Extension(auth::FeatureFlags {
                disable_registration: self.registration_disabled,
            })))
            .with_state(self.client_mgr.clone())
            .route(
                "/api/v1/generate-config",
                post(Self::handle_generate_config),
            )
            .route("/api/v1/parse-config", post(Self::handle_parse_config))
            .layer(MessagesManagerLayer)
            .layer(auth_layer)
            .layer(tower_http::cors::CorsLayer::very_permissive())
            .layer(compression_layer);

        #[cfg(feature = "embed")]
        let app = if let Some(web_router) = self.web_router.take() {
            app.merge(web_router)
        } else {
            app
        };

        let serve_task: ScopedTask<()> = tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        })
        .into();

        Ok((serve_task, delete_task))
    }
}
