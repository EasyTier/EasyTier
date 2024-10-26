mod auth;
pub(crate) mod captcha;
mod users;

use std::vec;
use std::{net::SocketAddr, sync::Arc};

use axum::extract::{Path, Query};
use axum::http::StatusCode;
use axum::routing::{delete, post};
use axum::{extract::State, routing::get, Json, Router};
use axum_login::tower_sessions::{ExpiredDeletion, SessionManagerLayer};
use axum_login::{login_required, AuthManagerLayerBuilder};
use axum_messages::MessagesManagerLayer;
use easytier::proto::{self, rpc_types, web::*};
use easytier::{common::scoped_task::ScopedTask, proto::rpc_types::controller::BaseController};
use sqlx::migrate::MigrateDatabase;
use sqlx::{Sqlite, SqlitePool};
use tokio::net::TcpListener;
use tower_sessions::cookie::time::Duration;
use tower_sessions::cookie::Key;
use tower_sessions::Expiry;
use tower_sessions_sqlx_store::SqliteStore;
use users::Backend;

use crate::client_manager::session::Session;
use crate::client_manager::storage::StorageToken;
use crate::client_manager::ClientManager;

pub struct RestfulServer {
    bind_addr: SocketAddr,
    client_mgr: Arc<ClientManager>,
    db: SqlitePool,

    serve_task: Option<ScopedTask<()>>,
    delete_task: Option<ScopedTask<tower_sessions::session_store::Result<()>>>,
}

type AppStateInner = Arc<ClientManager>;
type AppState = State<AppStateInner>;

#[derive(Debug, serde::Deserialize, serde::Serialize)]
struct ListSessionJsonResp(Vec<StorageToken>);

#[derive(Debug, serde::Deserialize, serde::Serialize)]
struct ValidateConfigJsonReq {
    config: String,
}

#[derive(Debug, serde::Deserialize, serde::Serialize)]
struct RunNetworkJsonReq {
    config: String,
}

#[derive(Debug, serde::Deserialize, serde::Serialize)]
struct ColletNetworkInfoJsonReq {
    inst_ids: Option<Vec<uuid::Uuid>>,
}

#[derive(Debug, serde::Deserialize, serde::Serialize)]
struct RemoveNetworkJsonReq {
    inst_ids: Vec<uuid::Uuid>,
}

#[derive(Debug, serde::Deserialize, serde::Serialize)]
struct ListNetworkInstanceIdsJsonResp(Vec<uuid::Uuid>);

type Error = proto::error::Error;
type ErrorKind = proto::error::error::ErrorKind;
type RpcError = rpc_types::error::Error;
type HttpHandleError = (StatusCode, Json<Error>);

fn convert_rpc_error(e: RpcError) -> (StatusCode, Json<Error>) {
    let status_code = match &e {
        RpcError::ExecutionError(_) => StatusCode::BAD_REQUEST,
        RpcError::Timeout(_) => StatusCode::GATEWAY_TIMEOUT,
        _ => StatusCode::BAD_GATEWAY,
    };
    let error = Error::from(&e);
    (status_code, Json(error))
}

impl RestfulServer {
    pub async fn new(
        bind_addr: SocketAddr,
        client_mgr: Arc<ClientManager>,
        db_path: &str,
    ) -> anyhow::Result<Self> {
        assert!(client_mgr.is_running());

        Ok(RestfulServer {
            bind_addr,
            client_mgr,
            db: Self::prepare_db(db_path).await?,
            serve_task: None,
            delete_task: None,
        })
    }

    #[tracing::instrument(ret)]
    async fn prepare_db(db_path: &str) -> anyhow::Result<SqlitePool> {
        if !Sqlite::database_exists(db_path).await.unwrap_or(false) {
            tracing::info!("Database not found, creating a new one");
            Sqlite::create_database(db_path).await?;
        }

        let db = SqlitePool::connect(db_path).await?;
        sqlx::migrate!().run(&db).await?;
        Ok(db)
    }

    async fn get_session_by_machine_id(
        client_mgr: &ClientManager,
        machine_id: &uuid::Uuid,
    ) -> Result<Arc<Session>, HttpHandleError> {
        let Some(result) = client_mgr.get_session_by_machine_id(machine_id) else {
            return Err((
                StatusCode::NOT_FOUND,
                Error {
                    error_kind: Some(ErrorKind::OtherError(proto::error::OtherError {
                        error_message: "No such session".to_string(),
                    })),
                }
                .into(),
            ));
        };

        Ok(result)
    }

    async fn handle_list_all_sessions(
        State(client_mgr): AppState,
    ) -> Result<Json<ListSessionJsonResp>, HttpHandleError> {
        let ret = client_mgr.list_sessions().await;
        Ok(ListSessionJsonResp(ret).into())
    }

    async fn handle_validate_config(
        State(client_mgr): AppState,
        Path(machine_id): Path<uuid::Uuid>,
        Json(payload): Json<ValidateConfigJsonReq>,
    ) -> Result<(), HttpHandleError> {
        let config = payload.config;
        let result = Self::get_session_by_machine_id(&client_mgr, &machine_id).await?;

        let c = result.scoped_rpc_client();
        c.validate_config(BaseController::default(), ValidateConfigRequest { config })
            .await
            .map_err(convert_rpc_error)?;
        Ok(())
    }

    async fn handle_run_network_instance(
        State(client_mgr): AppState,
        Path(machine_id): Path<uuid::Uuid>,
        Json(payload): Json<RunNetworkJsonReq>,
    ) -> Result<(), HttpHandleError> {
        let config = payload.config;
        let result = Self::get_session_by_machine_id(&client_mgr, &machine_id).await?;

        let c = result.scoped_rpc_client();
        c.run_network_instance(
            BaseController::default(),
            RunNetworkInstanceRequest { config },
        )
        .await
        .map_err(convert_rpc_error)?;
        Ok(())
    }

    async fn handle_collect_one_network_info(
        State(client_mgr): AppState,
        Path((machine_id, inst_id)): Path<(uuid::Uuid, uuid::Uuid)>,
    ) -> Result<Json<CollectNetworkInfoResponse>, HttpHandleError> {
        let result = Self::get_session_by_machine_id(&client_mgr, &machine_id).await?;

        let c = result.scoped_rpc_client();
        let ret = c
            .collect_network_info(
                BaseController::default(),
                CollectNetworkInfoRequest {
                    inst_ids: vec![inst_id.into()],
                },
            )
            .await
            .map_err(convert_rpc_error)?;
        Ok(ret.into())
    }

    async fn handle_collect_network_info(
        State(client_mgr): AppState,
        Path(machine_id): Path<uuid::Uuid>,
        Query(payload): Query<ColletNetworkInfoJsonReq>,
    ) -> Result<Json<CollectNetworkInfoResponse>, HttpHandleError> {
        let result = Self::get_session_by_machine_id(&client_mgr, &machine_id).await?;

        let c = result.scoped_rpc_client();
        let ret = c
            .collect_network_info(
                BaseController::default(),
                CollectNetworkInfoRequest {
                    inst_ids: payload
                        .inst_ids
                        .unwrap_or_default()
                        .into_iter()
                        .map(Into::into)
                        .collect(),
                },
            )
            .await
            .map_err(convert_rpc_error)?;
        Ok(ret.into())
    }

    async fn handle_list_network_instance_ids(
        State(client_mgr): AppState,
        Path(machine_id): Path<uuid::Uuid>,
    ) -> Result<Json<ListNetworkInstanceIdsJsonResp>, HttpHandleError> {
        let result = Self::get_session_by_machine_id(&client_mgr, &machine_id).await?;

        let c = result.scoped_rpc_client();
        let ret = c
            .list_network_instance(BaseController::default(), ListNetworkInstanceRequest {})
            .await
            .map_err(convert_rpc_error)?;
        Ok(
            ListNetworkInstanceIdsJsonResp(ret.inst_ids.into_iter().map(Into::into).collect())
                .into(),
        )
    }

    async fn handle_remove_network_instance(
        State(client_mgr): AppState,
        Path((machine_id, inst_id)): Path<(uuid::Uuid, uuid::Uuid)>,
    ) -> Result<(), HttpHandleError> {
        let result = Self::get_session_by_machine_id(&client_mgr, &machine_id).await?;

        let c = result.scoped_rpc_client();
        c.delete_network_instance(
            BaseController::default(),
            DeleteNetworkInstanceRequest {
                inst_ids: vec![inst_id.into()],
            },
        )
        .await
        .map_err(convert_rpc_error)?;
        Ok(())
    }

    pub async fn start(&mut self) -> Result<(), anyhow::Error> {
        let listener = TcpListener::bind(self.bind_addr).await?;

        // Session layer.
        //
        // This uses `tower-sessions` to establish a layer that will provide the session
        // as a request extension.
        let session_store = SqliteStore::new(self.db.clone());
        session_store.migrate().await?;

        self.delete_task.replace(
            tokio::task::spawn(
                session_store
                    .clone()
                    .continuously_delete_expired(tokio::time::Duration::from_secs(60)),
            )
            .into(),
        );

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

        let app = Router::new()
            .route("/api/v1/sessions", get(Self::handle_list_all_sessions))
            .route(
                "/api/v1/machine/:machine-id/validate-config",
                post(Self::handle_validate_config),
            )
            .route(
                "/api/v1/machine/:machine-id/networks",
                post(Self::handle_run_network_instance).get(Self::handle_list_network_instance_ids),
            )
            .route(
                "/api/v1/machine/:machine-id/networks/:inst-id",
                delete(Self::handle_remove_network_instance),
            )
            .route(
                "/api/v1/machine/:machine-id/networks/info",
                get(Self::handle_collect_network_info),
            )
            .route(
                "/api/v1/machine/:machine-id/networks/info/:inst-id",
                get(Self::handle_collect_one_network_info),
            )
            .with_state(self.client_mgr.clone())
            .route_layer(login_required!(Backend))
            .merge(auth::router())
            .layer(MessagesManagerLayer)
            .layer(auth_layer)
            .layer(tower_http::cors::CorsLayer::very_permissive());

        let task = tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });
        self.serve_task = Some(task.into());

        Ok(())
    }
}
