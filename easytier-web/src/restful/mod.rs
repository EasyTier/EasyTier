mod auth;
pub(crate) mod captcha;
mod network;
mod users;

use std::{net::SocketAddr, sync::Arc};

use axum::http::StatusCode;
use axum::{extract::State, routing::get, Json, Router};
use axum_login::tower_sessions::{ExpiredDeletion, SessionManagerLayer};
use axum_login::{login_required, AuthManagerLayerBuilder, AuthzBackend};
use axum_messages::MessagesManagerLayer;
use easytier::common::scoped_task::ScopedTask;
use easytier::proto::{self, rpc_types};
use network::NetworkApi;
use tokio::net::TcpListener;
use tower_sessions::cookie::time::Duration;
use tower_sessions::cookie::Key;
use tower_sessions::Expiry;
use tower_sessions_sqlx_store::SqliteStore;
use users::{AuthSession, Backend};

use crate::client_manager::session::Session;
use crate::client_manager::storage::StorageToken;
use crate::client_manager::ClientManager;
use crate::db::Db;

pub struct RestfulServer {
    bind_addr: SocketAddr,
    client_mgr: Arc<ClientManager>,
    db: Db,

    serve_task: Option<ScopedTask<()>>,
    delete_task: Option<ScopedTask<tower_sessions::session_store::Result<()>>>,

    network_api: NetworkApi,
}

type AppStateInner = Arc<ClientManager>;
type AppState = State<AppStateInner>;

#[derive(Debug, serde::Deserialize, serde::Serialize)]
struct ListSessionJsonResp(Vec<StorageToken>);

pub type Error = proto::error::Error;
pub type ErrorKind = proto::error::error::ErrorKind;
type RpcError = rpc_types::error::Error;
type HttpHandleError = (StatusCode, Json<Error>);

pub fn other_error<T: ToString>(error_message: T) -> Error {
    Error {
        error_kind: Some(ErrorKind::OtherError(proto::error::OtherError {
            error_message: error_message.to_string(),
        })),
    }
}

impl RestfulServer {
    pub async fn new(
        bind_addr: SocketAddr,
        client_mgr: Arc<ClientManager>,
        db: Db,
    ) -> anyhow::Result<Self> {
        assert!(client_mgr.is_running());

        let network_api = NetworkApi::new();

        Ok(RestfulServer {
            bind_addr,
            client_mgr,
            db,
            serve_task: None,
            delete_task: None,
            network_api,
        })
    }

    async fn get_session_by_machine_id(
        client_mgr: &ClientManager,
        machine_id: &uuid::Uuid,
    ) -> Result<Arc<Session>, HttpHandleError> {
        let Some(result) = client_mgr.get_session_by_machine_id(machine_id) else {
            return Err((StatusCode::NOT_FOUND, other_error("No such session").into()));
        };

        Ok(result)
    }

    async fn handle_list_all_sessions(
        auth_session: AuthSession,
        State(client_mgr): AppState,
    ) -> Result<Json<ListSessionJsonResp>, HttpHandleError> {
        let pers = auth_session
            .backend
            .get_group_permissions(auth_session.user.as_ref().unwrap())
            .await
            .unwrap();
        println!("{:?}", pers);
        let ret = client_mgr.list_sessions().await;
        Ok(ListSessionJsonResp(ret).into())
    }

    pub async fn start(&mut self) -> Result<(), anyhow::Error> {
        let listener = TcpListener::bind(self.bind_addr).await?;

        // Session layer.
        //
        // This uses `tower-sessions` to establish a layer that will provide the session
        // as a request extension.
        let session_store = SqliteStore::new(self.db.inner());
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
            .merge(self.network_api.build_route())
            .route_layer(login_required!(Backend))
            .merge(auth::router())
            .with_state(self.client_mgr.clone())
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
