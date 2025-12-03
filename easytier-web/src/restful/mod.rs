mod auth;
pub(crate) mod captcha;
mod network;
mod users;

use std::{
    net::SocketAddr,
    sync::{
        atomic::{AtomicU64, Ordering},
        Arc,
    },
};

use axum::body::Body;
use axum::http::StatusCode;
use axum::routing::post;
use axum::{extract::State, middleware::Next, response::IntoResponse, routing::get, Json, Router};
use axum_login::tower_sessions::{ExpiredDeletion, SessionManagerLayer};
use axum_login::{login_required, AuthManagerLayerBuilder, AuthUser, AuthzBackend};
use axum_messages::MessagesManagerLayer;
use easytier::common::config::{ConfigLoader, TomlConfigLoader};
use easytier::common::scoped_task::ScopedTask;
use easytier::launcher::NetworkConfig;
use easytier::proto::rpc_types;
use network::NetworkApi;
use sea_orm::DbErr;
use sysinfo::{CpuExt, CpuRefreshKind, NetworkExt, ProcessExt, RefreshKind, System, SystemExt};
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
    config_info: ConfigInfo,
    api_active_requests: Arc<AtomicU64>,
    sys: Arc<tokio::sync::Mutex<System>>,
    net_prev: Arc<tokio::sync::Mutex<Option<(u64, u64, u64)>>>,
    start_time: chrono::DateTime<chrono::Utc>,
    db: Db,

    // serve_task: Option<ScopedTask<()>>,
    // delete_task: Option<ScopedTask<tower_sessions::session_store::Result<()>>>,
    // network_api: NetworkApi<WebClientManager>,
    web_router: Option<Router>,
}

#[derive(Clone)]
pub struct ConfigInfo {
    pub config_server_port: u16,
    pub config_server_protocol: String,
    pub api_server_port: u16,
}

#[derive(Clone)]
struct AppStateInner {
    client_mgr: Arc<ClientManager>,
    config_info: ConfigInfo,
    api_active_requests: Arc<AtomicU64>,
    sys: Arc<tokio::sync::Mutex<System>>,
    net_prev: Arc<tokio::sync::Mutex<Option<(u64, u64, u64)>>>,
    start_time: chrono::DateTime<chrono::Utc>,
}
type AppState = State<AppStateInner>;

impl std::ops::Deref for AppStateInner {
    type Target = ClientManager;
    fn deref(&self) -> &Self::Target {
        &self.client_mgr
    }
}

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
struct ServerStatsResponse {
    config_server_port: u16,
    config_server_protocol: String,
    config_active_connections: u32,
    api_server_port: u16,
    api_active_requests: u64,
}

#[derive(Debug, serde::Deserialize, serde::Serialize)]
struct SystemStatsResponse {
    cpu_percent: f32,
    mem_percent: f64,
    timestamp: u64,
}

#[derive(Debug, serde::Deserialize, serde::Serialize)]
struct NetStatsResponse {
    rx_mbps: f64,
    tx_mbps: f64,
    timestamp: u64,
}

#[derive(Debug, serde::Deserialize, serde::Serialize)]
struct ProcessInfoResponse {
    start_time: String,
    query_time: String,
    open_handles: u64,
    threads: usize,
    memory_mb: f64,
    gc_count: u64,
    heap_mb: f64,
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
        config_info: ConfigInfo,
        db: Db,
        web_router: Option<Router>,
    ) -> anyhow::Result<Self> {
        assert!(client_mgr.is_running());

        // let network_api = NetworkApi::new();

        let sys = System::new_with_specifics(
            RefreshKind::new()
                .with_memory()
                .with_cpu(CpuRefreshKind::everything()),
        );

        Ok(RestfulServer {
            bind_addr,
            client_mgr,
            config_info,
            api_active_requests: Arc::new(AtomicU64::new(0)),
            net_prev: Arc::new(tokio::sync::Mutex::new(None)),
            start_time: chrono::Utc::now(),
            db,
            // serve_task: None,
            // delete_task: None,
            // network_api,
            web_router,
            sys: Arc::new(tokio::sync::Mutex::new(sys)),
        })
    }

    async fn handle_list_all_sessions(
        auth_session: AuthSession,
        State(app_state): AppState,
    ) -> Result<Json<ListSessionJsonResp>, HttpHandleError> {
        let perms = auth_session
            .backend
            .get_group_permissions(auth_session.user.as_ref().unwrap())
            .await
            .unwrap();
        println!("{:?}", perms);
        let ret = app_state.client_mgr.list_sessions().await;
        Ok(ListSessionJsonResp(ret).into())
    }

    async fn handle_get_summary(
        auth_session: AuthSession,
        State(app_state): AppState,
    ) -> Result<Json<GetSummaryJsonResp>, HttpHandleError> {
        let Some(user) = auth_session.user else {
            return Err((StatusCode::UNAUTHORIZED, other_error("No such user").into()));
        };

        let machines = app_state
            .client_mgr
            .list_machine_by_user_id(user.id())
            .await;

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

    async fn handle_get_server_stats(
        auth_session: AuthSession,
        State(app_state): AppState,
    ) -> Result<Json<ServerStatsResponse>, HttpHandleError> {
        if auth_session.user.is_none() {
            return Err((StatusCode::UNAUTHORIZED, other_error("No such user").into()));
        }

        Ok(ServerStatsResponse {
            config_server_port: app_state.config_info.config_server_port,
            config_server_protocol: app_state.config_info.config_server_protocol.clone(),
            config_active_connections: app_state.client_mgr.session_count(),
            api_server_port: app_state.config_info.api_server_port,
            api_active_requests: app_state.api_active_requests.load(Ordering::Relaxed),
        }
        .into())
    }

    async fn count_inflight(
        State(app_state): AppState,
        request: axum::http::Request<Body>,
        next: Next,
    ) -> impl IntoResponse {
        app_state
            .api_active_requests
            .fetch_add(1, Ordering::Relaxed);
        let response = next.run(request).await;
        app_state
            .api_active_requests
            .fetch_sub(1, Ordering::Relaxed);
        response
    }

    async fn handle_get_system_stats(
        auth_session: AuthSession,
        State(app_state): AppState,
    ) -> Result<Json<SystemStatsResponse>, HttpHandleError> {
        if auth_session.user.is_none() {
            return Err((StatusCode::UNAUTHORIZED, other_error("No such user").into()));
        }

        let mut sys = app_state.sys.lock().await;
        sys.refresh_cpu();
        sys.refresh_memory();
        let cpu_percent = sys.global_cpu_info().cpu_usage();
        let total_mem = sys.total_memory() as f64;
        let used_mem = (sys.total_memory() - sys.available_memory()) as f64;
        let mem_percent = if total_mem > 0.0 {
            (used_mem / total_mem) * 100.0
        } else {
            0.0
        };
        let timestamp = chrono::Utc::now().timestamp() as u64;

        Ok(SystemStatsResponse {
            cpu_percent,
            mem_percent,
            timestamp,
        }
        .into())
    }

    async fn handle_get_net_stats(
        auth_session: AuthSession,
        State(app_state): AppState,
    ) -> Result<Json<NetStatsResponse>, HttpHandleError> {
        if auth_session.user.is_none() {
            return Err((StatusCode::UNAUTHORIZED, other_error("No such user").into()));
        }

        let mut sys = app_state.sys.lock().await;
        sys.refresh_networks_list();
        sys.refresh_networks();
        let now = chrono::Utc::now().timestamp() as u64;
        let mut total_rx = 0u64;
        let mut total_tx = 0u64;
        for (_iface, data) in sys.networks() {
            total_rx += data.total_received();
            total_tx += data.total_transmitted();
        }

        let mut prev = app_state.net_prev.lock().await;
        let (rx_mbps, tx_mbps) = if let Some((last_ts, last_rx, last_tx)) = *prev {
            let dt = now.saturating_sub(last_ts).max(1);
            let rx_rate = (total_rx.saturating_sub(last_rx)) as f64 * 8.0 / (dt as f64) / 1_000_000.0;
            let tx_rate = (total_tx.saturating_sub(last_tx)) as f64 * 8.0 / (dt as f64) / 1_000_000.0;
            (rx_rate, tx_rate)
        } else {
            (0.0, 0.0)
        };
        *prev = Some((now, total_rx, total_tx));

        Ok(NetStatsResponse {
            rx_mbps,
            tx_mbps,
            timestamp: now,
        }
        .into())
    }

    async fn handle_get_process_info(
        auth_session: AuthSession,
        State(app_state): AppState,
    ) -> Result<Json<ProcessInfoResponse>, HttpHandleError> {
        if auth_session.user.is_none() {
            return Err((StatusCode::UNAUTHORIZED, other_error("No such user").into()));
        }

        let mut sys = app_state.sys.lock().await;
        sys.refresh_processes();
        let pid = sysinfo::get_current_pid().map_err(|e| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                other_error(format!("Pid error: {:?}", e)).into(),
            )
        })?;
        let process = sys.process(pid).ok_or((
            StatusCode::INTERNAL_SERVER_ERROR,
            other_error("Process not found").into(),
        ))?;

        let open_handles = std::fs::read_dir("/proc/self/fd")
            .ok()
            .map(|iter| iter.count() as u64)
            .unwrap_or(0);

        let threads = std::fs::read_dir("/proc/self/task")
            .ok()
            .map(|iter| iter.count())
            .unwrap_or(0);
        let memory_mb = (process.memory() as f64) / 1024.0; // KB to MB
        let heap_mb = memory_mb;
        let gc_count = 0u64; // Rust 无 GC

        let fmt_time = |t: chrono::DateTime<chrono::Utc>| t.format("%Y-%m-%d %H:%M:%S").to_string();

        Ok(ProcessInfoResponse {
            start_time: fmt_time(app_state.start_time),
            query_time: fmt_time(chrono::Utc::now()),
            open_handles,
            threads,
            memory_mb,
            gc_count,
            heap_mb,
        }
        .into())
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

        let app_state = AppStateInner {
            client_mgr: self.client_mgr.clone(),
            config_info: self.config_info.clone(),
            api_active_requests: self.api_active_requests.clone(),
            sys: self.sys.clone(),
            net_prev: self.net_prev.clone(),
            start_time: self.start_time,
        };

        let app = Router::new()
            .route("/api/v1/summary", get(Self::handle_get_summary))
            .route("/api/v1/sessions", get(Self::handle_list_all_sessions))
            .route("/api/v1/server-stats", get(Self::handle_get_server_stats))
            .route("/api/v1/system-stats", get(Self::handle_get_system_stats))
            .route("/api/v1/net-stats", get(Self::handle_get_net_stats))
            .route("/api/v1/process-info", get(Self::handle_get_process_info))
            .merge(NetworkApi::build_route())
            .route_layer(login_required!(Backend))
            .merge(auth::router())
            .with_state(app_state.clone())
            .layer(axum::middleware::from_fn_with_state(
                app_state.clone(),
                Self::count_inflight,
            ))
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
