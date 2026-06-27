mod managed_config;
mod runtime_reconcile;
pub mod session;
pub mod storage;

use std::sync::{
    Arc,
    atomic::{AtomicU32, Ordering},
};
use std::time::Duration;

use dashmap::DashMap;
use easytier::{
    proto::{
        api::manage::WebClientService, rpc_types::controller::BaseController, web::HeartbeatRequest,
    },
    rpc_service::remote_client::{self, RemoteClientManager},
    tunnel::TunnelListener,
    web_client::security,
};
use maxminddb::geoip2;
use session::{Location, Session};
use storage::{Storage, StorageToken};

use crate::FeatureFlags;
use crate::webhook::{ManagedNetworkConfig, SharedWebhookConfig};
use tokio::task::JoinSet;

use crate::db::{Db, UserIdInDb, entity::user_running_network_configs};

#[derive(rust_embed::Embed)]
#[folder = "resources/"]
#[include = "geoip2-cn.mmdb"]
struct GeoipDb;

pub fn is_managed_config_revision_conflict(error: &anyhow::Error) -> bool {
    managed_config::is_revision_conflict(error)
}

fn load_geoip_db(geoip_db: Option<String>) -> Option<maxminddb::Reader<Vec<u8>>> {
    if let Some(path) = geoip_db {
        match maxminddb::Reader::open_readfile(&path) {
            Ok(reader) => {
                tracing::info!("Successfully loaded GeoIP2 database from {}", path);
                Some(reader)
            }
            Err(err) => {
                tracing::debug!("Failed to load GeoIP2 database from {}: {}", path, err);
                None
            }
        }
    } else {
        let db = GeoipDb::get("geoip2-cn.mmdb").unwrap();
        let reader = maxminddb::Reader::from_source(db.data.to_vec()).ok()?;
        tracing::info!("Successfully loaded GeoIP2 database from embedded file");
        Some(reader)
    }
}

#[derive(Debug)]
pub struct ClientManager {
    tasks: JoinSet<()>,

    listeners_cnt: Arc<AtomicU32>,

    client_sessions: Arc<DashMap<url::Url, Arc<Session>>>,
    storage: Storage,

    feature_flags: Arc<FeatureFlags>,
    webhook_config: SharedWebhookConfig,

    geoip_db: Arc<Option<maxminddb::Reader<Vec<u8>>>>,
    heartbeat_min_response_delay: Duration,
}

impl ClientManager {
    pub fn new(
        db: Db,
        geoip_db: Option<String>,
        heartbeat_min_response_delay: Duration,
        feature_flags: Arc<FeatureFlags>,
        webhook_config: SharedWebhookConfig,
    ) -> Self {
        let client_sessions = Arc::new(DashMap::new());
        let sessions: Arc<DashMap<url::Url, Arc<Session>>> = client_sessions.clone();
        let mut tasks = JoinSet::new();
        tasks.spawn(async move {
            loop {
                tokio::time::sleep(std::time::Duration::from_secs(15)).await;
                sessions.retain(|_, session| session.is_running());
            }
        });
        ClientManager {
            tasks,

            listeners_cnt: Arc::new(AtomicU32::new(0)),

            client_sessions,
            storage: Storage::new(db),
            feature_flags,
            webhook_config,

            geoip_db: Arc::new(load_geoip_db(geoip_db)),
            heartbeat_min_response_delay,
        }
    }

    pub async fn add_listener<L: TunnelListener + 'static>(
        &mut self,
        mut listener: L,
    ) -> Result<(), anyhow::Error> {
        listener.listen().await?;
        self.listeners_cnt.fetch_add(1, Ordering::Relaxed);
        let sessions = self.client_sessions.clone();
        let storage = self.storage.weak_ref();
        let listeners_cnt = self.listeners_cnt.clone();
        let geoip_db = self.geoip_db.clone();
        let heartbeat_min_response_delay = self.heartbeat_min_response_delay;
        let feature_flags = self.feature_flags.clone();
        let webhook_config = self.webhook_config.clone();
        self.tasks.spawn(async move {
            while let Ok(tunnel) = listener.accept().await {
                let (tunnel, secure) = match security::accept_or_upgrade_server_tunnel(tunnel).await {
                    Ok(v) => v,
                    Err(error) => {
                        tracing::warn!(%error, "failed to accept secure tunnel, dropping connection");
                        continue;
                    }
                };
                let info = tunnel.info().unwrap();
                let client_url: url::Url = info.remote_addr.unwrap().into();
                let location = Self::lookup_location(&client_url, geoip_db.clone());
                tracing::info!(
                    "New session from {:?}, secure: {}, location: {:?}",
                    client_url,
                    secure,
                    location
                );
                let mut session = Session::new(
                    storage.clone(),
                    client_url.clone(),
                    location,
                    heartbeat_min_response_delay,
                    feature_flags.clone(),
                    webhook_config.clone(),
                );
                session.serve(tunnel).await;
                sessions.insert(client_url, Arc::new(session));
            }
            listeners_cnt.fetch_sub(1, Ordering::Relaxed);
        });

        Ok(())
    }

    pub fn is_running(&self) -> bool {
        self.listeners_cnt.load(Ordering::Relaxed) > 0
    }

    pub async fn list_sessions(&self) -> Vec<StorageToken> {
        self.storage.list_clients()
    }

    pub async fn list_all_sessions(&self) -> Vec<StorageToken> {
        self.storage.list_all_clients()
    }

    pub fn get_session_by_machine_id(
        &self,
        user_id: UserIdInDb,
        machine_id: &uuid::Uuid,
    ) -> Option<Arc<Session>> {
        let c_url = self
            .storage
            .get_client_url_by_machine_id(user_id, machine_id)?;
        self.client_sessions
            .get(&c_url)
            .map(|item| item.value().clone())
    }

    pub async fn disconnect_session_by_machine_id(
        &self,
        user_id: UserIdInDb,
        machine_id: &uuid::Uuid,
    ) -> bool {
        let Some(client_url) = self
            .storage
            .get_client_url_by_machine_id_with_auth(user_id, machine_id, false)
        else {
            return false;
        };
        let Some((_, session)) = self.client_sessions.remove(&client_url) else {
            return false;
        };
        session.stop().await;
        true
    }

    pub async fn list_machine_by_user_id(&self, user_id: UserIdInDb) -> Vec<url::Url> {
        self.storage.list_user_clients(user_id)
    }

    pub async fn reconcile_managed_network_configs(
        &self,
        user_id: UserIdInDb,
        machine_id: uuid::Uuid,
        desired_configs: Vec<ManagedNetworkConfig>,
        config_revision: Option<String>,
        expected_config_revision: Option<String>,
    ) -> anyhow::Result<()> {
        let expected_config_revision = match expected_config_revision.as_deref().map(str::trim) {
            None => managed_config::ExpectedConfigRevision::Any,
            Some("") => managed_config::ExpectedConfigRevision::Exact(None),
            Some(revision) => managed_config::ExpectedConfigRevision::Exact(Some(revision)),
        };
        managed_config::reconcile_web_source_configs(
            &self.storage,
            user_id,
            machine_id,
            desired_configs,
            config_revision.as_deref(),
            expected_config_revision,
        )
        .await?;
        if let Some(config_revision) = config_revision
            && let Some(session) = self.get_session_by_machine_id(user_id, &machine_id)
        {
            session
                .notify_config_revision_changed(user_id, machine_id, config_revision)
                .await;
        }
        Ok(())
    }

    pub async fn get_heartbeat_requests(&self, client_url: &url::Url) -> Option<HeartbeatRequest> {
        let s = self.client_sessions.get(client_url)?.clone();
        s.data().read().await.req()
    }

    pub async fn get_machine_location(&self, client_url: &url::Url) -> Option<Location> {
        let s = self.client_sessions.get(client_url)?.clone();
        s.data().read().await.location().cloned()
    }

    fn db(&self) -> &Db {
        self.storage.db()
    }

    fn lookup_location(
        client_url: &url::Url,
        geoip_db: Arc<Option<maxminddb::Reader<Vec<u8>>>>,
    ) -> Option<Location> {
        let host = client_url.host_str()?;
        let ip: std::net::IpAddr = if let Ok(ip) = host.parse() {
            ip
        } else {
            tracing::debug!("Failed to parse host as IP address: {}", host);
            return None;
        };

        // Skip lookup for private/special IPs
        let is_private = match ip {
            std::net::IpAddr::V4(ipv4) => {
                ipv4.is_private() || ipv4.is_loopback() || ipv4.is_unspecified()
            }
            std::net::IpAddr::V6(ipv6) => ipv6.is_loopback() || ipv6.is_unspecified(),
        };

        if is_private {
            tracing::debug!("Skipping GeoIP lookup for special IP: {}", ip);
            let location = Location {
                country: "本地网络".to_string(),
                city: None,
                region: None,
            };
            return Some(location);
        }

        let location = if let Some(db) = &*geoip_db {
            match db.lookup::<geoip2::City>(ip) {
                Ok(city) => {
                    let country = city
                        .country
                        .and_then(|c| c.names)
                        .and_then(|n| {
                            n.get("zh-CN")
                                .or_else(|| n.get("en"))
                                .map(|s| s.to_string())
                        })
                        .unwrap_or_else(|| "海外".to_string());

                    let city_name = city.city.and_then(|c| c.names).and_then(|n| {
                        n.get("zh-CN")
                            .or_else(|| n.get("en"))
                            .map(|s| s.to_string())
                    });

                    let region = city.subdivisions.map(|r| {
                        r.iter()
                            .filter_map(|x| x.names.as_ref())
                            .filter_map(|x| x.get("zh-CN").or_else(|| x.get("en")))
                            .map(|x| x.to_string())
                            .collect::<Vec<_>>()
                            .join(",")
                    });

                    Location {
                        country,
                        city: city_name,
                        region,
                    }
                }
                Err(err) => {
                    tracing::debug!("GeoIP lookup failed for {}: {}", ip, err);
                    Location {
                        country: "海外".to_string(),
                        city: None,
                        region: None,
                    }
                }
            }
        } else {
            tracing::debug!(
                "GeoIP database not available, using default location for {}",
                ip
            );
            Location {
                country: "海外".to_string(),
                city: None,
                region: None,
            }
        };

        Some(location)
    }
}

impl
    RemoteClientManager<
        (UserIdInDb, uuid::Uuid),
        user_running_network_configs::Model,
        sea_orm::DbErr,
    > for ClientManager
{
    fn get_rpc_client(
        &self,
        (user_id, machine_id): (UserIdInDb, uuid::Uuid),
    ) -> Option<Box<dyn WebClientService<Controller = BaseController> + Send>> {
        let s = self.get_session_by_machine_id(user_id, &machine_id)?;
        Some(s.scoped_rpc_client())
    }

    fn get_storage(
        &self,
    ) -> &impl remote_client::Storage<
        (UserIdInDb, uuid::Uuid),
        user_running_network_configs::Model,
        sea_orm::DbErr,
    > {
        self.storage.db()
    }
}

#[cfg(test)]
mod tests {
    use std::{
        collections::VecDeque,
        sync::{
            Arc,
            atomic::{AtomicBool, AtomicUsize, Ordering},
        },
        time::Duration,
    };

    use axum::{Json, Router, extract::State, routing::post};
    use easytier::{
        common::MachineIdOptions,
        instance_manager::NetworkInstanceManager,
        proto::{
            api::manage::{NetworkConfig, NetworkingMethod, PortForwardConfig},
            common::CompressionAlgoPb,
        },
        rpc_service::remote_client::Storage as RemoteStorage,
        tunnel::{
            common::tests::wait_for_condition,
            udp::{UdpTunnelConnector, UdpTunnelListener},
        },
        web_client::{WebClient, run_web_client},
    };
    use serde_json::json;
    use sqlx::Executor;
    use tokio::net::UdpSocket;

    use crate::{
        FeatureFlags, client_manager::ClientManager, db::Db, webhook::ManagedNetworkConfig,
    };

    const MANAGED_CONFIG_TOKEN: &str = "managed-config-token";

    #[derive(Debug, Clone)]
    struct TestWebhookState {
        validate_responses: Arc<tokio::sync::Mutex<VecDeque<bool>>>,
        validate_count: Arc<AtomicUsize>,
        block_second_validate: Arc<AtomicBool>,
        allow_second_validate: Arc<AtomicBool>,
    }

    impl TestWebhookState {
        fn new(validate_responses: impl IntoIterator<Item = bool>) -> Self {
            Self {
                validate_responses: Arc::new(tokio::sync::Mutex::new(
                    validate_responses.into_iter().collect(),
                )),
                validate_count: Arc::new(AtomicUsize::new(0)),
                block_second_validate: Arc::new(AtomicBool::new(false)),
                allow_second_validate: Arc::new(AtomicBool::new(true)),
            }
        }

        fn with_blocked_second_validate(
            validate_responses: impl IntoIterator<Item = bool>,
        ) -> Self {
            let state = Self::new(validate_responses);
            state.block_second_validate.store(true, Ordering::Release);
            state.allow_second_validate.store(false, Ordering::Release);
            state
        }

        fn allow_second_validate(&self) {
            self.allow_second_validate.store(true, Ordering::Release);
        }

        fn validate_count(&self) -> usize {
            self.validate_count.load(Ordering::Acquire)
        }
    }

    async fn validate_token_handler(
        State(state): State<TestWebhookState>,
    ) -> Json<serde_json::Value> {
        let count = state.validate_count.fetch_add(1, Ordering::AcqRel) + 1;
        if count == 2 && state.block_second_validate.load(Ordering::Acquire) {
            while !state.allow_second_validate.load(Ordering::Acquire) {
                tokio::time::sleep(Duration::from_millis(20)).await;
            }
        }
        let valid = state
            .validate_responses
            .lock()
            .await
            .pop_front()
            .unwrap_or(true);
        if !valid {
            return Json(json!({ "valid": false }));
        }

        Json(json!({
            "valid": true,
            "binding_version": count,
            "config_revision": format!("validated-rev-{count}")
        }))
    }

    async fn webhook_ack_handler() -> Json<serde_json::Value> {
        Json(json!({}))
    }

    async fn test_webhook_config() -> (
        crate::webhook::SharedWebhookConfig,
        tokio::task::JoinHandle<()>,
        TestWebhookState,
    ) {
        let state = TestWebhookState::new([true]);
        test_webhook_config_with_state(state).await
    }

    async fn test_webhook_config_with_state(
        state: TestWebhookState,
    ) -> (
        crate::webhook::SharedWebhookConfig,
        tokio::task::JoinHandle<()>,
        TestWebhookState,
    ) {
        let app = Router::new()
            .route("/validate-token", post(validate_token_handler))
            .route("/webhook/node-connected", post(webhook_ack_handler))
            .route("/webhook/node-disconnected", post(webhook_ack_handler))
            .with_state(state.clone());
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });

        (
            Arc::new(crate::webhook::WebhookConfig::new(
                Some(format!("http://{addr}")),
                None,
                None,
                None,
                None,
            )),
            server,
            state,
        )
    }

    async fn add_random_udp_listener(mgr: &mut ClientManager) -> std::net::SocketAddr {
        let socket = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let addr = socket.local_addr().unwrap();
        let listener =
            UdpTunnelListener::new_with_socket(format!("udp://{addr}").parse().unwrap(), socket);
        mgr.add_listener(listener).await.unwrap();
        addr
    }

    async fn wait_for_validated_user(mgr: &ClientManager, machine_id: uuid::Uuid) -> i32 {
        tokio::time::timeout(Duration::from_secs(12), async {
            loop {
                if let Some(token) = mgr.list_sessions().await.into_iter().find(|token| {
                    token.token == MANAGED_CONFIG_TOKEN && token.machine_id == machine_id
                }) {
                    break token.user_id;
                }
                tokio::time::sleep(Duration::from_millis(50)).await;
            }
        })
        .await
        .unwrap()
    }

    async fn wait_for_validate_count(state: &TestWebhookState, target: usize) {
        tokio::time::timeout(Duration::from_secs(12), async {
            loop {
                if state.validate_count() >= target {
                    break;
                }
                tokio::time::sleep(Duration::from_millis(20)).await;
            }
        })
        .await
        .unwrap();
    }

    async fn wait_for_session_urls(mgr: &ClientManager) -> Vec<url::Url> {
        tokio::time::timeout(Duration::from_secs(12), async {
            loop {
                let urls = mgr
                    .client_sessions
                    .iter()
                    .map(|entry| entry.key().clone())
                    .collect::<Vec<_>>();
                if !urls.is_empty() {
                    break urls;
                }
                tokio::time::sleep(Duration::from_millis(50)).await;
            }
        })
        .await
        .unwrap()
    }

    fn managed_config(
        instance_id: uuid::Uuid,
        network_config: serde_json::Value,
    ) -> ManagedNetworkConfig {
        ManagedNetworkConfig {
            instance_id: instance_id.to_string(),
            network_config,
        }
    }

    async fn wait_for_runtime_config(
        manager: &NetworkInstanceManager,
        inst_id: uuid::Uuid,
        predicate: impl Fn(&NetworkConfig) -> bool,
    ) -> NetworkConfig {
        tokio::time::timeout(Duration::from_secs(12), async {
            loop {
                if let Some(config) = manager
                    .get_instance_config(&inst_id)
                    .and_then(|config| NetworkConfig::new_from_config(&config).ok())
                    .filter(|config| predicate(config))
                {
                    break config;
                }
                tokio::time::sleep(Duration::from_millis(50)).await;
            }
        })
        .await
        .unwrap()
    }

    async fn start_web_client_for_test(
        config_server_addr: std::net::SocketAddr,
        machine_id: uuid::Uuid,
        manager: Arc<NetworkInstanceManager>,
    ) -> WebClient {
        run_web_client(
            &format!("udp://{config_server_addr}/{MANAGED_CONFIG_TOKEN}"),
            MachineIdOptions {
                explicit_machine_id: Some(machine_id.to_string()),
                state_dir: None,
            },
            Some("managed-config-core".to_string()),
            false,
            manager,
            None,
        )
        .await
        .unwrap()
    }

    async fn clear_managed_config_db(
        mgr: &ClientManager,
        user_id: i32,
        machine_id: uuid::Uuid,
        instance_id: uuid::Uuid,
    ) {
        mgr.db()
            .delete_web_network_configs((user_id, machine_id), &[instance_id])
            .await
            .unwrap();
        sqlx::query("DELETE FROM managed_config_revisions WHERE user_id = ? AND device_id = ?")
            .bind(user_id)
            .bind(machine_id.to_string())
            .execute(&mgr.db().inner())
            .await
            .unwrap();
    }

    fn assert_updated_runtime_config(updated: &NetworkConfig, instance_id: uuid::Uuid) {
        assert_eq!(
            updated.instance_id.as_deref(),
            Some(instance_id.to_string().as_str())
        );
        assert_eq!(updated.dhcp, Some(false));
        assert_eq!(updated.virtual_ipv4.as_deref(), Some("10.88.0.7"));
        assert_eq!(updated.network_length, Some(24));
        assert_eq!(updated.hostname.as_deref(), Some("managed-updated-host"));
        assert_eq!(updated.network_name.as_deref(), Some("managed-updated"));
        assert_eq!(updated.network_secret.as_deref(), Some("secret-updated"));
        assert_eq!(
            updated.networking_method,
            Some(NetworkingMethod::Manual as i32)
        );
        assert_eq!(updated.peer_urls, vec!["tcp://127.0.0.1:11010".to_string()]);
        assert_eq!(
            updated.proxy_cidrs,
            vec![
                "10.44.0.0/24".to_string(),
                "10.45.0.0/24->10.46.0.0/24".to_string()
            ]
        );
        assert_eq!(updated.no_tun, Some(true));
        assert_eq!(updated.disable_ipv6, Some(true));
        assert_eq!(updated.enable_kcp_proxy, Some(true));
        assert_eq!(updated.disable_kcp_input, Some(true));
        assert_eq!(updated.enable_quic_proxy, Some(true));
        assert_eq!(updated.disable_quic_input, Some(true));
        assert_eq!(updated.disable_p2p, Some(true));
        assert_eq!(updated.p2p_only, Some(true));
        assert_eq!(updated.lazy_p2p, Some(true));
        assert_eq!(updated.relay_all_peer_rpc, Some(true));
        assert_eq!(updated.need_p2p, Some(true));
        assert_eq!(updated.multi_thread, Some(false));
        assert_eq!(updated.proxy_forward_by_system, Some(true));
        assert_eq!(updated.disable_encryption, Some(true));
        assert_eq!(updated.enable_relay_network_whitelist, Some(true));
        assert_eq!(
            updated.relay_network_whitelist,
            vec!["10.44.0.0/24".to_string(), "10.45.0.0/24".to_string()]
        );
        assert_eq!(updated.enable_manual_routes, Some(true));
        assert_eq!(
            updated.routes,
            vec!["10.60.0.0/16".to_string(), "10.61.0.0/16".to_string()]
        );
        assert_eq!(updated.port_forwards[0].bind_ip, "127.0.0.1");
        assert_eq!(updated.port_forwards[0].bind_port, 0);
        assert_eq!(updated.port_forwards[0].dst_ip, "10.88.0.8");
        assert_eq!(updated.port_forwards[0].dst_port, 80);
        assert_eq!(updated.port_forwards[0].proto, "tcp");
        assert_eq!(updated.disable_udp_hole_punching, Some(true));
        assert_eq!(updated.disable_tcp_hole_punching, Some(true));
        assert_eq!(updated.disable_sym_hole_punching, Some(true));
        assert_eq!(updated.disable_upnp, Some(true));
        assert_eq!(updated.disable_relay_data, Some(true));
        assert_eq!(updated.enable_magic_dns, Some(true));
        assert_eq!(updated.enable_private_mode, Some(true));
        assert_eq!(updated.mtu, Some(1360));
        assert_eq!(
            updated.data_compress_algo,
            Some(CompressionAlgoPb::Zstd as i32)
        );
        assert_eq!(updated.encryption_algorithm.as_deref(), Some("xor"));
        assert_eq!(updated.instance_recv_bps_limit, Some(123456));
        assert_eq!(updated.enable_udp_broadcast_relay, Some(true));
        assert_eq!(updated.socket_mark, Some(0));
    }

    fn initial_managed_network_config(inst_id: uuid::Uuid) -> serde_json::Value {
        json!({
            "instance_id": inst_id.to_string(),
            "dhcp": true,
            "network_name": "managed-initial",
            "network_secret": "secret-initial",
            "networking_method": "Standalone",
            "no_tun": true,
            "disable_ipv6": true,
            "enable_kcp_proxy": false,
            "disable_kcp_input": false,
            "relay_all_peer_rpc": false,
            "multi_thread": false,
            "disable_relay_data": false,
            "mtu": 1380
        })
    }

    fn updated_managed_network_config(inst_id: uuid::Uuid) -> serde_json::Value {
        serde_json::to_value(NetworkConfig {
            instance_id: Some(inst_id.to_string()),
            dhcp: Some(false),
            virtual_ipv4: Some("10.88.0.7".to_string()),
            network_length: Some(24),
            hostname: Some("managed-updated-host".to_string()),
            network_name: Some("managed-updated".to_string()),
            network_secret: Some("secret-updated".to_string()),
            networking_method: Some(NetworkingMethod::Manual as i32),
            peer_urls: vec!["tcp://127.0.0.1:11010".to_string()],
            proxy_cidrs: vec![
                "10.44.0.0/24".to_string(),
                "10.45.0.0/24->10.46.0.0/24".to_string(),
            ],
            no_tun: Some(true),
            disable_ipv6: Some(true),
            enable_kcp_proxy: Some(true),
            disable_kcp_input: Some(true),
            enable_quic_proxy: Some(true),
            disable_quic_input: Some(true),
            disable_p2p: Some(true),
            p2p_only: Some(true),
            lazy_p2p: Some(true),
            relay_all_peer_rpc: Some(true),
            need_p2p: Some(true),
            multi_thread: Some(false),
            proxy_forward_by_system: Some(true),
            disable_encryption: Some(true),
            enable_relay_network_whitelist: Some(true),
            relay_network_whitelist: vec!["10.44.0.0/24".to_string(), "10.45.0.0/24".to_string()],
            enable_manual_routes: Some(true),
            routes: vec!["10.60.0.0/16".to_string(), "10.61.0.0/16".to_string()],
            port_forwards: vec![PortForwardConfig {
                bind_ip: "127.0.0.1".to_string(),
                bind_port: 0,
                dst_ip: "10.88.0.8".to_string(),
                dst_port: 80,
                proto: "tcp".to_string(),
            }],
            disable_udp_hole_punching: Some(true),
            disable_tcp_hole_punching: Some(true),
            disable_sym_hole_punching: Some(true),
            disable_upnp: Some(true),
            disable_relay_data: Some(true),
            enable_magic_dns: Some(true),
            enable_private_mode: Some(true),
            mtu: Some(1360),
            data_compress_algo: Some(CompressionAlgoPb::Zstd as i32),
            encryption_algorithm: Some("xor".to_string()),
            instance_recv_bps_limit: Some(123456),
            enable_udp_broadcast_relay: Some(true),
            socket_mark: Some(0),
            ..Default::default()
        })
        .unwrap()
    }

    fn redelivered_managed_network_config(inst_id: uuid::Uuid) -> serde_json::Value {
        serde_json::to_value(NetworkConfig {
            instance_id: Some(inst_id.to_string()),
            dhcp: Some(false),
            virtual_ipv4: Some("10.88.0.7".to_string()),
            network_length: Some(24),
            hostname: Some("managed-redelivered-host".to_string()),
            network_name: Some("managed-redelivered".to_string()),
            network_secret: Some("secret-updated".to_string()),
            networking_method: Some(NetworkingMethod::Manual as i32),
            peer_urls: vec!["tcp://127.0.0.1:11010".to_string()],
            proxy_cidrs: vec![
                "10.44.0.0/24".to_string(),
                "10.45.0.0/24->10.46.0.0/24".to_string(),
            ],
            no_tun: Some(true),
            disable_ipv6: Some(true),
            enable_kcp_proxy: Some(true),
            disable_kcp_input: Some(true),
            relay_all_peer_rpc: Some(true),
            need_p2p: Some(true),
            multi_thread: Some(false),
            enable_private_mode: Some(true),
            mtu: Some(1360),
            data_compress_algo: Some(CompressionAlgoPb::Zstd as i32),
            encryption_algorithm: Some("xor".to_string()),
            instance_recv_bps_limit: Some(654321),
            ..Default::default()
        })
        .unwrap()
    }

    #[tokio::test]
    async fn test_client() {
        let listener = UdpTunnelListener::new("udp://0.0.0.0:54333".parse().unwrap());
        let mut mgr = ClientManager::new(
            Db::memory_db().await,
            None,
            Duration::ZERO,
            Arc::new(FeatureFlags::default()),
            Arc::new(crate::webhook::WebhookConfig::new(
                None, None, None, None, None,
            )),
        );
        mgr.add_listener(Box::new(listener)).await.unwrap();

        mgr.db()
            .inner()
            .execute("INSERT INTO users (username, password) VALUES ('test', 'test')")
            .await
            .unwrap();

        let connector = UdpTunnelConnector::new("udp://127.0.0.1:54333".parse().unwrap());
        let _c = WebClient::new(
            connector,
            "test",
            uuid::Uuid::new_v4(),
            "test",
            false,
            Arc::new(NetworkInstanceManager::new()),
            None,
        );

        wait_for_condition(
            || async { !mgr.client_sessions.is_empty() },
            Duration::from_secs(12),
        )
        .await;

        let req = tokio::time::timeout(Duration::from_secs(12), async {
            loop {
                let sessions = mgr
                    .client_sessions
                    .iter()
                    .map(|item| item.value().clone())
                    .collect::<Vec<_>>();
                if sessions.is_empty() {
                    tokio::time::sleep(Duration::from_millis(100)).await;
                    continue;
                }
                let mut found_req = None;
                for session in sessions {
                    if let Some(req) = session.data().read().await.req() {
                        found_req = Some(req);
                        break;
                    }
                }
                if let Some(req) = found_req {
                    break req;
                }
                tokio::time::sleep(Duration::from_millis(100)).await;
            }
        })
        .await
        .unwrap();
        println!("{:?}", req);
        println!("{:?}", mgr);
    }

    #[tokio::test]
    async fn managed_web_config_revision_updates_running_core_config() {
        let (webhook_config, webhook_server, _) = test_webhook_config().await;
        let mut mgr = ClientManager::new(
            Db::memory_db().await,
            None,
            Duration::ZERO,
            Arc::new(FeatureFlags::default()),
            webhook_config,
        );
        let config_server_addr = add_random_udp_listener(&mut mgr).await;

        let machine_id = uuid::Uuid::new_v4();
        let instance_id = uuid::Uuid::new_v4();
        let core_manager = Arc::new(NetworkInstanceManager::new());
        let client =
            start_web_client_for_test(config_server_addr, machine_id, core_manager.clone()).await;

        let user_id = wait_for_validated_user(&mgr, machine_id).await;
        mgr.reconcile_managed_network_configs(
            user_id,
            machine_id,
            vec![managed_config(
                instance_id,
                initial_managed_network_config(instance_id),
            )],
            Some("rev-initial".to_string()),
            None,
        )
        .await
        .unwrap();

        wait_for_runtime_config(&core_manager, instance_id, |config| {
            config.network_name.as_deref() == Some("managed-initial")
        })
        .await;

        // Online revision update: web-owned running config is fully overwritten
        // when non-hot-patch flags such as enable_kcp_proxy change.
        mgr.reconcile_managed_network_configs(
            user_id,
            machine_id,
            vec![managed_config(
                instance_id,
                updated_managed_network_config(instance_id),
            )],
            Some("rev-updated".to_string()),
            Some("rev-initial".to_string()),
        )
        .await
        .unwrap();

        let updated = wait_for_runtime_config(&core_manager, instance_id, |config| {
            config.network_name.as_deref() == Some("managed-updated")
                && config.enable_kcp_proxy == Some(true)
                && config.port_forwards.len() == 1
        })
        .await;
        assert_updated_runtime_config(&updated, instance_id);

        assert_eq!(
            core_manager.get_instance_network_config_source(&instance_id),
            Some(easytier::common::config::ConfigSource::Web)
        );
        assert_eq!(
            mgr.db()
                .get_managed_config_revision((user_id, machine_id))
                .await
                .unwrap()
                .as_deref(),
            Some("rev-updated")
        );

        // Web DB loss path: clear web-owned config and revision, then simulate
        // the webhook re-posting the authoritative desired config. The already
        // connected session should receive the distinguishable re-delivered
        // revision without restarting.
        clear_managed_config_db(&mgr, user_id, machine_id, instance_id).await;
        assert!(
            mgr.db()
                .get_network_config((user_id, machine_id), &instance_id.to_string())
                .await
                .unwrap()
                .is_none()
        );
        assert!(
            mgr.db()
                .get_managed_config_revision((user_id, machine_id))
                .await
                .unwrap()
                .is_none()
        );

        mgr.reconcile_managed_network_configs(
            user_id,
            machine_id,
            vec![managed_config(
                instance_id,
                redelivered_managed_network_config(instance_id),
            )],
            Some("rev-webhook-redelivery".to_string()),
            None,
        )
        .await
        .unwrap();
        let redelivered = wait_for_runtime_config(&core_manager, instance_id, |config| {
            config.network_name.as_deref() == Some("managed-redelivered")
                && config.instance_recv_bps_limit == Some(654321)
        })
        .await;
        assert_eq!(
            redelivered.instance_id.as_deref(),
            Some(instance_id.to_string().as_str())
        );
        assert_eq!(
            redelivered.hostname.as_deref(),
            Some("managed-redelivered-host")
        );
        assert_eq!(
            redelivered.network_name.as_deref(),
            Some("managed-redelivered")
        );
        assert_eq!(redelivered.enable_kcp_proxy, Some(true));
        assert_eq!(redelivered.instance_recv_bps_limit, Some(654321));
        assert_eq!(
            core_manager.get_instance_network_config_source(&instance_id),
            Some(easytier::common::config::ConfigSource::Web)
        );
        assert_eq!(
            mgr.db()
                .get_managed_config_revision((user_id, machine_id))
                .await
                .unwrap()
                .as_deref(),
            Some("rev-webhook-redelivery")
        );

        // Reconnect path: a fresh core manager has no local runtime state, so
        // the new session must replay the managed config persisted in web DB.
        drop(client);
        let reconnected_core_manager = Arc::new(NetworkInstanceManager::new());
        let _reconnected_client = start_web_client_for_test(
            config_server_addr,
            machine_id,
            reconnected_core_manager.clone(),
        )
        .await;
        wait_for_validated_user(&mgr, machine_id).await;
        let replayed = wait_for_runtime_config(&reconnected_core_manager, instance_id, |config| {
            config.network_name.as_deref() == Some("managed-redelivered")
                && config.instance_recv_bps_limit == Some(654321)
        })
        .await;
        assert_eq!(
            replayed.network_name.as_deref(),
            Some("managed-redelivered")
        );
        assert_eq!(replayed.enable_kcp_proxy, Some(true));
        assert_eq!(replayed.instance_recv_bps_limit, Some(654321));

        webhook_server.abort();
    }

    #[tokio::test]
    async fn webhook_reject_disconnects_and_revalidates_after_reconnect() {
        let webhook_state = TestWebhookState::with_blocked_second_validate([false, true]);
        let (webhook_config, webhook_server, webhook_state) =
            test_webhook_config_with_state(webhook_state).await;
        let mut mgr = ClientManager::new(
            Db::memory_db().await,
            None,
            Duration::ZERO,
            Arc::new(FeatureFlags::default()),
            webhook_config,
        );
        let config_server_addr = add_random_udp_listener(&mut mgr).await;
        let machine_id = uuid::Uuid::new_v4();
        let core_manager = Arc::new(NetworkInstanceManager::new());
        let client =
            start_web_client_for_test(config_server_addr, machine_id, core_manager.clone()).await;

        let first_session_urls = wait_for_session_urls(&mgr).await;
        wait_for_validate_count(&webhook_state, 1).await;
        wait_for_validate_count(&webhook_state, 2).await;
        assert!(
            mgr.list_sessions().await.is_empty(),
            "invalid validate-token response must not authorize the session"
        );

        webhook_state.allow_second_validate();
        let user_id = wait_for_validated_user(&mgr, machine_id).await;
        tokio::time::timeout(Duration::from_secs(12), async {
            loop {
                let reconnected = mgr
                    .client_sessions
                    .iter()
                    .any(|entry| !first_session_urls.iter().any(|url| url == entry.key()));
                if reconnected {
                    break;
                }
                tokio::time::sleep(Duration::from_millis(50)).await;
            }
        })
        .await
        .unwrap();

        assert!(
            client.is_connected(),
            "web client should reconnect after invalid session heartbeat failure"
        );
        assert!(webhook_state.validate_count() >= 2);
        assert!(
            mgr.get_session_by_machine_id(user_id, &machine_id)
                .is_some()
        );

        webhook_server.abort();
    }
}
