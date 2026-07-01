use std::sync::Arc;

use crate::{
    common::{
        MachineIdOptions,
        config::TomlConfigLoader,
        global_ctx::{ArcGlobalCtx, GlobalCtx},
        log,
        os_info::collect_device_os_info,
        resolve_machine_id,
        stun::MockStunInfoCollector,
    },
    connector::create_connector_by_url,
    instance_manager::{DaemonGuard, NetworkInstanceManager},
    proto::common::NatType,
    tunnel::{IpVersion, Tunnel, TunnelConnector, TunnelError, TunnelScheme},
};
use anyhow::{Context as _, Result};
use async_trait::async_trait;
use tokio_util::task::AbortOnDropHandle;
use url::Url;
use uuid::Uuid;

#[async_trait]
pub trait WebClientHooks: Send + Sync {
    fn manages_remote_config_instances(&self) -> bool {
        false
    }

    async fn pre_run_network_instance(&self, _cfg: &TomlConfigLoader) -> Result<(), String> {
        Ok(())
    }

    async fn post_run_network_instance(&self, _id: &Uuid) -> Result<(), String> {
        Ok(())
    }

    async fn post_remove_network_instances(&self, _ids: &[Uuid]) -> Result<(), String> {
        Ok(())
    }
}

pub struct DefaultHooks;

#[async_trait]
impl WebClientHooks for DefaultHooks {}

pub mod controller;
pub mod security;
pub mod session;

use std::sync::atomic::{AtomicBool, Ordering};

pub struct WebClient {
    controller: Arc<controller::Controller>,
    tasks: AbortOnDropHandle<()>,
    manager_guard: DaemonGuard,
    connected: Arc<AtomicBool>,
}

struct ConfigServerConnector {
    url: Url,
    global_ctx: ArcGlobalCtx,
}

#[async_trait]
impl TunnelConnector for ConfigServerConnector {
    async fn connect(&mut self) -> std::result::Result<Box<dyn Tunnel>, TunnelError> {
        let mut connector =
            create_connector_by_url(self.url.as_str(), &self.global_ctx, IpVersion::Both)
                .await
                .map_err(|err| match err {
                    crate::common::error::Error::TunnelError(err) => err,
                    err => TunnelError::Anyhow(err.into()),
                })?;

        connector.connect().await
    }

    fn remote_url(&self) -> Url {
        self.url.clone()
    }
}

fn parse_config_server_input(config_server_url_s: &str) -> Result<Url> {
    match Url::parse(config_server_url_s) {
        Ok(u) => Ok(u),
        Err(_) => format!(
            "udp://config-server.easytier.cn:22020/{}",
            config_server_url_s
        )
        .parse()
        .with_context(|| "failed to parse config server URL"),
    }
}

fn is_config_server_http_short_link(url: &Url) -> bool {
    matches!(url.scheme(), "http" | "https")
}

impl WebClient {
    pub fn new<T: TunnelConnector + 'static, S: ToString, H: ToString>(
        connector: T,
        token: S,
        machine_id: Uuid,
        hostname: H,
        secure_mode: bool,
        manager: Arc<NetworkInstanceManager>,
        hooks: Option<Arc<dyn WebClientHooks>>,
    ) -> Self {
        let manager_guard = manager.register_daemon();
        let hooks = hooks.unwrap_or_else(|| Arc::new(DefaultHooks));
        let controller = Arc::new(controller::Controller::new(
            token.to_string(),
            machine_id,
            hostname.to_string(),
            collect_device_os_info(),
            manager,
            hooks,
        ));
        let connected = Arc::new(AtomicBool::new(false));

        let controller_clone = controller.clone();
        let connected_clone = connected.clone();
        let tasks = AbortOnDropHandle::new(tokio::spawn(async move {
            Self::routine(
                controller_clone,
                connected_clone,
                secure_mode,
                Box::new(connector),
            )
            .await;
        }));

        WebClient {
            controller,
            tasks,
            manager_guard,
            connected,
        }
    }

    async fn routine(
        controller: Arc<controller::Controller>,
        connected: Arc<AtomicBool>,
        secure_mode: bool,
        mut connector: Box<dyn TunnelConnector>,
    ) {
        loop {
            let conn = match connector.connect().await {
                Ok(conn) => conn,
                Err(error) => {
                    let wait = 1;
                    log::warn!(%error, "Failed to connect to the server, retrying in {} seconds...", wait);
                    tokio::time::sleep(std::time::Duration::from_secs(wait)).await;
                    continue;
                }
            };

            connected.store(true, Ordering::Release);
            log::info!("Successfully connected to {:?}", conn.info());

            let mut session = session::Session::new(conn, controller.clone());
            let support_encryption = match tokio::time::timeout(
                std::time::Duration::from_secs(3),
                session.get_feature(),
            )
            .await
            {
                Ok(Ok(feature)) => feature.support_encryption,
                Ok(Err(error)) => {
                    log::warn!(%error, "GetFeature rpc failed, fallback to legacy tunnel");
                    false
                }
                Err(_) => {
                    log::warn!("GetFeature rpc timeout, fallback to legacy tunnel");
                    false
                }
            };

            if support_encryption && security::web_secure_tunnel_supported() {
                log::info!("Server supports encryption, reconnecting with secure tunnel");
                drop(session);

                let conn = match connector.connect().await {
                    Ok(conn) => conn,
                    Err(error) => {
                        connected.store(false, Ordering::Release);
                        let wait = 1;
                        log::warn!(%error, "Failed to reconnect secure tunnel, retrying in {} seconds...", wait);
                        tokio::time::sleep(std::time::Duration::from_secs(wait)).await;
                        continue;
                    }
                };

                let conn = match security::upgrade_client_tunnel(conn).await {
                    Ok(conn) => conn,
                    Err(error) => {
                        connected.store(false, Ordering::Release);
                        let wait = 1;
                        log::warn!(%error, "Noise handshake failed, retrying in {} seconds...", wait);
                        tokio::time::sleep(std::time::Duration::from_secs(wait)).await;
                        continue;
                    }
                };

                let mut session = session::Session::new(conn, controller.clone());
                session.start_heartbeat().await;
                session.wait().await;
                connected.store(false, Ordering::Release);
                continue;
            }

            if support_encryption {
                if secure_mode {
                    connected.store(false, Ordering::Release);
                    let wait = 1;
                    log::warn!(
                        "secure-mode enabled but local build lacks aes-gcm support for web secure tunnel, retrying in {} seconds...",
                        wait
                    );
                    tokio::time::sleep(std::time::Duration::from_secs(wait)).await;
                    continue;
                }

                log::warn!(
                    "Server supports encryption but local build lacks aes-gcm support for web secure tunnel, falling back to legacy tunnel"
                );
            }

            if secure_mode {
                connected.store(false, Ordering::Release);
                let wait = 1;
                log::warn!(
                    "secure-mode enabled but server does not support encryption, retrying in {} seconds...",
                    wait
                );
                tokio::time::sleep(std::time::Duration::from_secs(wait)).await;
                continue;
            }

            session.start_heartbeat().await;
            session.wait().await;
            connected.store(false, Ordering::Release);
        }
    }

    pub fn is_connected(&self) -> bool {
        self.connected.load(Ordering::Acquire)
    }
}

pub async fn run_web_client(
    config_server_url_s: &str,
    machine_id_opts: MachineIdOptions,
    hostname: Option<String>,
    secure_mode: bool,
    manager: Arc<NetworkInstanceManager>,
    hooks: Option<Arc<dyn WebClientHooks>>,
) -> Result<WebClient> {
    let machine_id = resolve_machine_id(&machine_id_opts)
        .with_context(|| "failed to resolve machine id for web client")?;
    let config_server_url = parse_config_server_input(config_server_url_s)?;

    TunnelScheme::try_from(&config_server_url).map_err(|_| {
        anyhow::anyhow!(
            "unsupported config server scheme: {}",
            config_server_url.scheme()
        )
    })?;

    let mut c_url = config_server_url.clone();
    // Keep HTTP(S) paths so HttpTunnelConnector can request short links and handle their redirects.
    if !matches!(c_url.scheme(), "ws" | "wss") && !is_config_server_http_short_link(&c_url) {
        c_url.set_path("");
    }
    let token = config_server_url
        .path_segments()
        .and_then(|mut x| x.next_back())
        .map(|x| percent_encoding::percent_decode_str(x).decode_utf8())
        .transpose()
        .with_context(|| "failed to decode config server token")?
        .map(|x| x.to_string())
        .unwrap_or_default();

    if token.is_empty() {
        return Err(anyhow::anyhow!("empty token"));
    }

    let config = TomlConfigLoader::default();
    let global_ctx = Arc::new(GlobalCtx::new(config));
    global_ctx.replace_stun_info_collector(Box::new(MockStunInfoCollector {
        udp_nat_type: NatType::Unknown,
    }));
    let mut flags = global_ctx.get_flags();
    flags.bind_device = false;
    global_ctx.set_flags(flags);

    let hostname = match hostname {
        None => gethostname::gethostname().to_string_lossy().to_string(),
        Some(hostname) => hostname,
    };
    Ok(WebClient::new(
        ConfigServerConnector {
            url: c_url,
            global_ctx,
        },
        token.to_string(),
        machine_id,
        hostname,
        secure_mode,
        manager,
        hooks,
    ))
}

#[cfg(test)]
mod tests {
    use std::sync::{Arc, atomic::AtomicBool};

    use crate::{
        common::{MachineIdOptions, config::TomlConfigLoader, global_ctx::GlobalCtx},
        instance_manager::NetworkInstanceManager,
        tunnel::TunnelConnector,
    };
    use tokio::{
        io::{AsyncReadExt as _, AsyncWriteExt as _},
        net::TcpListener,
    };

    #[tokio::test]
    async fn test_manager_wait() {
        let manager = Arc::new(NetworkInstanceManager::new());
        let temp_dir = tempfile::tempdir().unwrap();
        let client = super::run_web_client(
            format!("ring://{}/test", uuid::Uuid::new_v4()).as_str(),
            MachineIdOptions {
                explicit_machine_id: None,
                state_dir: Some(temp_dir.path().to_path_buf()),
            },
            None,
            false,
            manager.clone(),
            None,
        )
        .await
        .unwrap();
        let sleep_finish = Arc::new(AtomicBool::new(false));
        let sleep_finish_clone = sleep_finish.clone();

        tokio::spawn(async move {
            tokio::time::sleep(std::time::Duration::from_secs(3)).await;
            println!("Dropping client...");
            sleep_finish_clone.store(true, std::sync::atomic::Ordering::Relaxed);
            drop(client);
            println!("Client dropped.");
        });

        println!("Waiting for manager...");
        manager.wait().await;
        assert!(sleep_finish.load(std::sync::atomic::Ordering::Relaxed));
        println!("Manager stopped.");
    }

    #[tokio::test]
    async fn test_run_web_client_with_unreachable_config_server() {
        let manager = Arc::new(NetworkInstanceManager::new());
        let temp_dir = tempfile::tempdir().unwrap();
        let client = super::run_web_client(
            "udp://config-server.invalid:22020/test",
            MachineIdOptions {
                explicit_machine_id: None,
                state_dir: Some(temp_dir.path().to_path_buf()),
            },
            None,
            false,
            manager,
            None,
        )
        .await
        .unwrap();

        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
        assert!(!client.is_connected());
        drop(client);
    }

    #[tokio::test]
    async fn config_server_short_link_uses_existing_http_redirect_connector() {
        let target_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let target_addr = target_listener.local_addr().unwrap();
        let target_task = tokio::spawn(async move {
            let _ = target_listener.accept().await.unwrap();
        });

        let http_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let http_addr = http_listener.local_addr().unwrap();
        let http_task = tokio::spawn(async move {
            let (mut stream, _) = http_listener.accept().await.unwrap();
            let mut buf = [0u8; 4096];
            let n = stream.read(&mut buf).await.unwrap();
            let req = String::from_utf8_lossy(&buf[..n]).to_string();
            let resp = format!(
                "HTTP/1.1 302 Found\r\nLocation: tcp://{}\r\nContent-Length: 0\r\n\r\n",
                target_addr
            );
            stream.write_all(resp.as_bytes()).await.unwrap();
            req
        });

        let config = TomlConfigLoader::default();
        let global_ctx = Arc::new(GlobalCtx::new(config));
        let mut flags = global_ctx.get_flags();
        flags.bind_device = false;
        global_ctx.set_flags(flags);
        let url: url::Url = format!("http://{}/short-token", http_addr).parse().unwrap();
        let mut connector = super::ConfigServerConnector { url, global_ctx };

        let tunnel = connector.connect().await.unwrap();

        let req = http_task.await.unwrap();
        assert!(req.starts_with("GET /short-token "));
        let info = tunnel.info().unwrap();
        assert_eq!(
            info.resolved_remote_addr.unwrap().url,
            format!("tcp://{}", target_addr)
        );
        target_task.await.unwrap();
    }
}
