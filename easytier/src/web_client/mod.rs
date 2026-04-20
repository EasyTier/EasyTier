use std::sync::Arc;

use crate::{
    common::{
        config::TomlConfigLoader,
        global_ctx::{ArcGlobalCtx, GlobalCtx},
        idn, log,
        os_info::collect_device_os_info,
        scoped_task::ScopedTask,
        set_default_machine_id,
        stun::MockStunInfoCollector,
    },
    connector::create_connector_by_url,
    instance_manager::{DaemonGuard, NetworkInstanceManager},
    proto::common::NatType,
    tunnel::{IpVersion, Tunnel, TunnelConnector, TunnelScheme},
};
use anyhow::{Context as _, Result};
use async_trait::async_trait;
use url::Url;
use uuid::Uuid;

#[async_trait]
pub trait WebClientHooks: Send + Sync {
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
    tasks: ScopedTask<()>,
    manager_guard: DaemonGuard,
    connected: Arc<AtomicBool>,
}

enum ConnectorSource {
    Fixed(Box<dyn TunnelConnector>),
    ConfigServer { url: Url, global_ctx: ArcGlobalCtx },
}

impl ConnectorSource {
    async fn connect(&mut self) -> Result<Box<dyn Tunnel>> {
        match self {
            Self::Fixed(connector) => Ok(connector.connect().await?),
            Self::ConfigServer { url, global_ctx } => {
                let mut connector =
                    create_connector_by_url(url.as_str(), global_ctx, IpVersion::Both)
                        .await
                        .with_context(|| {
                            format!("failed to create connector for config server {}", url)
                        })?;
                Ok(connector
                    .connect()
                    .await
                    .with_context(|| format!("failed to connect to config server {}", url))?)
            }
        }
    }
}

fn validate_config_server_url(config_server_url: &Url) -> Result<Url> {
    let config_server_url = idn::convert_idn_to_ascii(config_server_url.clone())?;
    let scheme = TunnelScheme::try_from(&config_server_url).map_err(|_| {
        anyhow::anyhow!(
            "unsupported config server scheme: {}",
            config_server_url.scheme()
        )
    })?;

    match scheme {
        #[cfg(unix)]
        TunnelScheme::Unix => {}
        TunnelScheme::Ip(_)
        | TunnelScheme::Http
        | TunnelScheme::Https
        | TunnelScheme::Ring
        | TunnelScheme::Txt
        | TunnelScheme::Srv => {
            if config_server_url.host_str().is_none() {
                anyhow::bail!(
                    "config server URL host should not be empty: {}",
                    config_server_url
                );
            }
        }
    }

    Ok(config_server_url)
}

impl WebClient {
    pub fn new<T: TunnelConnector + 'static, S: ToString, H: ToString>(
        connector: T,
        token: S,
        hostname: H,
        secure_mode: bool,
        manager: Arc<NetworkInstanceManager>,
        hooks: Option<Arc<dyn WebClientHooks>>,
    ) -> Self {
        Self::new_inner(
            ConnectorSource::Fixed(Box::new(connector)),
            token,
            hostname,
            secure_mode,
            manager,
            hooks,
        )
    }

    fn new_from_config_server<S: ToString, H: ToString>(
        config_server_url: Url,
        global_ctx: ArcGlobalCtx,
        token: S,
        hostname: H,
        secure_mode: bool,
        manager: Arc<NetworkInstanceManager>,
        hooks: Option<Arc<dyn WebClientHooks>>,
    ) -> Self {
        Self::new_inner(
            ConnectorSource::ConfigServer {
                url: config_server_url,
                global_ctx,
            },
            token,
            hostname,
            secure_mode,
            manager,
            hooks,
        )
    }

    fn new_inner<S: ToString, H: ToString>(
        connector: ConnectorSource,
        token: S,
        hostname: H,
        secure_mode: bool,
        manager: Arc<NetworkInstanceManager>,
        hooks: Option<Arc<dyn WebClientHooks>>,
    ) -> Self {
        let manager_guard = manager.register_daemon();
        let hooks = hooks.unwrap_or_else(|| Arc::new(DefaultHooks));
        let controller = Arc::new(controller::Controller::new(
            token.to_string(),
            hostname.to_string(),
            collect_device_os_info(),
            manager,
            hooks,
        ));
        let connected = Arc::new(AtomicBool::new(false));

        let controller_clone = controller.clone();
        let connected_clone = connected.clone();
        let tasks = ScopedTask::from(tokio::spawn(async move {
            Self::routine(controller_clone, connected_clone, secure_mode, connector).await;
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
        mut connector: ConnectorSource,
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
    machine_id: Option<String>,
    hostname: Option<String>,
    secure_mode: bool,
    manager: Arc<NetworkInstanceManager>,
    hooks: Option<Arc<dyn WebClientHooks>>,
) -> Result<WebClient> {
    set_default_machine_id(machine_id);
    let config_server_url = match Url::parse(config_server_url_s) {
        Ok(u) => u,
        Err(_) => format!(
            "udp://config-server.easytier.cn:22020/{}",
            config_server_url_s
        )
        .parse()
        .with_context(|| "failed to parse config server URL")?,
    };

    let mut c_url = validate_config_server_url(&config_server_url)?;
    if !matches!(c_url.scheme(), "ws" | "wss") {
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

    // Validate connector construction up front without forcing DNS resolution while offline.
    create_connector_by_url(c_url.as_str(), &global_ctx, IpVersion::Both).await?;

    let hostname = match hostname {
        None => gethostname::gethostname().to_string_lossy().to_string(),
        Some(hostname) => hostname,
    };
    Ok(WebClient::new_from_config_server(
        c_url,
        global_ctx,
        token.to_string(),
        hostname,
        secure_mode,
        manager.clone(),
        hooks,
    ))
}

#[cfg(test)]
mod tests {
    use std::sync::{Arc, atomic::AtomicBool};

    use crate::instance_manager::NetworkInstanceManager;

    #[tokio::test]
    async fn test_manager_wait() {
        let manager = Arc::new(NetworkInstanceManager::new());
        let client = super::run_web_client(
            format!("ring://{}/test", uuid::Uuid::new_v4()).as_str(),
            None,
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
        let client = super::run_web_client(
            "udp://config-server.invalid:22020/test",
            None,
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
    async fn test_run_web_client_rejects_invalid_config_server_scheme() {
        let manager = Arc::new(NetworkInstanceManager::new());
        let err =
            match super::run_web_client("ftp://example.com/test", None, None, false, manager, None)
                .await
            {
                Ok(_) => panic!("invalid config server scheme should fail fast"),
                Err(err) => err,
            };

        assert!(err.to_string().contains("unsupported config server scheme"));
    }
}
