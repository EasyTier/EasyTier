use std::{sync::Arc, time::Duration};

use anyhow::{Context as _, Result};
use async_trait::async_trait;
use easytier_core::{
    config::toml::ConfigLoader as _,
    connectivity::{
        manual::ManualTunnelConnector, protocol::raw::TunnelDialer, stun::StunServerConfig,
    },
    management::{ConfigServerEndpoint, ReportedPublicIp, WebClientConfig},
    socket::{IpVersion, SocketContext},
    tunnel::Tunnel,
};
use tokio_util::task::AbortOnDropHandle;
use url::Url;

#[cfg(feature = "management")]
use crate::{
    common::os_info::collect_device_os_info, instance::config_storage::NativeConfigFileStorage,
    rpc_service::logger::NativeLoggerControl,
};
use crate::{
    common::{
        MachineIdOptions,
        config::TomlConfigLoader,
        constants::EASYTIER_VERSION,
        global_ctx::GlobalCtx,
        resolve_machine_id,
        stun::{
            StunInfoCollector, default_stun_server_config, runtime_stun_info_collector_with_servers,
        },
    },
    instance::{
        composition::runtime_one_shot_manual_connector,
        factory::{NativeInstanceFactory, NativeInstanceManager},
        host::NativeInstanceHost,
    },
    tunnel::TunnelScheme,
};

pub use easytier_core::management::InstanceMutationHooks as WebClientHooks;

const PUBLIC_IP_REFRESH_INTERVAL: Duration = Duration::from_secs(10 * 60);
const PUBLIC_IP_MIN_RETRY_INTERVAL: Duration = Duration::from_secs(30);

pub struct WebClient {
    inner: easytier_core::management::WebClient<NativeInstanceFactory>,
    _public_ip_task: Option<AbortOnDropHandle<()>>,
}

impl WebClient {
    pub fn new<T, S, H>(
        connector: T,
        token: S,
        machine_id: uuid::Uuid,
        hostname: H,
        secure_mode: bool,
        manager: Arc<NativeInstanceManager>,
        hooks: Option<Arc<dyn WebClientHooks>>,
    ) -> Self
    where
        T: TunnelDialer + 'static,
        S: ToString,
        H: ToString,
    {
        Self::new_with_stun_servers(
            connector,
            token,
            machine_id,
            hostname,
            secure_mode,
            default_stun_server_config(),
            manager,
            hooks,
        )
    }

    /// Like [`WebClient::new`], but looks up the reported public IP with the
    /// given STUN servers; all-empty lists disable the lookup.
    #[allow(clippy::too_many_arguments)]
    pub fn new_with_stun_servers<T, S, H>(
        connector: T,
        token: S,
        machine_id: uuid::Uuid,
        hostname: H,
        secure_mode: bool,
        stun_servers: StunServerConfig,
        manager: Arc<NativeInstanceManager>,
        hooks: Option<Arc<dyn WebClientHooks>>,
    ) -> Self
    where
        T: TunnelDialer + 'static,
        S: ToString,
        H: ToString,
    {
        let public_ip = ReportedPublicIp::default();
        // Empty server lists are how users disable STUN; respect that here too.
        let stun_disabled = stun_servers.udp_servers.is_empty()
            && stun_servers.tcp_servers.is_empty()
            && stun_servers.udp_v6_servers.is_empty();
        let public_ip_task = (!stun_disabled).then(|| {
            let collector =
                runtime_stun_info_collector_with_servers(SocketContext::default(), stun_servers);
            AbortOnDropHandle::new(tokio::spawn(discover_public_ip(
                collector,
                public_ip.clone(),
            )))
        });
        let config = WebClientConfig {
            token: token.to_string(),
            machine_id,
            hostname: hostname.to_string(),
            device_os: web_client_device_os_info(),
            easytier_version: EASYTIER_VERSION.to_owned(),
            secure_mode,
            public_ip,
        };
        #[cfg(feature = "management")]
        let inner = easytier_core::management::WebClient::new(
            connector,
            config,
            manager,
            hooks.unwrap_or_else(|| Arc::new(DefaultHooks)),
            Arc::new(NativeConfigFileStorage),
            Arc::new(NativeLoggerControl),
        );
        #[cfg(not(feature = "management"))]
        let inner = easytier_core::management::WebClient::new(
            connector,
            config,
            manager,
            hooks.unwrap_or_else(|| Arc::new(DefaultHooks)),
            Arc::new(easytier_core::management::UnsupportedConfigFileStorage),
        );
        Self {
            inner,
            _public_ip_task: public_ip_task,
        }
    }

    pub fn is_connected(&self) -> bool {
        self.inner.is_connected()
    }
}

/// Asks STUN servers for this node's public IP as soon as the web client
/// starts and refreshes it periodically, so heartbeats follow address changes.
/// Failures back off exponentially and only the first of a streak is a warning.
async fn discover_public_ip(collector: StunInfoCollector, public_ip: ReportedPublicIp) {
    let mut retry_interval = PUBLIC_IP_MIN_RETRY_INTERVAL;
    let mut failure_streak = 0u32;
    loop {
        let delay = match collector.query_public_ip().await {
            Ok(ip) => {
                if public_ip.get() != Some(ip) {
                    tracing::info!(%ip, "discovered public IP via STUN for config server");
                    public_ip.set(ip);
                }
                retry_interval = PUBLIC_IP_MIN_RETRY_INTERVAL;
                failure_streak = 0;
                PUBLIC_IP_REFRESH_INTERVAL
            }
            Err(error) => {
                if failure_streak == 0 {
                    tracing::warn!(%error, "failed to discover public IP via STUN; will retry");
                } else {
                    tracing::debug!(%error, failure_streak, "public IP STUN lookup still failing");
                }
                failure_streak = failure_streak.saturating_add(1);
                let delay = retry_interval;
                retry_interval = (retry_interval * 2).min(PUBLIC_IP_REFRESH_INTERVAL);
                delay
            }
        };
        tokio::time::sleep(delay).await;
    }
}

#[cfg(feature = "management")]
fn web_client_device_os_info() -> easytier_proto::web::DeviceOsInfo {
    collect_device_os_info()
}

#[cfg(not(feature = "management"))]
fn web_client_device_os_info() -> easytier_proto::web::DeviceOsInfo {
    easytier_proto::web::DeviceOsInfo {
        os_type: std::env::consts::OS.to_owned(),
        version: String::new(),
        distribution: String::new(),
    }
}

pub struct DefaultHooks;

#[async_trait]
impl WebClientHooks for DefaultHooks {}

struct ConfigServerConnector {
    url: Url,
    connector: ManualTunnelConnector<NativeInstanceHost>,
}

#[async_trait]
impl TunnelDialer for ConfigServerConnector {
    async fn connect(&self) -> anyhow::Result<Box<dyn Tunnel>> {
        self.connector
            .connect(self.url.clone(), IpVersion::Both)
            .await
    }

    fn remote_url(&self) -> Url {
        self.url.clone()
    }
}

pub fn parse_config_server_endpoint(input: &str) -> anyhow::Result<ConfigServerEndpoint> {
    ConfigServerEndpoint::parse(input, |url| TunnelScheme::try_from(url).is_ok())
}

pub async fn run_web_client(
    config_server_url: &str,
    machine_id_options: MachineIdOptions,
    hostname: Option<String>,
    secure_mode: bool,
    manager: Arc<NativeInstanceManager>,
    hooks: Option<Arc<dyn WebClientHooks>>,
) -> Result<WebClient> {
    run_web_client_with_stun_servers(
        config_server_url,
        machine_id_options,
        hostname,
        secure_mode,
        default_stun_server_config(),
        manager,
        hooks,
    )
    .await
}

/// Like [`run_web_client`], but looks up the reported public IP with the given
/// STUN servers; all-empty lists disable the lookup.
pub async fn run_web_client_with_stun_servers(
    config_server_url: &str,
    machine_id_options: MachineIdOptions,
    hostname: Option<String>,
    secure_mode: bool,
    stun_servers: StunServerConfig,
    manager: Arc<NativeInstanceManager>,
    hooks: Option<Arc<dyn WebClientHooks>>,
) -> Result<WebClient> {
    let machine_id = resolve_machine_id(&machine_id_options)
        .with_context(|| "failed to resolve machine id for web client")?;
    let endpoint = parse_config_server_endpoint(config_server_url)?;

    let config = TomlConfigLoader::default();
    let global_ctx = Arc::new(GlobalCtx::new(config.clone()));
    let mut flags = global_ctx.get_flags();
    flags.bind_device = false;
    config.set_flags(flags.clone());
    global_ctx.set_flags(flags);
    let hostname =
        hostname.unwrap_or_else(|| gethostname::gethostname().to_string_lossy().to_string());
    let connector =
        runtime_one_shot_manual_connector(global_ctx, &config, manager.process_runtime())?;

    Ok(WebClient::new_with_stun_servers(
        ConfigServerConnector {
            url: endpoint.connect_url().clone(),
            connector,
        },
        endpoint.token(),
        machine_id,
        hostname,
        secure_mode,
        stun_servers,
        manager,
        hooks,
    ))
}

#[cfg(test)]
mod tests {
    use std::sync::{Arc, atomic::AtomicBool};

    use crate::{common::MachineIdOptions, instance::factory::native_instance_manager};

    #[tokio::test]
    async fn test_manager_wait() {
        let manager = Arc::new(native_instance_manager());
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
            sleep_finish_clone.store(true, std::sync::atomic::Ordering::Relaxed);
            drop(client);
        });

        manager.wait().await;
        assert!(sleep_finish.load(std::sync::atomic::Ordering::Relaxed));
    }

    #[tokio::test]
    async fn test_run_web_client_with_unreachable_config_server() {
        let manager = Arc::new(native_instance_manager());
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
    }
}
