use std::sync::Arc;

use anyhow::{Context as _, Result};
use async_trait::async_trait;
use easytier_core::{
    connectivity::{manual::ManualTunnelConnector, protocol::raw::TunnelDialer},
    management::{ConfigServerEndpoint, WebClientConfig},
    socket::IpVersion,
    tunnel::Tunnel,
};
use url::Url;

use crate::{
    common::{
        MachineIdOptions, config::TomlConfigLoader, constants::EASYTIER_VERSION,
        global_ctx::GlobalCtx, os_info::collect_device_os_info, resolve_machine_id,
    },
    instance::{
        composition::runtime_one_shot_manual_connector,
        config_storage::NativeConfigFileStorage,
        factory::{NativeInstanceFactory, NativeInstanceSet},
        host::NativeInstanceHost,
    },
    rpc_service::logger::NativeLoggerControl,
    tunnel::TunnelScheme,
};

pub use easytier_core::management::InstanceMutationHooks as WebClientHooks;

pub struct WebClient {
    inner: easytier_core::management::WebClient<NativeInstanceFactory, NativeInstanceHost>,
}

impl WebClient {
    pub fn new<T, S, H>(
        connector: T,
        token: S,
        machine_id: uuid::Uuid,
        hostname: H,
        secure_mode: bool,
        manager: Arc<NativeInstanceSet>,
        hooks: Option<Arc<dyn WebClientHooks>>,
    ) -> Self
    where
        T: TunnelDialer + 'static,
        S: ToString,
        H: ToString,
    {
        Self {
            inner: easytier_core::management::WebClient::new(
                connector,
                WebClientConfig {
                    token: token.to_string(),
                    machine_id,
                    hostname: hostname.to_string(),
                    device_os: collect_device_os_info(),
                    easytier_version: EASYTIER_VERSION.to_owned(),
                    secure_mode,
                },
                manager,
                hooks.unwrap_or_else(|| Arc::new(DefaultHooks)),
                Arc::new(NativeConfigFileStorage),
                Arc::new(NativeLoggerControl),
            ),
        }
    }

    pub fn is_connected(&self) -> bool {
        self.inner.is_connected()
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
    manager: Arc<NativeInstanceSet>,
    hooks: Option<Arc<dyn WebClientHooks>>,
) -> Result<WebClient> {
    let machine_id = resolve_machine_id(&machine_id_options)
        .with_context(|| "failed to resolve machine id for web client")?;
    let endpoint = parse_config_server_endpoint(config_server_url)?;

    let config = TomlConfigLoader::default();
    let global_ctx = Arc::new(GlobalCtx::new(config.clone()));
    let mut flags = global_ctx.get_flags();
    flags.bind_device = false;
    global_ctx.set_flags(flags);
    let hostname =
        hostname.unwrap_or_else(|| gethostname::gethostname().to_string_lossy().to_string());
    let connector =
        runtime_one_shot_manual_connector(global_ctx, &config, manager.process_runtime())?;

    Ok(WebClient::new(
        ConfigServerConnector {
            url: endpoint.connect_url().clone(),
            connector,
        },
        endpoint.token(),
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

    use crate::{common::MachineIdOptions, instance::factory::native_instance_set};

    #[tokio::test]
    async fn test_manager_wait() {
        let manager = Arc::new(native_instance_set());
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
        let manager = Arc::new(native_instance_set());
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
