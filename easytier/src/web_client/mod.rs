use std::sync::Arc;

use crate::{
    common::{
        config::TomlConfigLoader, global_ctx::GlobalCtx, scoped_task::ScopedTask,
        set_default_machine_id, stun::MockStunInfoCollector,
    },
    connector::create_connector_by_url,
    instance_manager::{DaemonGuard, NetworkInstanceManager},
    proto::common::NatType,
    tunnel::{IpVersion, TunnelConnector},
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
pub mod session;

use std::sync::atomic::{AtomicBool, Ordering};

pub struct WebClient {
    controller: Arc<controller::Controller>,
    tasks: ScopedTask<()>,
    manager_guard: DaemonGuard,
    connected: Arc<AtomicBool>,
}

impl WebClient {
    pub fn new<T: TunnelConnector + 'static, S: ToString, H: ToString>(
        connector: T,
        token: S,
        hostname: H,
        manager: Arc<NetworkInstanceManager>,
        hooks: Option<Arc<dyn WebClientHooks>>,
    ) -> Self {
        let manager_guard = manager.register_daemon();
        let hooks = hooks.unwrap_or_else(|| Arc::new(DefaultHooks));
        let controller = Arc::new(controller::Controller::new(
            token.to_string(),
            hostname.to_string(),
            manager,
            hooks,
        ));
        let connected = Arc::new(AtomicBool::new(false));

        let controller_clone = controller.clone();
        let connected_clone = connected.clone();
        let tasks = ScopedTask::from(tokio::spawn(async move {
            Self::routine(controller_clone, connected_clone, Box::new(connector)).await;
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
        mut connector: Box<dyn TunnelConnector>,
    ) {
        loop {
            let conn = match connector.connect().await {
                Ok(conn) => conn,
                Err(e) => {
                    println!(
                        "Failed to connect to the server ({}), retrying in 5 seconds...",
                        e
                    );
                    tokio::time::sleep(std::time::Duration::from_secs(1)).await;
                    continue;
                }
            };

            connected.store(true, Ordering::Release);
            println!("Successfully connected to {:?}", conn.info());

            let mut session = session::Session::new(conn, controller.clone());
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

    let mut c_url = config_server_url.clone();
    c_url.set_path("");
    let token = config_server_url
        .path_segments()
        .and_then(|mut x| x.next())
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
        create_connector_by_url(c_url.as_str(), &global_ctx, IpVersion::Both).await?,
        token.to_string(),
        hostname,
        manager.clone(),
        hooks,
    ))
}

#[cfg(test)]
mod tests {
    use std::sync::{atomic::AtomicBool, Arc};

    use crate::instance_manager::NetworkInstanceManager;

    #[tokio::test]
    async fn test_manager_wait() {
        let manager = Arc::new(NetworkInstanceManager::new());
        let client = super::run_web_client(
            format!("ring://{}/test", uuid::Uuid::new_v4()).as_str(),
            None,
            None,
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
}
