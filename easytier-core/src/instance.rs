//! Lifecycle owner for the portable EasyTier runtime.

use std::sync::Arc;

use tokio::sync::Mutex;
use url::Url;

use crate::{
    connectivity::{
        direct::{DirectConnectorHost, DirectConnectorManager, DirectConnectorOptions},
        manual::{
            ManualConnectivityEventSink, ManualConnectorManager, ManualConnectorOptions,
            ManualConnectorSnapshot, ManualEndpointResolver,
        },
        protocol::ClientProtocolUpgrader,
    },
    hole_punch::tcp::{TcpHolePunchConnector, TcpHolePunchHost},
    peers::peer_manager::PeerManagerCore,
    socket::{dns::DnsResolver, tcp::VirtualTcpSocketFactory},
};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CoreInstanceState {
    Created,
    Starting,
    Running,
    Stopping,
    Stopped,
}

#[derive(Debug, Clone)]
pub struct CoreInstanceConfig {
    pub initial_peers: Vec<Url>,
    pub manual: ManualConnectorOptions,
    pub direct: DirectConnectorOptions,
}

impl Default for CoreInstanceConfig {
    fn default() -> Self {
        Self {
            initial_peers: Vec::new(),
            manual: ManualConnectorOptions::default(),
            direct: DirectConnectorOptions::default(),
        }
    }
}

pub struct CoreInstanceAdapters<H>
where
    H: DirectConnectorHost + TcpHolePunchHost,
{
    pub host: Arc<H>,
    pub dns: Arc<dyn DnsResolver>,
    pub endpoint_resolver: Arc<dyn ManualEndpointResolver>,
    pub protocol: Arc<dyn ClientProtocolUpgrader<<H as VirtualTcpSocketFactory>::Socket>>,
    pub manual_events: Option<Arc<dyn ManualConnectivityEventSink>>,
}

/// Owns the portable peer and connectivity runtime for one EasyTier instance.
///
/// An instance is intentionally one-shot: after it is stopped, construct a new
/// instance rather than trying to rebuild partially consumed peer-manager state.
pub struct CoreInstance<H>
where
    H: DirectConnectorHost + TcpHolePunchHost,
{
    state: Mutex<CoreInstanceState>,
    peer_manager: Arc<PeerManagerCore>,
    manual: ManualConnectorManager<H>,
    direct: DirectConnectorManager<H>,
    tcp_hole_punch: TcpHolePunchConnector<H>,
}

impl<H> CoreInstance<H>
where
    H: DirectConnectorHost + TcpHolePunchHost,
{
    pub fn new(
        peer_manager: Arc<PeerManagerCore>,
        adapters: CoreInstanceAdapters<H>,
        config: CoreInstanceConfig,
    ) -> anyhow::Result<Self> {
        let manual = match adapters.manual_events {
            Some(events) => ManualConnectorManager::new_with_events(
                peer_manager.clone(),
                adapters.host.clone(),
                adapters.dns.clone(),
                adapters.endpoint_resolver,
                adapters.protocol.clone(),
                config.manual,
                events,
            ),
            None => ManualConnectorManager::new(
                peer_manager.clone(),
                adapters.host.clone(),
                adapters.dns.clone(),
                adapters.endpoint_resolver,
                adapters.protocol.clone(),
                config.manual,
            ),
        };
        for url in config.initial_peers {
            manual.add_connector(url)?;
        }

        let direct = DirectConnectorManager::new(
            peer_manager.clone(),
            adapters.host.clone(),
            adapters.dns,
            adapters.protocol,
            config.direct,
        );
        let tcp_hole_punch =
            TcpHolePunchConnector::new(peer_manager.clone(), adapters.host.clone());

        Ok(Self {
            state: Mutex::new(CoreInstanceState::Created),
            peer_manager,
            manual,
            direct,
            tcp_hole_punch,
        })
    }

    pub async fn state(&self) -> CoreInstanceState {
        *self.state.lock().await
    }

    pub async fn start(&self) -> anyhow::Result<()> {
        let mut state = self.state.lock().await;
        if *state != CoreInstanceState::Created {
            anyhow::bail!("core instance cannot start from state {state:?}");
        }
        *state = CoreInstanceState::Starting;

        if let Err(error) = self.peer_manager.run().await {
            self.peer_manager.clear_resources().await;
            *state = CoreInstanceState::Stopped;
            return Err(error.into());
        }
        self.direct.run();
        self.tcp_hole_punch.run();
        self.manual.start();

        *state = CoreInstanceState::Running;
        Ok(())
    }

    pub async fn stop(&self) {
        let mut state = self.state.lock().await;
        match *state {
            CoreInstanceState::Created | CoreInstanceState::Stopped => {
                *state = CoreInstanceState::Stopped;
                return;
            }
            CoreInstanceState::Starting
            | CoreInstanceState::Running
            | CoreInstanceState::Stopping => {
                *state = CoreInstanceState::Stopping;
            }
        }

        self.manual.stop().await;
        self.tcp_hole_punch.stop().await;
        self.direct.stop().await;
        self.peer_manager.clear_resources().await;
        *state = CoreInstanceState::Stopped;
    }

    pub fn add_connector(&self, url: Url) -> anyhow::Result<()> {
        self.manual.add_connector(url)
    }

    pub fn remove_connector(&self, url: &Url) -> bool {
        self.manual.remove_connector(url)
    }

    pub fn clear_connectors(&self) {
        self.manual.clear_connectors();
    }

    pub fn list_connectors(&self) -> Vec<ManualConnectorSnapshot> {
        self.manual.list_connectors()
    }
}
