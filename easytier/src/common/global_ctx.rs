use std::{
    collections::HashSet,
    net::{IpAddr, Ipv6Addr},
    sync::{Arc, Mutex},
};

use arc_swap::ArcSwap;
use async_trait::async_trait;
use easytier_core::connectivity::composite::ConnectorRuntime as _;
use easytier_core::peers::public_ipv6::PublicIpv6Host;
use easytier_core::socket::{NetNamespace, SocketContext};
use easytier_core::tunnel::effective_encryption_uses_xor;
use easytier_core::{
    config::{PeerId, peers::PeerRuntimeSnapshot, runtime::CoreInstanceRuntimeConfig},
    instance::{CoreInstanceConfig, CoreInstanceHostConfig},
};

use super::{
    config::{ConfigLoader, Flags, NetworkIdentity},
    netns::NetNS,
};
#[cfg(feature = "management")]
use crate::proto::api::config::InstanceConfigPatch;
use crate::proto::api::instance::PeerConnInfo;
use crate::proto::common::PortForwardConfigPb;
use crossbeam::atomic::AtomicCell;

#[derive(Debug, Clone, PartialEq)]
#[cfg_attr(feature = "management", derive(serde::Serialize, serde::Deserialize))]
pub enum GlobalCtxEvent {
    TunDeviceReady(String),
    TunDeviceError(String),

    PeerAdded(PeerId),
    PeerRemoved(PeerId),
    PeerConnAdded(PeerConnInfo),
    PeerConnRemoved(PeerConnInfo),

    ListenerAdded(url::Url),
    ListenerAddFailed(url::Url, String), // (url, error message)
    ListenerAcceptFailed(url::Url, String), // (url, error message)
    ConnectionAccepted(String, String),  // (local url, remote url)
    ConnectionError(String, String, String), // (local url, remote url, error message)
    ListenerPortMappingEstablished {
        local_listener: url::Url,
        mapped_listener: url::Url,
        backend: String,
    },

    Connecting(url::Url),
    ConnectError(String, String, String), // (dst, ip version, error message)

    VpnPortalStarted(String),                    // (portal)
    VpnPortalClientConnected(String, String),    // (portal, client ip)
    VpnPortalClientDisconnected(String, String), // (portal, client ip)

    DhcpIpv4Changed(Option<cidr::Ipv4Inet>, Option<cidr::Ipv4Inet>), // (old, new)
    DhcpIpv4Conflicted(Option<cidr::Ipv4Inet>),
    PublicIpv6Changed(Option<cidr::Ipv6Inet>, Option<cidr::Ipv6Inet>), // (old, new)
    PublicIpv6RoutesUpdated(Vec<cidr::Ipv6Inet>, Vec<cidr::Ipv6Inet>), // (added, removed)

    PortForwardAdded(PortForwardConfigPb),

    #[cfg(feature = "management")]
    ConfigPatched(InstanceConfigPatch),

    ProxyCidrsUpdated(Vec<cidr::Ipv4Cidr>, Vec<cidr::Ipv4Cidr>), // (added, removed)

    UdpBroadcastRelayStartResult {
        capture_backend: Option<String>,
        error: Option<String>,
    },

    CredentialChanged,
}

pub type EventBus = tokio::sync::broadcast::Sender<GlobalCtxEvent>;
pub type EventBusSubscriber = tokio::sync::broadcast::Receiver<GlobalCtxEvent>;

pub struct GlobalCtx {
    pub inst_name: String,
    pub id: uuid::Uuid,
    pub config: Box<dyn ConfigLoader>,
    pub net_ns: NetNS,
    pub network: NetworkIdentity,

    event_bus: EventBus,

    cached_ipv4: AtomicCell<Option<cidr::Ipv4Inet>>,
    cached_ipv6: AtomicCell<Option<cidr::Ipv6Inet>>,
    vpn_portal_cidr: AtomicCell<Option<cidr::Ipv4Cidr>>,
    hostname: Mutex<String>,

    tun_device_name: Mutex<Option<String>>,

    flags: ArcSwap<Flags>,
    runtime_endpoint_protocols: Option<HashSet<String>>,
}

impl std::fmt::Debug for GlobalCtx {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("GlobalCtx")
            .field("inst_name", &self.inst_name)
            .field("id", &self.id)
            .field("net_ns", &self.net_ns.name())
            .field("event_bus", &"EventBus")
            .field("ipv4", &self.cached_ipv4)
            .finish()
    }
}

pub type ArcGlobalCtx = std::sync::Arc<GlobalCtx>;

#[async_trait]
impl PublicIpv6Host for GlobalCtx {
    async fn collect_reserved_public_ipv6_addrs(
        &self,
        prefix: cidr::Ipv6Cidr,
    ) -> HashSet<Ipv6Addr> {
        let context = SocketContext::default()
            .with_socket_mark(self.get_flags().socket_mark)
            .with_netns(self.net_ns.name().map(NetNamespace::new));
        let ip_list = crate::host_runtime::native_host_runtime()
            .collect_ip_addrs(&context)
            .await;
        let mut reserved = HashSet::new();
        reserved.extend(
            ip_list
                .interface_ipv6s
                .into_iter()
                .map(Ipv6Addr::from)
                .filter(|addr| prefix.contains(addr)),
        );
        reserved.extend(
            ip_list
                .public_ipv6
                .into_iter()
                .map(Ipv6Addr::from)
                .filter(|addr| prefix.contains(addr)),
        );
        reserved
    }
}

impl GlobalCtx {
    pub fn new(config_fs: impl ConfigLoader + 'static) -> Self {
        Self::new_inner(config_fs, None, None)
    }

    pub(crate) fn new_with_runtime_config(
        config_fs: impl ConfigLoader + 'static,
        runtime: &CoreInstanceConfig,
        host: &CoreInstanceHostConfig,
    ) -> Self {
        let runtime = CoreInstanceRuntimeConfig {
            services: runtime.connectivity.runtime.clone(),
            peer: Arc::new(runtime.peer.snapshot.clone()),
        };
        let protocols = host.ignore_unsupported_config.then(|| {
            host.endpoint_protocols
                .iter()
                .map(|protocol| protocol.to_ascii_lowercase())
                .collect()
        });
        Self::new_inner(config_fs, Some(&runtime), protocols)
    }

    fn new_inner(
        config_fs: impl ConfigLoader + 'static,
        runtime: Option<&CoreInstanceRuntimeConfig>,
        runtime_endpoint_protocols: Option<HashSet<String>>,
    ) -> Self {
        let id = config_fs.get_id();
        let network = config_fs.get_network_identity();
        let net_ns = NetNS::new(config_fs.get_netns());
        let hostname = runtime
            .and_then(|runtime| runtime.peer.runtime.core.node.hostname.clone())
            .unwrap_or_else(|| match config_fs.get_hostname() {
                hostname if !hostname.is_empty() => hostname,
                _ => gethostname::gethostname().to_string_lossy().to_string(),
            });
        let flags = runtime
            .map(|runtime| runtime.peer.flags.clone())
            .unwrap_or_else(|| config_fs.get_flags());
        let ipv4 = runtime
            .map(|runtime| Self::runtime_ipv4(&runtime.peer))
            .unwrap_or_else(|| config_fs.get_ipv4());
        let ipv6 = runtime
            .map(|runtime| Self::runtime_ipv6(&runtime.peer))
            .unwrap_or_else(|| config_fs.get_ipv6());
        let vpn_portal_cidr = runtime
            .map(|runtime| runtime.peer.vpn_portal_cidr)
            .unwrap_or_else(|| {
                config_fs
                    .get_vpn_portal_config()
                    .map(|config| config.client_cidr)
            });
        if flags.enable_encryption && effective_encryption_uses_xor(&flags.encryption_algorithm) {
            tracing::warn!("using insecure XOR because no AEAD encryption is configured");
        }

        let (event_bus, _) = tokio::sync::broadcast::channel(16);
        GlobalCtx {
            inst_name: config_fs.get_inst_name(),
            id,
            config: Box::new(config_fs),
            net_ns: net_ns.clone(),
            network,

            event_bus,
            cached_ipv4: AtomicCell::new(ipv4),
            cached_ipv6: AtomicCell::new(ipv6),
            vpn_portal_cidr: AtomicCell::new(vpn_portal_cidr),
            hostname: Mutex::new(hostname),

            tun_device_name: Mutex::new(None),

            flags: ArcSwap::new(Arc::new(flags)),
            runtime_endpoint_protocols,
        }
    }

    pub(crate) fn runtime_ipv4(peer: &PeerRuntimeSnapshot) -> Option<cidr::Ipv4Inet> {
        let prefix = peer.runtime.core.routes.ipv4.as_ref()?;
        let IpAddr::V4(address) = prefix.address else {
            return None;
        };
        cidr::Ipv4Inet::new(address, prefix.prefix_len).ok()
    }

    pub(crate) fn runtime_ipv6(peer: &PeerRuntimeSnapshot) -> Option<cidr::Ipv6Inet> {
        let prefix = peer.runtime.core.routes.ipv6.as_ref()?;
        let IpAddr::V6(address) = prefix.address else {
            return None;
        };
        cidr::Ipv6Inet::new(address, prefix.prefix_len).ok()
    }

    pub fn subscribe(&self) -> EventBusSubscriber {
        self.event_bus.subscribe()
    }

    pub fn issue_event(&self, event: GlobalCtxEvent) {
        if let Err(e) = self.event_bus.send(event.clone()) {
            tracing::warn!(
                "Failed to send event: {:?}, error: {:?}, receiver count: {}",
                event,
                e,
                self.event_bus.receiver_count()
            );
        }
    }

    #[cfg(any(feature = "tun", test))]
    fn set_tun_device_name(&self, name: Option<String>) {
        *self.tun_device_name.lock().unwrap() = name;
    }

    #[cfg(any(feature = "tun", test))]
    pub(crate) fn set_tun_device_ready(&self, name: String) {
        self.set_tun_device_name(Some(name.clone()));
        self.issue_event(GlobalCtxEvent::TunDeviceReady(name));
    }

    #[cfg(any(feature = "tun", test))]
    pub(crate) fn set_tun_device_error(&self, error: String) {
        self.set_tun_device_name(None);
        self.issue_event(GlobalCtxEvent::TunDeviceError(error));
    }

    pub fn get_tun_device_name(&self) -> Option<String> {
        self.tun_device_name.lock().unwrap().clone()
    }

    pub fn get_ipv4(&self) -> Option<cidr::Ipv4Inet> {
        self.cached_ipv4.load()
    }

    pub fn set_ipv4(&self, addr: Option<cidr::Ipv4Inet>) {
        self.cached_ipv4.store(addr);
    }

    pub fn get_ipv6(&self) -> Option<cidr::Ipv6Inet> {
        self.cached_ipv6.load()
    }

    pub fn set_ipv6(&self, addr: Option<cidr::Ipv6Inet>) {
        self.cached_ipv6.store(addr);
    }

    pub fn is_ip_local_ipv6(&self, ip: &std::net::Ipv6Addr) -> bool {
        self.get_ipv6().map(|x| x.address() == *ip).unwrap_or(false)
    }

    pub fn get_id(&self) -> uuid::Uuid {
        self.config.get_id()
    }

    pub fn is_ip_in_same_network(&self, ip: &IpAddr) -> bool {
        match ip {
            IpAddr::V4(v4) => self.get_ipv4().map(|x| x.contains(v4)).unwrap_or(false),
            IpAddr::V6(v6) => self.get_ipv6().map(|x| x.contains(v6)).unwrap_or(false),
        }
    }

    pub fn is_ip_local_virtual_ip(&self, ip: &IpAddr) -> bool {
        match ip {
            IpAddr::V4(v4) => self.get_ipv4().map(|x| x.address() == *v4).unwrap_or(false),
            IpAddr::V6(v6) => self.is_ip_local_ipv6(v6),
        }
    }

    pub fn get_network_identity(&self) -> NetworkIdentity {
        self.config.get_network_identity()
    }

    pub fn get_network_name(&self) -> String {
        self.get_network_identity().network_name
    }

    pub fn get_hostname(&self) -> String {
        return self.hostname.lock().unwrap().clone();
    }

    pub fn set_hostname(&self, hostname: String) {
        *self.hostname.lock().unwrap() = hostname;
    }

    pub fn get_vpn_portal_cidr(&self) -> Option<cidr::Ipv4Cidr> {
        self.vpn_portal_cidr.load()
    }

    pub fn get_flags(&self) -> Flags {
        self.flags.load().as_ref().clone()
    }

    pub fn set_flags(&self, flags: Flags) {
        self.flags.store(Arc::new(flags));
    }

    pub fn flags_arc(&self) -> Arc<Flags> {
        self.flags.load_full()
    }

    pub fn enable_exit_node(&self) -> bool {
        self.flags.load().enable_exit_node || cfg!(target_env = "ohos")
    }

    pub fn proxy_forward_by_system(&self) -> bool {
        self.flags.load().proxy_forward_by_system
    }

    pub fn no_tun(&self) -> bool {
        self.flags.load().no_tun
    }

    pub fn runtime_mapped_listeners(&self) -> Vec<url::Url> {
        let listeners = self.config.get_mapped_listeners();
        let Some(protocols) = &self.runtime_endpoint_protocols else {
            return listeners;
        };
        listeners
            .into_iter()
            .filter(|listener| protocols.contains(&listener.scheme().to_ascii_lowercase()))
            .collect()
    }
}

#[cfg(test)]
pub mod tests {
    use crate::common::config::TomlConfigLoader;

    use super::*;

    #[tokio::test]
    async fn test_global_ctx() {
        let config = TomlConfigLoader::default();
        let global_ctx = GlobalCtx::new(config);

        let mut subscriber = global_ctx.subscribe();
        let peer_id = rand::random();
        global_ctx.issue_event(GlobalCtxEvent::PeerAdded(peer_id));
        global_ctx.issue_event(GlobalCtxEvent::PeerRemoved(peer_id));
        global_ctx.issue_event(GlobalCtxEvent::PeerConnAdded(PeerConnInfo::default()));
        global_ctx.issue_event(GlobalCtxEvent::PeerConnRemoved(PeerConnInfo::default()));

        assert_eq!(
            subscriber.recv().await.unwrap(),
            GlobalCtxEvent::PeerAdded(peer_id)
        );
        assert_eq!(
            subscriber.recv().await.unwrap(),
            GlobalCtxEvent::PeerRemoved(peer_id)
        );
        assert_eq!(
            subscriber.recv().await.unwrap(),
            GlobalCtxEvent::PeerConnAdded(PeerConnInfo::default())
        );
        assert_eq!(
            subscriber.recv().await.unwrap(),
            GlobalCtxEvent::PeerConnRemoved(PeerConnInfo::default())
        );
    }

    #[tokio::test]
    async fn test_tun_device_name_tracks_explicit_runtime_state() {
        let config = TomlConfigLoader::default();
        let global_ctx = GlobalCtx::new(config);

        assert_eq!(global_ctx.get_tun_device_name(), None);

        global_ctx.issue_event(GlobalCtxEvent::TunDeviceReady("ignored".to_string()));
        assert_eq!(global_ctx.get_tun_device_name(), None);

        let mut subscriber = global_ctx.subscribe();

        global_ctx.set_tun_device_ready("easytier0".to_string());
        assert_eq!(
            global_ctx.get_tun_device_name(),
            Some("easytier0".to_string())
        );
        assert_eq!(
            subscriber.recv().await.unwrap(),
            GlobalCtxEvent::TunDeviceReady("easytier0".to_string())
        );

        global_ctx.set_tun_device_error("closed".to_string());
        assert_eq!(global_ctx.get_tun_device_name(), None);
        assert_eq!(
            subscriber.recv().await.unwrap(),
            GlobalCtxEvent::TunDeviceError("closed".to_string())
        );
    }

    #[test]
    fn host_hostname_fallback_does_not_materialize_in_toml() {
        let config = TomlConfigLoader::default();
        let global_ctx = GlobalCtx::new(config.clone());

        assert!(!global_ctx.get_hostname().is_empty());
        assert!(!config.dump().contains("hostname"));
    }

    #[test]
    fn active_dhcp_ipv4_survives_declarative_config_replacement() {
        let config = TomlConfigLoader::default();
        config.set_dhcp(true);
        let global_ctx = GlobalCtx::new(config.clone());
        let lease = "10.144.144.7/24".parse().unwrap();

        global_ctx.set_ipv4(Some(lease));
        config.set_ipv4(None);

        assert_eq!(global_ctx.get_ipv4(), Some(lease));
    }

    #[test]
    fn runtime_state_does_not_rewrite_toml_config() {
        let config = TomlConfigLoader::default();
        let global_ctx = GlobalCtx::new(config.clone());
        let mut runtime_flags = global_ctx.get_flags();
        runtime_flags.enable_exit_node = true;

        global_ctx.set_ipv4(Some("10.144.144.7/24".parse().unwrap()));
        global_ctx.set_ipv6(Some("fd00::7/64".parse().unwrap()));
        global_ctx.set_flags(runtime_flags);

        assert_eq!(config.get_ipv4(), None);
        assert_eq!(config.get_ipv6(), None);
        assert!(!config.get_flags().enable_exit_node);
        assert_eq!(
            global_ctx.get_ipv4(),
            Some("10.144.144.7/24".parse().unwrap())
        );
        assert_eq!(global_ctx.get_ipv6(), Some("fd00::7/64".parse().unwrap()));
        assert!(global_ctx.get_flags().enable_exit_node);
    }

    #[test]
    fn compact_runtime_does_not_advertise_unsupported_mapped_listeners() {
        let config = TomlConfigLoader::default();
        config.set_mapped_listeners(Some(vec![
            "tcp://127.0.0.1:11010".parse().unwrap(),
            "quic://127.0.0.1:11011".parse().unwrap(),
        ]));
        let host = crate::instance::config::compact_runtime_core_host_config();
        let normalized =
            easytier_core::instance::CoreInstanceConfig::from_toml_with_host(&config, &host)
                .unwrap();

        let global_ctx = GlobalCtx::new_with_runtime_config(config.clone(), &normalized, &host);

        assert_eq!(config.get_mapped_listeners().len(), 2);
        assert_eq!(global_ctx.runtime_mapped_listeners().len(), 1);
        assert_eq!(global_ctx.runtime_mapped_listeners()[0].scheme(), "tcp");
    }

    pub fn get_mock_global_ctx_with_network(
        network_identy: Option<NetworkIdentity>,
    ) -> ArcGlobalCtx {
        let config_fs = TomlConfigLoader::default();
        config_fs.set_inst_name(format!("test_{}", config_fs.get_id()));
        config_fs.set_network_identity(network_identy.unwrap_or_default());

        Arc::new(GlobalCtx::new(config_fs))
    }

    pub fn get_mock_global_ctx() -> ArcGlobalCtx {
        get_mock_global_ctx_with_network(None)
    }
}
