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
    config::{PeerId, runtime::InstanceConfigStore},
    instance::CoreInstanceHostConfig,
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
    hostname: Mutex<String>,

    tun_device_name: Mutex<Option<String>>,

    flags: ArcSwap<Flags>,
    runtime_endpoint_protocols: Option<HashSet<String>>,
    pub(crate) runtime_config_store: Option<InstanceConfigStore>,
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
        Self::new_inner(config_fs, None, None, None)
    }

    pub(crate) fn new_with_runtime_config(
        config_fs: impl ConfigLoader + 'static,
        store: &InstanceConfigStore,
        host: &CoreInstanceHostConfig,
    ) -> Self {
        let snapshot = store.snapshot();
        let parsed = snapshot.parsed();
        let protocols = host.ignore_unsupported_config.then(|| {
            host.endpoint_protocols
                .iter()
                .map(|protocol| protocol.to_ascii_lowercase())
                .collect()
        });
        Self::new_inner(config_fs, Some(parsed), protocols, Some(store.clone()))
    }

    fn new_inner(
        config_fs: impl ConfigLoader + 'static,
        prepared: Option<&easytier_core::config::InstanceConfigParsed>,
        runtime_endpoint_protocols: Option<HashSet<String>>,
        runtime_config_store: Option<InstanceConfigStore>,
    ) -> Self {
        let id = config_fs.get_id();
        let network = config_fs.get_network_identity();
        let net_ns = NetNS::new(config_fs.get_netns());
        let hostname = prepared
            .and_then(|p| {
                let h = &p.hostname;
                (!h.is_empty()).then(|| h.clone())
            })
            .unwrap_or_else(|| match config_fs.get_hostname() {
                hostname if !hostname.is_empty() => hostname,
                _ => gethostname::gethostname().to_string_lossy().to_string(),
            });
        let flags = prepared
            .map(|p| p.flags.clone())
            .unwrap_or_else(|| config_fs.get_flags());
        let ipv4 = prepared
            .and_then(|p| p.ipv4)
            .or_else(|| config_fs.get_ipv4());
        let ipv6 = prepared
            .and_then(|p| p.ipv6)
            .or_else(|| config_fs.get_ipv6());
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
            hostname: Mutex::new(hostname),

            tun_device_name: Mutex::new(None),

            flags: ArcSwap::new(Arc::new(flags)),
            runtime_endpoint_protocols,
            runtime_config_store,
        }
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
        if let Some(store) = &self.runtime_config_store {
            let hostname = store.snapshot().hostname.clone();
            if !hostname.is_empty() {
                return hostname;
            }
        }
        self.hostname.lock().unwrap().clone()
    }

    pub fn set_hostname(&self, hostname: String) {
        *self.hostname.lock().unwrap() = hostname;
    }

    pub fn get_flags(&self) -> Flags {
        if let Some(store) = &self.runtime_config_store {
            let mut flags = store.snapshot().flags.clone();
            let local_flags = self.flags.load();
            if flags.dev_name.is_empty() && !local_flags.dev_name.is_empty() {
                flags.dev_name = local_flags.dev_name.clone();
            }
            return flags;
        }
        self.flags.load().as_ref().clone()
    }

    pub fn set_flags(&self, flags: Flags) {
        self.flags.store(Arc::new(flags));
    }

    pub fn flags_arc(&self) -> Arc<Flags> {
        Arc::new(self.get_flags())
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
        use easytier_core::config::{runtime::InstanceConfigStore, toml::ConfigLoader as _};

        let config = TomlConfigLoader::default();
        config.set_mapped_listeners(Some(vec![
            "tcp://127.0.0.1:11010".parse().unwrap(),
            "quic://127.0.0.1:11011".parse().unwrap(),
        ]));
        let host = crate::instance::config::compact_runtime_core_host_config();
        let snapshot = config.snapshot().unwrap();
        let prepared = easytier_core::instance::prepare_instance_config(snapshot, &host).unwrap();
        let store = InstanceConfigStore::new(prepared);

        let global_ctx = GlobalCtx::new_with_runtime_config(config.clone(), &store, &host);

        assert_eq!(config.get_mapped_listeners().len(), 2);
        assert_eq!(global_ctx.runtime_mapped_listeners().len(), 1);
        assert_eq!(global_ctx.runtime_mapped_listeners()[0].scheme(), "tcp");
    }

    #[tokio::test]
    async fn global_ctx_reads_hostname_and_flags_directly_from_runtime_config_store() {
        let config = TomlConfigLoader::new_from_str(
            r#"
hostname = "before"
[network_identity]
network_name = "test"
network_secret = "secret"
"#,
        )
        .unwrap();
        let instance = crate::instance::test_instance::TestInstance::new_with_process_runtime(
            config,
            easytier_core::process_runtime::CoreProcessRuntime::new(),
        );
        let global_ctx = instance.get_global_ctx();
        let core = instance.get_core_instance();

        assert_eq!(global_ctx.get_hostname(), "before");
        assert!(!global_ctx.get_flags().disable_relay_data);

        // Store updates via update_runtime_config must be immediately visible to GlobalCtx
        let mut update = (*core.config_store().snapshot()).clone();
        update.update_parsed(|p| {
            p.hostname = "after".to_owned();
            p.flags.disable_relay_data = true;
        });
        core.update_runtime_config(update).await.unwrap();

        assert_eq!(global_ctx.get_hostname(), "after");
        assert!(global_ctx.get_flags().disable_relay_data);
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
