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
#[cfg(test)]
use easytier_core::stun::{StunProviderSlot, StunSocketMapper};

use super::{
    PeerId,
    config::{ConfigLoader, Flags},
    netns::NetNS,
};
#[cfg(test)]
use crate::socket::udp::RuntimeUdpSocket;
use crate::{
    common::config::ProxyNetworkConfig,
    proto::{
        api::{config::InstanceConfigPatch, instance::PeerConnInfo},
        common::PortForwardConfigPb,
    },
    rpc_service::protected_port,
};
use crossbeam::atomic::AtomicCell;

pub type NetworkIdentity = crate::common::config::NetworkIdentity;

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
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
    cached_proxy_cidrs: AtomicCell<Option<Vec<ProxyNetworkConfig>>>,

    hostname: Mutex<String>,

    #[cfg(test)]
    stun_info_collection: Arc<StunProviderSlot<RuntimeUdpSocket>>,

    tun_device_name: Mutex<Option<String>>,

    flags: ArcSwap<Flags>,
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
            .with_socket_mark(self.config.get_flags().socket_mark)
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

    fn public_ipv6_lease_changed(&self, old: Option<cidr::Ipv6Inet>, new: Option<cidr::Ipv6Inet>) {
        self.issue_event(GlobalCtxEvent::PublicIpv6Changed(old, new));
    }

    fn public_ipv6_routes_changed(&self, added: Vec<cidr::Ipv6Inet>, removed: Vec<cidr::Ipv6Inet>) {
        self.issue_event(GlobalCtxEvent::PublicIpv6RoutesUpdated(added, removed));
    }
}

impl GlobalCtx {
    pub fn new(config_fs: impl ConfigLoader + 'static) -> Self {
        let id = config_fs.get_id();
        let network = config_fs.get_network_identity();
        let net_ns = NetNS::new(config_fs.get_netns());
        let hostname = config_fs.get_hostname();
        let flags = config_fs.get_flags();

        let (event_bus, _) = tokio::sync::broadcast::channel(16);
        #[cfg(test)]
        let stun_info_collection = Arc::new(StunProviderSlot::empty());

        GlobalCtx {
            inst_name: config_fs.get_inst_name(),
            id,
            config: Box::new(config_fs),
            net_ns: net_ns.clone(),
            network,

            event_bus,
            cached_ipv4: AtomicCell::new(None),
            cached_ipv6: AtomicCell::new(None),
            cached_proxy_cidrs: AtomicCell::new(None),

            hostname: Mutex::new(hostname),

            #[cfg(test)]
            stun_info_collection,

            tun_device_name: Mutex::new(None),

            flags: ArcSwap::new(Arc::new(flags)),
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

    fn set_tun_device_name(&self, name: Option<String>) {
        *self.tun_device_name.lock().unwrap() = name;
    }

    pub(crate) fn set_tun_device_ready(&self, name: String) {
        self.set_tun_device_name(Some(name.clone()));
        self.issue_event(GlobalCtxEvent::TunDeviceReady(name));
    }

    pub(crate) fn set_tun_device_error(&self, error: String) {
        self.set_tun_device_name(None);
        self.issue_event(GlobalCtxEvent::TunDeviceError(error));
    }

    pub fn get_tun_device_name(&self) -> Option<String> {
        self.tun_device_name.lock().unwrap().clone()
    }

    pub fn get_ipv4(&self) -> Option<cidr::Ipv4Inet> {
        if let Some(ret) = self.cached_ipv4.load() {
            return Some(ret);
        }
        let addr = self.config.get_ipv4();
        self.cached_ipv4.store(addr);
        addr
    }

    pub fn set_ipv4(&self, addr: Option<cidr::Ipv4Inet>) {
        self.config.set_ipv4(addr);
        self.cached_ipv4.store(None);
    }

    pub fn get_ipv6(&self) -> Option<cidr::Ipv6Inet> {
        if let Some(ret) = self.cached_ipv6.load() {
            return Some(ret);
        }
        let addr = self.config.get_ipv6();
        self.cached_ipv6.store(addr);
        addr
    }

    pub fn set_ipv6(&self, addr: Option<cidr::Ipv6Inet>) {
        self.config.set_ipv6(addr);
        self.cached_ipv6.store(None);
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

    #[cfg(test)]
    pub fn get_stun_info_collector(&self) -> Arc<dyn StunSocketMapper<RuntimeUdpSocket>> {
        self.stun_info_collection.clone()
    }

    #[cfg(test)]
    pub(crate) fn stun_projection(&self) -> Arc<StunProviderSlot<RuntimeUdpSocket>> {
        self.stun_info_collection.clone()
    }

    #[cfg(test)]
    pub fn replace_stun_info_collector(
        &self,
        collector: Box<dyn StunSocketMapper<RuntimeUdpSocket>>,
    ) {
        let arc_collector: Arc<dyn StunSocketMapper<RuntimeUdpSocket>> = Arc::from(collector);
        self.stun_info_collection.replace(arc_collector);
    }

    pub fn get_vpn_portal_cidr(&self) -> Option<cidr::Ipv4Cidr> {
        self.config.get_vpn_portal_config().map(|x| x.client_cidr)
    }

    pub fn get_flags(&self) -> Flags {
        self.flags.load().as_ref().clone()
    }

    pub fn set_flags(&self, flags: Flags) {
        self.config.set_flags(flags.clone());
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

    pub fn is_local_ip(&self, ip: &IpAddr) -> bool {
        let _guard = self.net_ns.guard();
        self.is_ip_local_virtual_ip(ip) || std::net::UdpSocket::bind(format!("{ip}:0")).is_ok()
    }

    pub fn is_protected_tcp_port(&self, port: u16) -> bool {
        protected_port::is_protected_tcp_port(port)
    }
}

#[cfg(test)]
pub mod tests {
    use crate::{
        common::{config::TomlConfigLoader, new_peer_id, stun::MockStunInfoCollector},
        proto::common::NatType,
    };

    use super::*;

    #[tokio::test]
    async fn test_global_ctx() {
        let config = TomlConfigLoader::default();
        let global_ctx = GlobalCtx::new(config);

        let mut subscriber = global_ctx.subscribe();
        let peer_id = new_peer_id();
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
    async fn held_stun_provider_handle_observes_replacement() {
        let global_ctx = GlobalCtx::new(TomlConfigLoader::default());
        let held_provider = global_ctx.get_stun_info_collector();

        global_ctx.replace_stun_info_collector(Box::new(MockStunInfoCollector {
            udp_nat_type: NatType::PortRestricted,
        }));

        assert_eq!(
            held_provider.get_stun_info().udp_nat_type,
            NatType::PortRestricted as i32
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

    pub fn get_mock_global_ctx_with_network(
        network_identy: Option<NetworkIdentity>,
    ) -> ArcGlobalCtx {
        let config_fs = TomlConfigLoader::default();
        config_fs.set_inst_name(format!("test_{}", config_fs.get_id()));
        config_fs.set_network_identity(network_identy.unwrap_or_default());

        let ctx = Arc::new(GlobalCtx::new(config_fs));
        ctx.replace_stun_info_collector(Box::new(MockStunInfoCollector {
            udp_nat_type: NatType::Unknown,
        }));
        ctx
    }

    pub fn get_mock_global_ctx() -> ArcGlobalCtx {
        get_mock_global_ctx_with_network(None)
    }
}
