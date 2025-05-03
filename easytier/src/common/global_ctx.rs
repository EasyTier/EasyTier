use std::collections::hash_map::DefaultHasher;
use std::{
    hash::Hasher,
    sync::{Arc, Mutex},
};

use crate::proto::cli::PeerConnInfo;
use crate::proto::common::{PeerFeatureFlag, PortForwardConfigPb};
use crossbeam::atomic::AtomicCell;

use super::{
    config::{ConfigLoader, Flags},
    netns::NetNS,
    network::IPCollector,
    stun::{StunInfoCollector, StunInfoCollectorTrait},
    PeerId,
};

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

    Connecting(url::Url),
    ConnectError(String, String, String), // (dst, ip version, error message)

    VpnPortalClientConnected(String, String), // (portal, client ip)
    VpnPortalClientDisconnected(String, String), // (portal, client ip)

    DhcpIpv4Changed(Option<cidr::Ipv4Inet>, Option<cidr::Ipv4Inet>), // (old, new)
    DhcpIpv4Conflicted(Option<cidr::Ipv4Inet>),

    PortForwardAdded(PortForwardConfigPb),
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
    cached_proxy_cidrs: AtomicCell<Option<Vec<cidr::IpCidr>>>,

    ip_collector: Arc<IPCollector>,

    hostname: Mutex<String>,

    stun_info_collection: Box<dyn StunInfoCollectorTrait>,

    running_listeners: Mutex<Vec<url::Url>>,

    enable_exit_node: bool,
    proxy_forward_by_system: bool,
    no_tun: bool,

    feature_flags: AtomicCell<PeerFeatureFlag>,
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

impl GlobalCtx {
    pub fn new(config_fs: impl ConfigLoader + 'static + Send + Sync) -> Self {
        let id = config_fs.get_id();
        let network = config_fs.get_network_identity();
        let net_ns = NetNS::new(config_fs.get_netns());
        let hostname = config_fs.get_hostname();

        let (event_bus, _) = tokio::sync::broadcast::channel(8);

        let stun_info_collection = Arc::new(StunInfoCollector::new_with_default_servers());

        let enable_exit_node = config_fs.get_flags().enable_exit_node;
        let proxy_forward_by_system = config_fs.get_flags().proxy_forward_by_system;
        let no_tun = config_fs.get_flags().no_tun;

        let mut feature_flags = PeerFeatureFlag::default();
        feature_flags.kcp_input = !config_fs.get_flags().disable_kcp_input;
        feature_flags.no_relay_kcp = config_fs.get_flags().disable_relay_kcp;

        GlobalCtx {
            inst_name: config_fs.get_inst_name(),
            id,
            config: Box::new(config_fs),
            net_ns: net_ns.clone(),
            network,

            event_bus,
            cached_ipv4: AtomicCell::new(None),
            cached_proxy_cidrs: AtomicCell::new(None),

            ip_collector: Arc::new(IPCollector::new(net_ns, stun_info_collection.clone())),

            hostname: Mutex::new(hostname),

            stun_info_collection: Box::new(stun_info_collection),

            running_listeners: Mutex::new(Vec::new()),

            enable_exit_node,
            proxy_forward_by_system,
            no_tun,

            feature_flags: AtomicCell::new(feature_flags),
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

    pub fn check_network_in_whitelist(&self, network_name: &str) -> Result<(), anyhow::Error> {
        if self
            .get_flags()
            .relay_network_whitelist
            .split(" ")
            .map(wildmatch::WildMatch::new)
            .any(|wl| wl.matches(network_name))
        {
            Ok(())
        } else {
            Err(anyhow::anyhow!("network {} not in whitelist", network_name).into())
        }
    }

    pub fn get_ipv4(&self) -> Option<cidr::Ipv4Inet> {
        if let Some(ret) = self.cached_ipv4.load() {
            return Some(ret);
        }
        let addr = self.config.get_ipv4();
        self.cached_ipv4.store(addr.clone());
        return addr;
    }

    pub fn set_ipv4(&self, addr: Option<cidr::Ipv4Inet>) {
        self.config.set_ipv4(addr);
        self.cached_ipv4.store(None);
    }

    pub fn add_proxy_cidr(&self, cidr: cidr::IpCidr) -> Result<(), std::io::Error> {
        self.config.add_proxy_cidr(cidr);
        self.cached_proxy_cidrs.store(None);
        Ok(())
    }

    pub fn remove_proxy_cidr(&self, cidr: cidr::IpCidr) -> Result<(), std::io::Error> {
        self.config.remove_proxy_cidr(cidr);
        self.cached_proxy_cidrs.store(None);
        Ok(())
    }

    pub fn get_proxy_cidrs(&self) -> Vec<cidr::IpCidr> {
        if let Some(proxy_cidrs) = self.cached_proxy_cidrs.take() {
            self.cached_proxy_cidrs.store(Some(proxy_cidrs.clone()));
            return proxy_cidrs;
        }

        let ret = self.config.get_proxy_cidrs();
        self.cached_proxy_cidrs.store(Some(ret.clone()));
        ret
    }

    pub fn get_id(&self) -> uuid::Uuid {
        self.config.get_id()
    }

    pub fn get_network_identity(&self) -> NetworkIdentity {
        self.config.get_network_identity()
    }

    pub fn get_network_name(&self) -> String {
        self.get_network_identity().network_name
    }

    pub fn get_ip_collector(&self) -> Arc<IPCollector> {
        self.ip_collector.clone()
    }

    pub fn get_hostname(&self) -> String {
        return self.hostname.lock().unwrap().clone();
    }

    pub fn set_hostname(&self, hostname: String) {
        *self.hostname.lock().unwrap() = hostname;
    }

    pub fn get_stun_info_collector(&self) -> impl StunInfoCollectorTrait + '_ {
        self.stun_info_collection.as_ref()
    }

    pub fn replace_stun_info_collector(&self, collector: Box<dyn StunInfoCollectorTrait>) {
        // force replace the stun_info_collection without mut and drop the old one
        let ptr = &self.stun_info_collection as *const Box<dyn StunInfoCollectorTrait>;
        let ptr = ptr as *mut Box<dyn StunInfoCollectorTrait>;
        unsafe {
            std::ptr::drop_in_place(ptr);
            #[allow(invalid_reference_casting)]
            std::ptr::write(ptr, collector);
        }
    }

    pub fn get_running_listeners(&self) -> Vec<url::Url> {
        self.running_listeners.lock().unwrap().clone()
    }

    pub fn add_running_listener(&self, url: url::Url) {
        let mut l = self.running_listeners.lock().unwrap();
        if !l.contains(&url) {
            l.push(url);
        }
    }

    pub fn get_vpn_portal_cidr(&self) -> Option<cidr::Ipv4Cidr> {
        self.config.get_vpn_portal_config().map(|x| x.client_cidr)
    }

    pub fn get_flags(&self) -> Flags {
        self.config.get_flags()
    }

    pub fn set_flags(&self, flags: Flags) {
        self.config.set_flags(flags);
    }

    pub fn get_128_key(&self) -> [u8; 16] {
        let mut key = [0u8; 16];
        let secret = self
            .config
            .get_network_identity()
            .network_secret
            .unwrap_or_default();
        // fill key according to network secret
        let mut hasher = DefaultHasher::new();
        hasher.write(secret.as_bytes());
        key[0..8].copy_from_slice(&hasher.finish().to_be_bytes());
        hasher.write(&key[0..8]);
        key[8..16].copy_from_slice(&hasher.finish().to_be_bytes());
        hasher.write(&key[0..16]);
        key
    }

    pub fn enable_exit_node(&self) -> bool {
        self.enable_exit_node
    }

    pub fn proxy_forward_by_system(&self) -> bool {
        self.proxy_forward_by_system
    }

    pub fn no_tun(&self) -> bool {
        self.no_tun
    }

    pub fn get_feature_flags(&self) -> PeerFeatureFlag {
        self.feature_flags.load()
    }

    pub fn set_feature_flags(&self, flags: PeerFeatureFlag) {
        self.feature_flags.store(flags);
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
        global_ctx.issue_event(GlobalCtxEvent::PeerAdded(peer_id.clone()));
        global_ctx.issue_event(GlobalCtxEvent::PeerRemoved(peer_id.clone()));
        global_ctx.issue_event(GlobalCtxEvent::PeerConnAdded(PeerConnInfo::default()));
        global_ctx.issue_event(GlobalCtxEvent::PeerConnRemoved(PeerConnInfo::default()));

        assert_eq!(
            subscriber.recv().await.unwrap(),
            GlobalCtxEvent::PeerAdded(peer_id.clone())
        );
        assert_eq!(
            subscriber.recv().await.unwrap(),
            GlobalCtxEvent::PeerRemoved(peer_id.clone())
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

    pub fn get_mock_global_ctx_with_network(
        network_identy: Option<NetworkIdentity>,
    ) -> ArcGlobalCtx {
        let config_fs = TomlConfigLoader::default();
        config_fs.set_inst_name(format!("test_{}", config_fs.get_id()));
        config_fs.set_network_identity(network_identy.unwrap_or(NetworkIdentity::default()));

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
