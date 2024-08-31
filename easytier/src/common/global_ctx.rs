use std::collections::hash_map::DefaultHasher;
use std::{
    hash::Hasher,
    sync::{Arc, Mutex},
};

use crate::rpc::PeerConnInfo;
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

    DhcpIpv4Changed(Option<std::net::Ipv4Addr>, Option<std::net::Ipv4Addr>), // (old, new)
    DhcpIpv4Conflicted(Option<std::net::Ipv4Addr>),
}

type EventBus = tokio::sync::broadcast::Sender<GlobalCtxEvent>;
type EventBusSubscriber = tokio::sync::broadcast::Receiver<GlobalCtxEvent>;

pub struct GlobalCtx {
    pub inst_name: String,
    pub id: uuid::Uuid,
    pub config: Box<dyn ConfigLoader>,
    pub net_ns: NetNS,
    pub network: NetworkIdentity,

    event_bus: EventBus,

    cached_ipv4: AtomicCell<Option<std::net::Ipv4Addr>>,
    cached_proxy_cidrs: AtomicCell<Option<Vec<cidr::IpCidr>>>,

    ip_collector: Arc<IPCollector>,

    hostname: String,

    stun_info_collection: Box<dyn StunInfoCollectorTrait>,

    running_listeners: Mutex<Vec<url::Url>>,

    enable_exit_node: bool,
    no_tun: bool,
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

        let (event_bus, _) = tokio::sync::broadcast::channel(1024);

        let stun_info_collection = Arc::new(StunInfoCollector::new_with_default_servers());

        let enable_exit_node = config_fs.get_flags().enable_exit_node;
        let no_tun = config_fs.get_flags().no_tun;

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

            hostname,

            stun_info_collection: Box::new(stun_info_collection),

            running_listeners: Mutex::new(Vec::new()),

            enable_exit_node,
            no_tun,
        }
    }

    pub fn subscribe(&self) -> EventBusSubscriber {
        self.event_bus.subscribe()
    }

    pub fn issue_event(&self, event: GlobalCtxEvent) {
        if self.event_bus.receiver_count() != 0 {
            self.event_bus.send(event).unwrap();
        } else {
            tracing::warn!("No subscriber for event: {:?}", event);
        }
    }

    pub fn get_ipv4(&self) -> Option<std::net::Ipv4Addr> {
        if let Some(ret) = self.cached_ipv4.load() {
            return Some(ret);
        }
        let addr = self.config.get_ipv4();
        self.cached_ipv4.store(addr.clone());
        return addr;
    }

    pub fn set_ipv4(&self, addr: Option<std::net::Ipv4Addr>) {
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

    pub fn get_ip_collector(&self) -> Arc<IPCollector> {
        self.ip_collector.clone()
    }

    pub fn get_hostname(&self) -> String {
        return self.hostname.clone();
    }

    pub fn get_stun_info_collector(&self) -> impl StunInfoCollectorTrait + '_ {
        self.stun_info_collection.as_ref()
    }

    #[cfg(test)]
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
        self.running_listeners.lock().unwrap().push(url);
    }

    pub fn get_vpn_portal_cidr(&self) -> Option<cidr::Ipv4Cidr> {
        self.config.get_vpn_portal_config().map(|x| x.client_cidr)
    }

    pub fn get_flags(&self) -> Flags {
        self.config.get_flags()
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

    pub fn no_tun(&self) -> bool {
        self.no_tun
    }
}

#[cfg(test)]
pub mod tests {
    use crate::common::{config::TomlConfigLoader, new_peer_id};

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
        std::sync::Arc::new(GlobalCtx::new(config_fs))
    }

    pub fn get_mock_global_ctx() -> ArcGlobalCtx {
        get_mock_global_ctx_with_network(None)
    }
}
