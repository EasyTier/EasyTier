use std::collections::hash_map::DefaultHasher;
use std::{
    hash::Hasher,
    sync::{Arc, Mutex},
};

use crate::common::config::ProxyNetworkConfig;
use crate::common::stats_manager::StatsManager;
use crate::common::token_bucket::TokenBucketManager;
use crate::peers::acl_filter::AclFilter;
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
    cached_ipv6: AtomicCell<Option<cidr::Ipv6Inet>>,
    cached_proxy_cidrs: AtomicCell<Option<Vec<ProxyNetworkConfig>>>,

    ip_collector: Mutex<Option<Arc<IPCollector>>>,

    hostname: Mutex<String>,

    stun_info_collection: Mutex<Arc<dyn StunInfoCollectorTrait>>,

    running_listeners: Mutex<Vec<url::Url>>,

    enable_exit_node: bool,
    proxy_forward_by_system: bool,
    no_tun: bool,

    feature_flags: AtomicCell<PeerFeatureFlag>,

    quic_proxy_port: AtomicCell<Option<u16>>,

    token_bucket_manager: TokenBucketManager,

    stats_manager: Arc<StatsManager>,

    acl_filter: Arc<AclFilter>,
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
    pub fn new(config_fs: impl ConfigLoader + 'static) -> Self {
        let id = config_fs.get_id();
        let network = config_fs.get_network_identity();
        let net_ns = NetNS::new(config_fs.get_netns());
        let hostname = config_fs.get_hostname();

        let (event_bus, _) = tokio::sync::broadcast::channel(8);

        let stun_servers = config_fs.get_stun_servers();
        let stun_info_collection = Arc::new(if stun_servers.is_empty() {
            StunInfoCollector::new_with_default_servers()
        } else {
            StunInfoCollector::new(stun_servers)
        });

        let enable_exit_node = config_fs.get_flags().enable_exit_node || cfg!(target_env = "ohos");
        let proxy_forward_by_system = config_fs.get_flags().proxy_forward_by_system;
        let no_tun = config_fs.get_flags().no_tun;

        let feature_flags = PeerFeatureFlag {
            kcp_input: !config_fs.get_flags().disable_kcp_input,
            no_relay_kcp: config_fs.get_flags().disable_relay_kcp,
            ..Default::default()
        };

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

            ip_collector: Mutex::new(Some(Arc::new(IPCollector::new(
                net_ns,
                stun_info_collection.clone(),
            )))),

            hostname: Mutex::new(hostname),

            stun_info_collection: Mutex::new(stun_info_collection),

            running_listeners: Mutex::new(Vec::new()),

            enable_exit_node,
            proxy_forward_by_system,
            no_tun,

            feature_flags: AtomicCell::new(feature_flags),
            quic_proxy_port: AtomicCell::new(None),

            token_bucket_manager: TokenBucketManager::new(),

            stats_manager: Arc::new(StatsManager::new()),

            acl_filter: Arc::new(AclFilter::new()),
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
            Err(anyhow::anyhow!("network {} not in whitelist", network_name))
        }
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
        self.ip_collector.lock().unwrap().as_ref().unwrap().clone()
    }

    pub fn get_hostname(&self) -> String {
        return self.hostname.lock().unwrap().clone();
    }

    pub fn set_hostname(&self, hostname: String) {
        *self.hostname.lock().unwrap() = hostname;
    }

    pub fn get_stun_info_collector(&self) -> Arc<dyn StunInfoCollectorTrait> {
        self.stun_info_collection.lock().unwrap().clone()
    }

    pub fn replace_stun_info_collector(&self, collector: Box<dyn StunInfoCollectorTrait>) {
        let arc_collector: Arc<dyn StunInfoCollectorTrait> = Arc::new(collector);
        *self.stun_info_collection.lock().unwrap() = arc_collector.clone();

        // rebuild the ip collector
        *self.ip_collector.lock().unwrap() = Some(Arc::new(IPCollector::new(
            self.net_ns.clone(),
            arc_collector,
        )));
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

    pub fn get_256_key(&self) -> [u8; 32] {
        let mut key = [0u8; 32];
        let secret = self
            .config
            .get_network_identity()
            .network_secret
            .unwrap_or_default();
        // fill key according to network secret
        let mut hasher = DefaultHasher::new();
        hasher.write(secret.as_bytes());
        hasher.write(b"easytier-256bit-key"); // 添加固定盐值以区分128位和256位密钥

        // 生成32字节密钥
        for i in 0..4 {
            let chunk_start = i * 8;
            let chunk_end = chunk_start + 8;
            hasher.write(&key[0..chunk_start]);
            hasher.write(&[i as u8]); // 添加索引以确保每个8字节块都不同
            key[chunk_start..chunk_end].copy_from_slice(&hasher.finish().to_be_bytes());
        }
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

    pub fn get_quic_proxy_port(&self) -> Option<u16> {
        self.quic_proxy_port.load()
    }

    pub fn set_quic_proxy_port(&self, port: Option<u16>) {
        self.quic_proxy_port.store(port);
    }

    pub fn token_bucket_manager(&self) -> &TokenBucketManager {
        &self.token_bucket_manager
    }

    pub fn stats_manager(&self) -> &Arc<StatsManager> {
        &self.stats_manager
    }

    pub fn get_acl_filter(&self) -> &Arc<AclFilter> {
        &self.acl_filter
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
