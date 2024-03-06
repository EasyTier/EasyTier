use std::{io::Write, sync::Arc};

use crate::rpc::PeerConnInfo;
use crossbeam::atomic::AtomicCell;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use super::{
    config_fs::ConfigFs,
    netns::NetNS,
    network::IPCollector,
    stun::{StunInfoCollector, StunInfoCollectorTrait},
};

#[derive(Debug, Clone, PartialEq)]
pub enum GlobalCtxEvent {
    PeerAdded(Uuid),
    PeerRemoved(Uuid),
    PeerConnAdded(PeerConnInfo),
    PeerConnRemoved(PeerConnInfo),
}

type EventBus = tokio::sync::broadcast::Sender<GlobalCtxEvent>;
type EventBusSubscriber = tokio::sync::broadcast::Receiver<GlobalCtxEvent>;

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq)]
pub struct NetworkIdentity {
    pub network_name: String,
    pub network_secret: String,
}

impl NetworkIdentity {
    pub fn new(network_name: String, network_secret: String) -> Self {
        NetworkIdentity {
            network_name,
            network_secret,
        }
    }

    pub fn default() -> Self {
        Self::new("default".to_string(), "".to_string())
    }
}

pub struct GlobalCtx {
    pub inst_name: String,
    pub id: uuid::Uuid,
    pub config_fs: ConfigFs,
    pub net_ns: NetNS,
    pub network: NetworkIdentity,

    event_bus: EventBus,

    cached_ipv4: AtomicCell<Option<std::net::Ipv4Addr>>,
    cached_proxy_cidrs: AtomicCell<Option<Vec<cidr::IpCidr>>>,

    ip_collector: Arc<IPCollector>,

    hotname: AtomicCell<Option<String>>,

    stun_info_collection: Box<dyn StunInfoCollectorTrait>,
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
    pub fn new(
        inst_name: &str,
        config_fs: ConfigFs,
        net_ns: NetNS,
        network: Option<NetworkIdentity>,
    ) -> Self {
        let id = config_fs
            .get_or_add_file("inst_id", || uuid::Uuid::new_v4().to_string())
            .unwrap();
        let id = uuid::Uuid::parse_str(&id).unwrap();
        let network = network.unwrap_or(NetworkIdentity::default());

        let (event_bus, _) = tokio::sync::broadcast::channel(100);

        GlobalCtx {
            inst_name: inst_name.to_string(),
            id,
            config_fs,
            net_ns: net_ns.clone(),
            network,

            event_bus,
            cached_ipv4: AtomicCell::new(None),
            cached_proxy_cidrs: AtomicCell::new(None),

            ip_collector: Arc::new(IPCollector::new(net_ns)),

            hotname: AtomicCell::new(None),

            stun_info_collection: Box::new(StunInfoCollector::new_with_default_servers()),
        }
    }

    pub fn subscribe(&self) -> EventBusSubscriber {
        self.event_bus.subscribe()
    }

    pub fn issue_event(&self, event: GlobalCtxEvent) {
        if self.event_bus.receiver_count() != 0 {
            self.event_bus.send(event).unwrap();
        } else {
            log::warn!("No subscriber for event: {:?}", event);
        }
    }

    pub fn get_ipv4(&self) -> Option<std::net::Ipv4Addr> {
        if let Some(ret) = self.cached_ipv4.load() {
            return Some(ret);
        }

        let Ok(addr) = self.config_fs.get("ipv4") else {
            return None;
        };

        let Ok(addr) = addr.parse() else {
            tracing::error!("invalid ipv4 addr: {}", addr);
            return None;
        };

        self.cached_ipv4.store(Some(addr));
        return Some(addr);
    }

    pub fn set_ipv4(&mut self, addr: std::net::Ipv4Addr) {
        self.config_fs
            .add_file("ipv4")
            .unwrap()
            .write_all(addr.to_string().as_bytes())
            .unwrap();

        self.cached_ipv4.store(None);
    }

    pub fn add_proxy_cidr(&self, cidr: cidr::IpCidr) -> Result<(), std::io::Error> {
        let escaped_cidr = cidr.to_string().replace("/", "_");
        self.config_fs
            .add_file(&format!("proxy_cidrs/{}", escaped_cidr))?;
        self.cached_proxy_cidrs.store(None);
        Ok(())
    }

    pub fn remove_proxy_cidr(&self, cidr: cidr::IpCidr) -> Result<(), std::io::Error> {
        let escaped_cidr = cidr.to_string().replace("/", "_");
        self.config_fs
            .remove(&format!("proxy_cidrs/{}", escaped_cidr))?;
        self.cached_proxy_cidrs.store(None);
        Ok(())
    }

    pub fn get_proxy_cidrs(&self) -> Vec<cidr::IpCidr> {
        if let Some(proxy_cidrs) = self.cached_proxy_cidrs.take() {
            self.cached_proxy_cidrs.store(Some(proxy_cidrs.clone()));
            return proxy_cidrs;
        }

        let Ok(keys) = self.config_fs.list_keys("proxy_cidrs") else {
            return vec![];
        };

        let mut ret = Vec::new();
        for key in keys.iter() {
            let key = key.replace("_", "/");
            let Ok(cidr) = key.parse() else {
                tracing::error!("invalid proxy cidr: {}", key);
                continue;
            };
            ret.push(cidr);
        }

        self.cached_proxy_cidrs.store(Some(ret.clone()));
        ret
    }

    pub fn get_ip_collector(&self) -> Arc<IPCollector> {
        self.ip_collector.clone()
    }

    pub fn get_hostname(&self) -> Option<String> {
        if let Some(hostname) = self.hotname.take() {
            self.hotname.store(Some(hostname.clone()));
            return Some(hostname);
        }

        let hostname = gethostname::gethostname().to_string_lossy().to_string();
        self.hotname.store(Some(hostname.clone()));
        return Some(hostname);
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

    pub fn get_id(&self) -> uuid::Uuid {
        self.id
    }

    pub fn get_network_identity(&self) -> NetworkIdentity {
        self.network.clone()
    }
}

#[cfg(test)]
pub mod tests {
    use super::*;

    #[tokio::test]
    async fn test_global_ctx() {
        let config_fs = ConfigFs::new("/tmp/easytier");
        let net_ns = NetNS::new(None);
        let global_ctx = GlobalCtx::new("test", config_fs, net_ns, None);

        let mut subscriber = global_ctx.subscribe();
        let uuid = Uuid::new_v4();
        global_ctx.issue_event(GlobalCtxEvent::PeerAdded(uuid.clone()));
        global_ctx.issue_event(GlobalCtxEvent::PeerRemoved(uuid.clone()));
        global_ctx.issue_event(GlobalCtxEvent::PeerConnAdded(PeerConnInfo::default()));
        global_ctx.issue_event(GlobalCtxEvent::PeerConnRemoved(PeerConnInfo::default()));

        assert_eq!(
            subscriber.recv().await.unwrap(),
            GlobalCtxEvent::PeerAdded(uuid.clone())
        );
        assert_eq!(
            subscriber.recv().await.unwrap(),
            GlobalCtxEvent::PeerRemoved(uuid.clone())
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
        let node_id = uuid::Uuid::new_v4();
        let config_fs = ConfigFs::new_with_dir(node_id.to_string().as_str(), "/tmp/easytier");
        let net_ns = NetNS::new(None);
        std::sync::Arc::new(GlobalCtx::new(
            format!("test_{}", node_id).as_str(),
            config_fs,
            net_ns,
            network_identy,
        ))
    }

    pub fn get_mock_global_ctx() -> ArcGlobalCtx {
        get_mock_global_ctx_with_network(None)
    }
}
