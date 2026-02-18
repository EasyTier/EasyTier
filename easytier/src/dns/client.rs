use std::net::{Ipv4Addr, Ipv6Addr};
use std::sync::Arc;
use std::time::Duration;

use super::config::{DnsConfig, DNS_SERVER_RPC_ADDR};
use crate::common::config::ConfigLoader;
use crate::common::PeerId;
use crate::peers::peer_manager::PeerManager;
use crate::proto::dns::{
    DeterministicDigest, DnsConfigPb, DnsHeartbeat, DnsServerRpcClientFactory, DnsSnapshot,
    ZoneConfigPb,
};
use crate::proto::peer_rpc::{OspfRouteRpcClientFactory, RoutePeerInfo};
use crate::proto::rpc_impl::standalone::StandAloneClient;
use crate::proto::rpc_types::controller::BaseController;
use crate::tunnel::tcp::TcpTunnelConnector;
use dashmap::DashMap;
use derivative::Derivative;
use hickory_proto::rr::Name;
use tokio::sync::Mutex;
use url::Url;

// Stores the digest of peer DNS configs to avoid re-fetching if unchanged.
type PeerDigestMap = Arc<DashMap<PeerId, Vec<u8>>>;
// Stores peer DNS configs.
type PeerConfigMap = Arc<DashMap<PeerId, DnsConfigPb>>;

#[derive(Derivative, Clone)]
#[derivative(Debug)]
pub struct DnsClient {
    peer_mgr: Arc<PeerManager>,

    peer_configs: PeerConfigMap,
    peer_digests: PeerDigestMap,

    #[derivative(Debug = "ignore")]
    // Client to talk to local DnsServer
    server_rpc_client: Arc<Mutex<StandAloneClient<TcpTunnelConnector>>>,
}

impl DnsClient {
    pub fn new(peer_mgr: Arc<PeerManager>) -> Self {
        let connector = TcpTunnelConnector::new(DNS_SERVER_RPC_ADDR.clone());
        let server_rpc_client = Arc::new(Mutex::new(StandAloneClient::new(connector)));

        Self {
            peer_mgr,
            peer_configs: Arc::new(DashMap::new()),
            peer_digests: Arc::new(DashMap::new()),
            server_rpc_client,
        }
    }

    fn config(&self) -> DnsConfig {
        self.peer_mgr.get_global_ctx_ref().config.get_dns()
    }

    pub async fn run(&self) {
        loop {
            if let Err(e) = self.do_heartbeat().await {
                // tracing::error!("DnsClient heartbeat failed: {:?}", e);
            }
            tokio::time::sleep(Duration::from_secs(1)).await;
        }
    }

    async fn do_heartbeat(&self) -> anyhow::Result<()> {
        // scoped_client of StandAloneClient takes &mut self
        let client = {
            let mut client = self.server_rpc_client.lock().await; // Lock the mutex
            client
                .scoped_client::<DnsServerRpcClientFactory<BaseController>>("".to_string())
                .await?
        };

        let snapshot = self.build_snapshot().await;
        let heartbeat = DnsHeartbeat {
            inst_id: Some(self.peer_mgr.get_global_ctx_ref().id.into()),
            checksum: 0, // Compute proper checksum if needed for optimization
            data: Some(snapshot),
        };

        client
            .heartbeat(BaseController::default(), heartbeat)
            .await?;
        Ok(())
    }

    fn create_dedicated_zone(
        origin: &str,
        ipv4: Option<Ipv4Addr>,
        ipv6: Vec<Ipv6Addr>,
    ) -> Option<ZoneConfigPb> {
        let mut records = Vec::new();

        if let Some(ipv4) = ipv4 {
            records.push(format!("@ IN A {}", ipv4));
        }
        for ipv6 in ipv6 {
            records.push(format!("@ IN AAAA {}", ipv6));
        }
        (!records.is_empty()).then_some(ZoneConfigPb {
            origin: origin.to_string(),
            records,

            ..Default::default()
        })
    }

    async fn build_snapshot(&self) -> DnsSnapshot {
        let global_ctx = self.peer_mgr.get_global_ctx_ref();

        let mut zones = Vec::new();

        let config = self.config();

        // 1. Local zones
        zones.extend(config.zones.iter().map(Into::into));

        // 1.5. Specialized zone for self (domain.tld -> self_ip)
        if let Ok(origin) = Name::from(config.get_name()).append_domain(&*config.domain) {
            let ipv4 = global_ctx.get_ipv4().map(|ip| ip.address());
            let ipv6 = global_ctx.get_ipv6().map(|ip| ip.address());
            let ipv6 = ipv6.map(|a| vec![a]).unwrap_or_default();
            if let Some(zone) = Self::create_dedicated_zone(origin.to_string().as_str(), ipv4, ipv6)
            {
                zones.push(zone);
            }
        }

        // 2. Peer zones
        for ref_multi in self.peer_configs.iter() {
            let config = ref_multi.value();
            // TODO: apply import policy here
            zones.extend(config.zones.clone());
        }

        // 3. Specialized zones for peers (domain.tld -> peer_ip)
        let routes = self.peer_mgr.list_routes().await;
        for route in routes.iter() {
            let peer_id = route.peer_id;
            if let Some(peer_config) = self.peer_configs.get(&peer_id) {
                let origin = format!("{}.{}", peer_config.name, peer_config.domain);
                let ipv4 = route
                    .ipv4_addr
                    .map(|ip| ip.address)
                    .flatten()
                    .map(Into::into);
                let ipv6 = route
                    .ipv6_addr
                    .map(|ip| ip.address)
                    .flatten()
                    .map(Into::into);
                let ipv6 = ipv6.map(|a| vec![a]).unwrap_or_default();
                if let Some(zone) = Self::create_dedicated_zone(origin.as_str(), ipv4, ipv6) {
                    zones.push(zone);
                }
            }
        }

        DnsSnapshot {
            zones,
            addresses: self
                .config()
                .addresses
                .clone()
                .into_iter()
                .map(Into::into)
                .collect(),
            listeners: self
                .config()
                .listeners
                .iter()
                .map(Url::from)
                .map(Into::into)
                .collect(),
        }
    }

    pub async fn handle_route_peer_info(&self, peer_info: &RoutePeerInfo) {
        let peer_id = peer_info.peer_id;
        let new_digest = &peer_info.dns;

        if new_digest.is_empty() {
            self.peer_configs.remove(&peer_id);
            self.peer_digests.remove(&peer_id);
            return;
        }
        // Compare dedicated zone

        let old_digest = self.peer_digests.get(&peer_id);
        if let Some(d) = old_digest {
            if d.as_slice() == new_digest.as_slice() {
                return;
            }
        }

        // Need fetch
        // Spawn a task to avoid blocking the caller (which might be the peer manager thread)
        let client_clone = self.clone();
        let peer_id = peer_id;
        let digest_clone = new_digest.clone();
        let new_digest_vec = new_digest.to_vec();

        tokio::spawn(async move {
            match client_clone.fetch_peer_config(peer_id).await {
                Ok(Some(config)) => {
                    let digest = config.digest();
                    // Verify digest matches?
                    if digest == new_digest_vec {
                        client_clone.peer_configs.insert(peer_id, config);
                        client_clone.peer_digests.insert(peer_id, digest);
                        // Trigger heartbeat immediately?
                        if let Err(e) = client_clone.do_heartbeat().await {
                            tracing::warn!(
                                "Failed to push DNS snapshot after peer update: {:?}",
                                e
                            );
                        }
                    } else {
                        tracing::warn!("Fetched DNS config digest mismatch for peer {}", peer_id);
                    }
                }
                Ok(None) => {
                    client_clone.peer_configs.remove(&peer_id);
                    client_clone.peer_digests.remove(&peer_id);
                }
                Err(e) => {
                    tracing::warn!("Failed to fetch DNS config from peer {}: {:?}", peer_id, e);
                }
            }
        });
    }

    async fn fetch_peer_config(&self, peer_id: PeerId) -> anyhow::Result<Option<DnsConfigPb>> {
        let peer_mgr = self.peer_mgr.clone();
        let rpc_mgr = peer_mgr.get_peer_rpc_mgr();

        let client = rpc_mgr.rpc_client();
        let stub = client.scoped_client::<OspfRouteRpcClientFactory<BaseController>>(
            peer_mgr.my_peer_id(),
            peer_id,
            peer_mgr.get_global_ctx_ref().get_network_name(),
        );

        Ok(None)
    }
}
