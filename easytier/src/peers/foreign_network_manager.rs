/*
foreign_network_manager is used to forward packets of other networks.  currently
only forward packets of peers that directly connected to this node.

in future, with the help wo peer center we can forward packets of peers that
connected to any node in the local network.
*/
use std::sync::Arc;

use dashmap::DashMap;
use tokio::{
    sync::{
        mpsc::{self, UnboundedReceiver, UnboundedSender},
        Mutex,
    },
    task::JoinSet,
};

use crate::{
    common::{
        error::Error,
        global_ctx::{ArcGlobalCtx, GlobalCtxEvent, NetworkIdentity},
        PeerId,
    },
    rpc::{ForeignNetworkEntryPb, ListForeignNetworkResponse, PeerInfo},
    tunnel::packet_def::{PacketType, ZCPacket},
};

use super::{
    peer_conn::PeerConn,
    peer_map::PeerMap,
    peer_rpc::{PeerRpcManager, PeerRpcManagerTransport},
    route_trait::NextHopPolicy,
    PacketRecvChan, PacketRecvChanReceiver,
};

struct ForeignNetworkEntry {
    network: NetworkIdentity,
    peer_map: Arc<PeerMap>,
    relay_data: bool,
}

impl ForeignNetworkEntry {
    fn new(
        network: NetworkIdentity,
        packet_sender: PacketRecvChan,
        global_ctx: ArcGlobalCtx,
        my_peer_id: PeerId,
        relay_data: bool,
    ) -> Self {
        let peer_map = Arc::new(PeerMap::new(packet_sender, global_ctx, my_peer_id));
        Self {
            network,
            peer_map,
            relay_data,
        }
    }
}

struct ForeignNetworkManagerData {
    network_peer_maps: DashMap<String, Arc<ForeignNetworkEntry>>,
    peer_network_map: DashMap<PeerId, String>,
}

impl ForeignNetworkManagerData {
    async fn send_msg(&self, msg: ZCPacket, dst_peer_id: PeerId) -> Result<(), Error> {
        let network_name = self
            .peer_network_map
            .get(&dst_peer_id)
            .ok_or_else(|| Error::RouteError(Some("network not found".to_string())))?
            .clone();
        let entry = self
            .network_peer_maps
            .get(&network_name)
            .ok_or_else(|| Error::RouteError(Some("no peer in network".to_string())))?
            .clone();
        entry
            .peer_map
            .send_msg(msg, dst_peer_id, NextHopPolicy::LeastHop)
            .await
    }

    fn get_peer_network(&self, peer_id: PeerId) -> Option<String> {
        self.peer_network_map.get(&peer_id).map(|v| v.clone())
    }

    fn get_network_entry(&self, network_name: &str) -> Option<Arc<ForeignNetworkEntry>> {
        self.network_peer_maps.get(network_name).map(|v| v.clone())
    }

    fn remove_peer(&self, peer_id: PeerId) {
        self.peer_network_map.remove(&peer_id);
        self.network_peer_maps.retain(|_, v| !v.peer_map.is_empty());
    }

    fn clear_no_conn_peer(&self) {
        for item in self.network_peer_maps.iter() {
            let peer_map = item.value().peer_map.clone();
            tokio::spawn(async move {
                peer_map.clean_peer_without_conn().await;
            });
        }
    }
}

struct RpcTransport {
    my_peer_id: PeerId,
    data: Arc<ForeignNetworkManagerData>,

    packet_recv: Mutex<UnboundedReceiver<ZCPacket>>,
}

#[async_trait::async_trait]
impl PeerRpcManagerTransport for RpcTransport {
    fn my_peer_id(&self) -> PeerId {
        self.my_peer_id
    }

    async fn send(&self, msg: ZCPacket, dst_peer_id: PeerId) -> Result<(), Error> {
        self.data.send_msg(msg, dst_peer_id).await
    }

    async fn recv(&self) -> Result<ZCPacket, Error> {
        if let Some(o) = self.packet_recv.lock().await.recv().await {
            Ok(o)
        } else {
            Err(Error::Unknown)
        }
    }
}

pub const FOREIGN_NETWORK_SERVICE_ID: u32 = 1;

#[tarpc::service]
pub trait ForeignNetworkService {
    async fn list_network_peers(network_identy: NetworkIdentity) -> Option<Vec<PeerId>>;
}

#[tarpc::server]
impl ForeignNetworkService for Arc<ForeignNetworkManagerData> {
    async fn list_network_peers(
        self,
        _: tarpc::context::Context,
        network_identy: NetworkIdentity,
    ) -> Option<Vec<PeerId>> {
        let entry = self.network_peer_maps.get(&network_identy.network_name)?;
        Some(entry.peer_map.list_peers().await)
    }
}

pub struct ForeignNetworkManager {
    my_peer_id: PeerId,
    global_ctx: ArcGlobalCtx,
    packet_sender_to_mgr: PacketRecvChan,

    packet_sender: PacketRecvChan,
    packet_recv: Mutex<Option<PacketRecvChanReceiver>>,

    data: Arc<ForeignNetworkManagerData>,
    rpc_mgr: Arc<PeerRpcManager>,
    rpc_transport_sender: UnboundedSender<ZCPacket>,

    tasks: Mutex<JoinSet<()>>,
}

impl ForeignNetworkManager {
    pub fn new(
        my_peer_id: PeerId,
        global_ctx: ArcGlobalCtx,
        packet_sender_to_mgr: PacketRecvChan,
    ) -> Self {
        // recv packet from all foreign networks
        let (packet_sender, packet_recv) = mpsc::channel(1000);

        let data = Arc::new(ForeignNetworkManagerData {
            network_peer_maps: DashMap::new(),
            peer_network_map: DashMap::new(),
        });

        // handle rpc from foreign networks
        let (rpc_transport_sender, peer_rpc_tspt_recv) = mpsc::unbounded_channel();
        let rpc_mgr = Arc::new(PeerRpcManager::new(RpcTransport {
            my_peer_id,
            data: data.clone(),
            packet_recv: Mutex::new(peer_rpc_tspt_recv),
        }));

        Self {
            my_peer_id,
            global_ctx,
            packet_sender_to_mgr,

            packet_sender,
            packet_recv: Mutex::new(Some(packet_recv)),

            data,
            rpc_mgr,
            rpc_transport_sender,

            tasks: Mutex::new(JoinSet::new()),
        }
    }

    fn check_network_in_whitelist(&self, network_name: &str) -> Result<(), Error> {
        if self
            .global_ctx
            .get_flags()
            .foreign_network_whitelist
            .split(" ")
            .map(wildmatch::WildMatch::new)
            .any(|wl| wl.matches(network_name))
        {
            Ok(())
        } else {
            Err(anyhow::anyhow!("network {} not in whitelist", network_name).into())
        }
    }

    pub async fn add_peer_conn(&self, peer_conn: PeerConn) -> Result<(), Error> {
        tracing::info!(peer_conn = ?peer_conn.get_conn_info(), network = ?peer_conn.get_network_identity(), "add new peer conn in foreign network manager");

        let relay_peer_rpc = self.global_ctx.get_flags().relay_all_peer_rpc;
        let ret = self.check_network_in_whitelist(&peer_conn.get_network_identity().network_name);
        if ret.is_err() && !relay_peer_rpc {
            return ret;
        }

        let entry = self
            .data
            .network_peer_maps
            .entry(peer_conn.get_network_identity().network_name.clone())
            .or_insert_with(|| {
                Arc::new(ForeignNetworkEntry::new(
                    peer_conn.get_network_identity(),
                    self.packet_sender.clone(),
                    self.global_ctx.clone(),
                    self.my_peer_id,
                    !ret.is_err(),
                ))
            })
            .clone();

        self.data.peer_network_map.insert(
            peer_conn.get_peer_id(),
            peer_conn.get_network_identity().network_name.clone(),
        );

        if entry.network != peer_conn.get_network_identity() {
            return Err(anyhow::anyhow!(
                "network secret not match. exp: {:?} real: {:?}",
                entry.network,
                peer_conn.get_network_identity()
            )
            .into());
        }

        Ok(entry.peer_map.add_new_peer_conn(peer_conn).await)
    }

    async fn start_global_event_handler(&self) {
        let data = self.data.clone();
        let mut s = self.global_ctx.subscribe();
        self.tasks.lock().await.spawn(async move {
            while let Ok(e) = s.recv().await {
                if let GlobalCtxEvent::PeerRemoved(peer_id) = &e {
                    tracing::info!(?e, "remove peer from foreign network manager");
                    data.remove_peer(*peer_id);
                } else if let GlobalCtxEvent::PeerConnRemoved(..) = &e {
                    tracing::info!(?e, "clear no conn peer from foreign network manager");
                    data.clear_no_conn_peer();
                }
            }
        });
    }

    async fn start_packet_recv(&self) {
        let mut recv = self.packet_recv.lock().await.take().unwrap();
        let sender_to_mgr = self.packet_sender_to_mgr.clone();
        let my_node_id = self.my_peer_id;
        let rpc_sender = self.rpc_transport_sender.clone();
        let data = self.data.clone();

        self.tasks.lock().await.spawn(async move {
            while let Some(packet_bytes) = recv.recv().await {
                let Some(hdr) = packet_bytes.peer_manager_header() else {
                    tracing::warn!("invalid packet, skip");
                    continue;
                };
                let from_peer_id = hdr.from_peer_id.get();
                let to_peer_id = hdr.to_peer_id.get();
                if to_peer_id == my_node_id {
                    if hdr.packet_type == PacketType::TaRpc as u8 {
                        rpc_sender.send(packet_bytes).unwrap();
                        continue;
                    }
                    if let Err(e) = sender_to_mgr.send(packet_bytes).await {
                        tracing::error!("send packet to mgr failed: {:?}", e);
                    }
                } else {
                    let Some(from_network) = data.get_peer_network(from_peer_id) else {
                        continue;
                    };
                    let Some(to_network) = data.get_peer_network(to_peer_id) else {
                        continue;
                    };
                    if from_network != to_network {
                        continue;
                    }

                    if let Some(entry) = data.get_network_entry(&from_network) {
                        if !entry.relay_data && hdr.packet_type == PacketType::Data as u8 {
                            continue;
                        }

                        let ret = entry
                            .peer_map
                            .send_msg(packet_bytes, to_peer_id, NextHopPolicy::LeastHop)
                            .await;
                        if ret.is_err() {
                            tracing::error!("forward packet to peer failed: {:?}", ret.err());
                        }
                    } else {
                        tracing::error!("foreign network not found: {}", from_network);
                    }
                }
            }
        });
    }

    async fn register_peer_rpc_service(&self) {
        self.rpc_mgr.run();
        self.rpc_mgr
            .run_service(FOREIGN_NETWORK_SERVICE_ID, self.data.clone().serve())
    }

    pub async fn run(&self) {
        self.start_global_event_handler().await;
        self.start_packet_recv().await;
        self.register_peer_rpc_service().await;
    }

    pub async fn list_foreign_networks(&self) -> ListForeignNetworkResponse {
        let mut ret = ListForeignNetworkResponse::default();
        let networks = self
            .data
            .network_peer_maps
            .iter()
            .map(|v| v.key().clone())
            .collect::<Vec<_>>();

        for network_name in networks {
            let Some(item) = self
                .data
                .network_peer_maps
                .get(&network_name)
                .map(|v| v.clone())
            else {
                continue;
            };

            let mut entry = ForeignNetworkEntryPb::default();
            for peer in item.peer_map.list_peers().await {
                let mut peer_info = PeerInfo::default();
                peer_info.peer_id = peer;
                peer_info.conns = item.peer_map.list_peer_conns(peer).await.unwrap_or(vec![]);
                entry.peers.push(peer_info);
            }

            ret.foreign_networks.insert(network_name, entry);
        }
        ret
    }
}

#[cfg(test)]
mod tests {
    use crate::{
        common::global_ctx::tests::get_mock_global_ctx_with_network,
        connector::udp_hole_punch::tests::{
            create_mock_peer_manager_with_mock_stun, replace_stun_info_collector,
        },
        peers::{
            peer_manager::{PeerManager, RouteAlgoType},
            tests::{connect_peer_manager, wait_route_appear},
        },
        rpc::NatType,
    };

    use super::*;

    async fn create_mock_peer_manager_for_foreign_network(network: &str) -> Arc<PeerManager> {
        let (s, _r) = tokio::sync::mpsc::channel(1000);
        let peer_mgr = Arc::new(PeerManager::new(
            RouteAlgoType::Ospf,
            get_mock_global_ctx_with_network(Some(NetworkIdentity::new(
                network.to_string(),
                network.to_string(),
            ))),
            s,
        ));
        replace_stun_info_collector(peer_mgr.clone(), NatType::Unknown);
        peer_mgr.run().await.unwrap();
        peer_mgr
    }

    #[tokio::test]
    async fn foreign_network_basic() {
        let pm_center = create_mock_peer_manager_with_mock_stun(crate::rpc::NatType::Unknown).await;
        tracing::debug!("pm_center: {:?}", pm_center.my_peer_id());

        let pma_net1 = create_mock_peer_manager_for_foreign_network("net1").await;
        let pmb_net1 = create_mock_peer_manager_for_foreign_network("net1").await;
        tracing::debug!(
            "pma_net1: {:?}, pmb_net1: {:?}",
            pma_net1.my_peer_id(),
            pmb_net1.my_peer_id()
        );
        connect_peer_manager(pma_net1.clone(), pm_center.clone()).await;
        connect_peer_manager(pmb_net1.clone(), pm_center.clone()).await;
        wait_route_appear(pma_net1.clone(), pmb_net1.clone())
            .await
            .unwrap();
        assert_eq!(1, pma_net1.list_routes().await.len());
        assert_eq!(1, pmb_net1.list_routes().await.len());

        let rpc_resp = pm_center
            .get_foreign_network_manager()
            .list_foreign_networks()
            .await;
        assert_eq!(1, rpc_resp.foreign_networks.len());
        assert_eq!(2, rpc_resp.foreign_networks["net1"].peers.len());
    }

    async fn foreign_network_whitelist_helper(name: String) {
        let pm_center = create_mock_peer_manager_with_mock_stun(crate::rpc::NatType::Unknown).await;
        tracing::debug!("pm_center: {:?}", pm_center.my_peer_id());
        let mut flag = pm_center.get_global_ctx().get_flags();
        flag.foreign_network_whitelist = vec!["net1".to_string(), "net2*".to_string()].join(" ");
        pm_center.get_global_ctx().config.set_flags(flag);

        let pma_net1 = create_mock_peer_manager_for_foreign_network(name.as_str()).await;

        let (a_ring, b_ring) = crate::tunnel::ring::create_ring_tunnel_pair();
        let b_mgr_copy = pm_center.clone();
        let s_ret = tokio::spawn(async move { b_mgr_copy.add_tunnel_as_server(b_ring).await });

        pma_net1.add_client_tunnel(a_ring).await.unwrap();

        s_ret.await.unwrap().unwrap();
    }

    #[tokio::test]
    async fn foreign_network_whitelist() {
        foreign_network_whitelist_helper("net1".to_string()).await;
        foreign_network_whitelist_helper("net2".to_string()).await;
        foreign_network_whitelist_helper("net2abc".to_string()).await;
    }

    #[tokio::test]
    async fn only_relay_peer_rpc() {
        let pm_center = create_mock_peer_manager_with_mock_stun(crate::rpc::NatType::Unknown).await;
        let mut flag = pm_center.get_global_ctx().get_flags();
        flag.foreign_network_whitelist = "".to_string();
        flag.relay_all_peer_rpc = true;
        pm_center.get_global_ctx().config.set_flags(flag);
        tracing::debug!("pm_center: {:?}", pm_center.my_peer_id());

        let pma_net1 = create_mock_peer_manager_for_foreign_network("net1").await;
        let pmb_net1 = create_mock_peer_manager_for_foreign_network("net1").await;
        tracing::debug!(
            "pma_net1: {:?}, pmb_net1: {:?}",
            pma_net1.my_peer_id(),
            pmb_net1.my_peer_id()
        );
        connect_peer_manager(pma_net1.clone(), pm_center.clone()).await;
        connect_peer_manager(pmb_net1.clone(), pm_center.clone()).await;
        wait_route_appear(pma_net1.clone(), pmb_net1.clone())
            .await
            .unwrap();
        assert_eq!(1, pma_net1.list_routes().await.len());
        assert_eq!(1, pmb_net1.list_routes().await.len());
    }

    #[tokio::test]
    #[should_panic]
    async fn foreign_network_whitelist_fail() {
        foreign_network_whitelist_helper("net3".to_string()).await;
    }

    #[tokio::test]
    async fn test_foreign_network_manager() {
        let pm_center = create_mock_peer_manager_with_mock_stun(crate::rpc::NatType::Unknown).await;
        let pm_center2 =
            create_mock_peer_manager_with_mock_stun(crate::rpc::NatType::Unknown).await;
        connect_peer_manager(pm_center.clone(), pm_center2.clone()).await;

        tracing::debug!(
            "pm_center: {:?}, pm_center2: {:?}",
            pm_center.my_peer_id(),
            pm_center2.my_peer_id()
        );

        let pma_net1 = create_mock_peer_manager_for_foreign_network("net1").await;
        let pmb_net1 = create_mock_peer_manager_for_foreign_network("net1").await;
        connect_peer_manager(pma_net1.clone(), pm_center.clone()).await;
        connect_peer_manager(pmb_net1.clone(), pm_center.clone()).await;

        tracing::debug!(
            "pma_net1: {:?}, pmb_net1: {:?}",
            pma_net1.my_peer_id(),
            pmb_net1.my_peer_id()
        );

        let now = std::time::Instant::now();
        let mut succ = false;
        while now.elapsed().as_secs() < 10 {
            let table = pma_net1.get_foreign_network_client().get_next_hop_table();
            if table.len() >= 1 {
                succ = true;
                break;
            }
            tokio::time::sleep(std::time::Duration::from_secs(1)).await;
        }
        assert!(succ);

        assert_eq!(
            vec![pm_center.my_peer_id()],
            pma_net1
                .get_foreign_network_client()
                .get_peer_map()
                .list_peers()
                .await
        );
        assert_eq!(
            vec![pm_center.my_peer_id()],
            pmb_net1
                .get_foreign_network_client()
                .get_peer_map()
                .list_peers()
                .await
        );
        wait_route_appear(pma_net1.clone(), pmb_net1.clone())
            .await
            .unwrap();
        assert_eq!(1, pma_net1.list_routes().await.len());
        assert_eq!(1, pmb_net1.list_routes().await.len());

        let pmc_net1 = create_mock_peer_manager_for_foreign_network("net1").await;
        connect_peer_manager(pmc_net1.clone(), pm_center.clone()).await;
        wait_route_appear(pma_net1.clone(), pmc_net1.clone())
            .await
            .unwrap();
        wait_route_appear(pmb_net1.clone(), pmc_net1.clone())
            .await
            .unwrap();
        assert_eq!(2, pmc_net1.list_routes().await.len());

        tracing::debug!("pmc_net1: {:?}", pmc_net1.my_peer_id());

        let pma_net2 = create_mock_peer_manager_for_foreign_network("net2").await;
        let pmb_net2 = create_mock_peer_manager_for_foreign_network("net2").await;
        tracing::debug!(
            "pma_net2: {:?}, pmb_net2: {:?}",
            pma_net2.my_peer_id(),
            pmb_net2.my_peer_id()
        );
        connect_peer_manager(pma_net2.clone(), pm_center.clone()).await;
        connect_peer_manager(pmb_net2.clone(), pm_center.clone()).await;
        wait_route_appear(pma_net2.clone(), pmb_net2.clone())
            .await
            .unwrap();
        assert_eq!(1, pma_net2.list_routes().await.len());
        assert_eq!(1, pmb_net2.list_routes().await.len());

        assert_eq!(
            5,
            pm_center
                .get_foreign_network_manager()
                .data
                .peer_network_map
                .len()
        );

        assert_eq!(
            2,
            pm_center
                .get_foreign_network_manager()
                .data
                .network_peer_maps
                .len()
        );

        let rpc_resp = pm_center
            .get_foreign_network_manager()
            .list_foreign_networks()
            .await;
        assert_eq!(2, rpc_resp.foreign_networks.len());
        assert_eq!(3, rpc_resp.foreign_networks["net1"].peers.len());
        assert_eq!(2, rpc_resp.foreign_networks["net2"].peers.len());

        drop(pmb_net2);
        tokio::time::sleep(std::time::Duration::from_secs(1)).await;
        assert_eq!(
            4,
            pm_center
                .get_foreign_network_manager()
                .data
                .peer_network_map
                .len()
        );
        drop(pma_net2);
        tokio::time::sleep(std::time::Duration::from_secs(1)).await;
        assert_eq!(
            3,
            pm_center
                .get_foreign_network_manager()
                .data
                .peer_network_map
                .len()
        );
        assert_eq!(
            1,
            pm_center
                .get_foreign_network_manager()
                .data
                .network_peer_maps
                .len()
        );
    }
}
