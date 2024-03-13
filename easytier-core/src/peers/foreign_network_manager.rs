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
use tokio_util::bytes::Bytes;

use crate::common::{
    error::Error,
    global_ctx::{ArcGlobalCtx, GlobalCtxEvent, NetworkIdentity},
    PeerId,
};

use super::{
    packet::{self},
    peer_conn::PeerConn,
    peer_map::PeerMap,
    peer_rpc::{PeerRpcManager, PeerRpcManagerTransport},
};

struct ForeignNetworkEntry {
    network: NetworkIdentity,
    peer_map: Arc<PeerMap>,
}

impl ForeignNetworkEntry {
    fn new(
        network: NetworkIdentity,
        packet_sender: mpsc::Sender<Bytes>,
        global_ctx: ArcGlobalCtx,
        my_peer_id: PeerId,
    ) -> Self {
        let peer_map = Arc::new(PeerMap::new(packet_sender, global_ctx, my_peer_id));
        Self { network, peer_map }
    }
}

struct ForeignNetworkManagerData {
    network_peer_maps: DashMap<String, Arc<ForeignNetworkEntry>>,
    peer_network_map: DashMap<PeerId, String>,
}

impl ForeignNetworkManagerData {
    async fn send_msg(&self, msg: Bytes, dst_peer_id: PeerId) -> Result<(), Error> {
        let network_name = self
            .peer_network_map
            .get(&dst_peer_id)
            .ok_or_else(|| Error::RouteError("network not found".to_string()))?
            .clone();
        let entry = self
            .network_peer_maps
            .get(&network_name)
            .ok_or_else(|| Error::RouteError("no peer in network".to_string()))?
            .clone();
        entry.peer_map.send_msg(msg, dst_peer_id).await
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

    packet_recv: Mutex<UnboundedReceiver<Bytes>>,
}

#[async_trait::async_trait]
impl PeerRpcManagerTransport for RpcTransport {
    fn my_peer_id(&self) -> PeerId {
        self.my_peer_id
    }

    async fn send(&self, msg: Bytes, dst_peer_id: PeerId) -> Result<(), Error> {
        self.data.send_msg(msg, dst_peer_id).await
    }

    async fn recv(&self) -> Result<Bytes, Error> {
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
    packet_sender_to_mgr: mpsc::Sender<Bytes>,

    packet_sender: mpsc::Sender<Bytes>,
    packet_recv: Mutex<Option<mpsc::Receiver<Bytes>>>,

    data: Arc<ForeignNetworkManagerData>,
    rpc_mgr: Arc<PeerRpcManager>,
    rpc_transport_sender: UnboundedSender<Bytes>,

    tasks: Mutex<JoinSet<()>>,
}

impl ForeignNetworkManager {
    pub fn new(
        my_peer_id: PeerId,
        global_ctx: ArcGlobalCtx,
        packet_sender_to_mgr: mpsc::Sender<Bytes>,
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

    pub async fn add_peer_conn(&self, peer_conn: PeerConn) -> Result<(), Error> {
        tracing::warn!(peer_conn = ?peer_conn.get_conn_info(), network = ?peer_conn.get_network_identity(), "add new peer conn in foreign network manager");

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
                ))
            })
            .clone();

        self.data.peer_network_map.insert(
            peer_conn.get_peer_id(),
            peer_conn.get_network_identity().network_name.clone(),
        );

        if entry.network.network_secret != peer_conn.get_network_identity().network_secret {
            return Err(anyhow::anyhow!("network secret not match").into());
        }

        Ok(entry.peer_map.add_new_peer_conn(peer_conn).await)
    }

    async fn start_global_event_handler(&self) {
        let data = self.data.clone();
        let mut s = self.global_ctx.subscribe();
        self.tasks.lock().await.spawn(async move {
            while let Ok(e) = s.recv().await {
                tracing::warn!(?e, "global event");
                if let GlobalCtxEvent::PeerRemoved(peer_id) = &e {
                    data.remove_peer(*peer_id);
                } else if let GlobalCtxEvent::PeerConnRemoved(..) = &e {
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
                let packet = packet::Packet::decode(&packet_bytes);
                let from_peer_id = packet.from_peer.into();
                let to_peer_id = packet.to_peer.into();
                if to_peer_id == my_node_id {
                    if packet.packet_type == packet::PacketType::TaRpc {
                        rpc_sender.send(packet_bytes.clone()).unwrap();
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
                        let ret = entry.peer_map.send_msg(packet_bytes, to_peer_id).await;
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
}

#[cfg(test)]
mod tests {
    use crate::{
        common::global_ctx::tests::get_mock_global_ctx_with_network,
        connector::udp_hole_punch::tests::{
            create_mock_peer_manager_with_mock_stun, replace_stun_info_collector,
        },
        peers::{
            peer_manager::PeerManager,
            tests::{connect_peer_manager, wait_route_appear},
        },
        rpc::NatType,
    };

    use super::*;

    async fn create_mock_peer_manager_for_foreign_network(network: &str) -> Arc<PeerManager> {
        let (s, _r) = tokio::sync::mpsc::channel(1000);
        let peer_mgr = Arc::new(PeerManager::new(
            get_mock_global_ctx_with_network(Some(NetworkIdentity {
                network_name: network.to_string(),
                network_secret: network.to_string(),
            })),
            s,
        ));
        replace_stun_info_collector(peer_mgr.clone(), NatType::Unknown);
        peer_mgr.run().await.unwrap();
        peer_mgr
    }

    #[tokio::test]
    async fn test_foreign_network_manager() {
        let pm_center = create_mock_peer_manager_with_mock_stun(crate::rpc::NatType::Unknown).await;
        let pm_center2 =
            create_mock_peer_manager_with_mock_stun(crate::rpc::NatType::Unknown).await;
        connect_peer_manager(pm_center.clone(), pm_center2.clone()).await;

        let pma_net1 = create_mock_peer_manager_for_foreign_network("net1").await;
        let pmb_net1 = create_mock_peer_manager_for_foreign_network("net1").await;
        connect_peer_manager(pma_net1.clone(), pm_center.clone()).await;
        connect_peer_manager(pmb_net1.clone(), pm_center.clone()).await;

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
        wait_route_appear(pma_net1.clone(), pmb_net1.my_peer_id())
            .await
            .unwrap();
        assert_eq!(1, pma_net1.list_routes().await.len());
        assert_eq!(1, pmb_net1.list_routes().await.len());

        let pmc_net1 = create_mock_peer_manager_for_foreign_network("net1").await;
        connect_peer_manager(pmc_net1.clone(), pm_center.clone()).await;
        wait_route_appear(pma_net1.clone(), pmc_net1.my_peer_id())
            .await
            .unwrap();
        wait_route_appear(pmb_net1.clone(), pmc_net1.my_peer_id())
            .await
            .unwrap();
        assert_eq!(2, pmc_net1.list_routes().await.len());

        let pma_net2 = create_mock_peer_manager_for_foreign_network("net2").await;
        let pmb_net2 = create_mock_peer_manager_for_foreign_network("net2").await;
        connect_peer_manager(pma_net2.clone(), pm_center.clone()).await;
        connect_peer_manager(pmb_net2.clone(), pm_center.clone()).await;
        wait_route_appear(pma_net2.clone(), pmb_net2.my_peer_id())
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
