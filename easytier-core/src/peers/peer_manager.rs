use std::{
    fmt::Debug,
    net::Ipv4Addr,
    sync::{Arc, Weak},
};

use async_trait::async_trait;
use futures::{StreamExt, TryFutureExt};

use tokio::{
    sync::{
        mpsc::{self, UnboundedReceiver, UnboundedSender},
        Mutex, RwLock,
    },
    task::JoinSet,
};
use tokio_stream::wrappers::ReceiverStream;
use tokio_util::bytes::{Bytes, BytesMut};

use crate::{
    common::{
        error::Error, global_ctx::ArcGlobalCtx, rkyv_util::extract_bytes_from_archived_string,
        PeerId,
    },
    peers::{
        packet, peer_conn::PeerConn, peer_rpc::PeerRpcManagerTransport,
        route_trait::RouteInterface, PeerPacketFilter,
    },
    tunnels::{SinkItem, Tunnel, TunnelConnector},
};

use super::{
    foreign_network_client::ForeignNetworkClient,
    foreign_network_manager::ForeignNetworkManager,
    peer_conn::PeerConnId,
    peer_map::PeerMap,
    peer_ospf_route::PeerRoute,
    peer_rip_route::BasicRoute,
    peer_rpc::PeerRpcManager,
    route_trait::{ArcRoute, Route},
    BoxNicPacketFilter, BoxPeerPacketFilter,
};

struct RpcTransport {
    my_peer_id: PeerId,
    peers: Weak<PeerMap>,
    foreign_peers: Mutex<Option<Weak<ForeignNetworkClient>>>,

    packet_recv: Mutex<UnboundedReceiver<Bytes>>,
    peer_rpc_tspt_sender: UnboundedSender<Bytes>,
}

#[async_trait::async_trait]
impl PeerRpcManagerTransport for RpcTransport {
    fn my_peer_id(&self) -> PeerId {
        self.my_peer_id
    }

    async fn send(&self, msg: Bytes, dst_peer_id: PeerId) -> Result<(), Error> {
        let foreign_peers = self
            .foreign_peers
            .lock()
            .await
            .as_ref()
            .ok_or(Error::Unknown)?
            .upgrade()
            .ok_or(Error::Unknown)?;
        let peers = self.peers.upgrade().ok_or(Error::Unknown)?;

        if foreign_peers.has_next_hop(dst_peer_id) {
            return foreign_peers.send_msg(msg, dst_peer_id).await;
        }

        peers.send_msg(msg, dst_peer_id).map_err(|e| e.into()).await
    }

    async fn recv(&self) -> Result<Bytes, Error> {
        if let Some(o) = self.packet_recv.lock().await.recv().await {
            Ok(o)
        } else {
            Err(Error::Unknown)
        }
    }
}

pub enum RouteAlgoType {
    Rip,
    Ospf,
    None,
}

enum RouteAlgoInst {
    Rip(Arc<BasicRoute>),
    Ospf(Arc<PeerRoute>),
    None,
}

pub struct PeerManager {
    my_peer_id: PeerId,

    global_ctx: ArcGlobalCtx,
    nic_channel: mpsc::Sender<SinkItem>,

    tasks: Arc<Mutex<JoinSet<()>>>,

    packet_recv: Arc<Mutex<Option<mpsc::Receiver<Bytes>>>>,

    peers: Arc<PeerMap>,

    peer_rpc_mgr: Arc<PeerRpcManager>,
    peer_rpc_tspt: Arc<RpcTransport>,

    peer_packet_process_pipeline: Arc<RwLock<Vec<BoxPeerPacketFilter>>>,
    nic_packet_process_pipeline: Arc<RwLock<Vec<BoxNicPacketFilter>>>,

    route_algo_inst: RouteAlgoInst,

    foreign_network_manager: Arc<ForeignNetworkManager>,
    foreign_network_client: Arc<ForeignNetworkClient>,
}

impl Debug for PeerManager {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PeerManager")
            .field("my_peer_id", &self.my_peer_id())
            .field("instance_name", &self.global_ctx.inst_name)
            .field("net_ns", &self.global_ctx.net_ns.name())
            .finish()
    }
}

impl PeerManager {
    pub fn new(
        route_algo: RouteAlgoType,
        global_ctx: ArcGlobalCtx,
        nic_channel: mpsc::Sender<SinkItem>,
    ) -> Self {
        let my_peer_id = rand::random();

        let (packet_send, packet_recv) = mpsc::channel(100);
        let peers = Arc::new(PeerMap::new(
            packet_send.clone(),
            global_ctx.clone(),
            my_peer_id,
        ));

        // TODO: remove these because we have impl pipeline processor.
        let (peer_rpc_tspt_sender, peer_rpc_tspt_recv) = mpsc::unbounded_channel();
        let rpc_tspt = Arc::new(RpcTransport {
            my_peer_id,
            peers: Arc::downgrade(&peers),
            foreign_peers: Mutex::new(None),
            packet_recv: Mutex::new(peer_rpc_tspt_recv),
            peer_rpc_tspt_sender,
        });
        let peer_rpc_mgr = Arc::new(PeerRpcManager::new(rpc_tspt.clone()));

        let route_algo_inst = match route_algo {
            RouteAlgoType::Rip => {
                RouteAlgoInst::Rip(Arc::new(BasicRoute::new(my_peer_id, global_ctx.clone())))
            }
            RouteAlgoType::Ospf => RouteAlgoInst::Ospf(PeerRoute::new(
                my_peer_id,
                global_ctx.clone(),
                peer_rpc_mgr.clone(),
            )),
            RouteAlgoType::None => RouteAlgoInst::None,
        };

        let foreign_network_manager = Arc::new(ForeignNetworkManager::new(
            my_peer_id,
            global_ctx.clone(),
            packet_send.clone(),
        ));
        let foreign_network_client = Arc::new(ForeignNetworkClient::new(
            global_ctx.clone(),
            packet_send.clone(),
            peer_rpc_mgr.clone(),
            my_peer_id,
        ));

        PeerManager {
            my_peer_id,

            global_ctx,
            nic_channel,

            tasks: Arc::new(Mutex::new(JoinSet::new())),

            packet_recv: Arc::new(Mutex::new(Some(packet_recv))),

            peers: peers.clone(),

            peer_rpc_mgr,
            peer_rpc_tspt: rpc_tspt,

            peer_packet_process_pipeline: Arc::new(RwLock::new(Vec::new())),
            nic_packet_process_pipeline: Arc::new(RwLock::new(Vec::new())),

            route_algo_inst,

            foreign_network_manager,
            foreign_network_client,
        }
    }

    pub async fn add_client_tunnel(
        &self,
        tunnel: Box<dyn Tunnel>,
    ) -> Result<(PeerId, PeerConnId), Error> {
        let mut peer = PeerConn::new(self.my_peer_id, self.global_ctx.clone(), tunnel);
        peer.do_handshake_as_client().await?;
        let conn_id = peer.get_conn_id();
        let peer_id = peer.get_peer_id();
        if peer.get_network_identity() == self.global_ctx.get_network_identity() {
            self.peers.add_new_peer_conn(peer).await;
        } else {
            self.foreign_network_client.add_new_peer_conn(peer).await;
        }
        Ok((peer_id, conn_id))
    }

    #[tracing::instrument]
    pub async fn try_connect<C>(&self, mut connector: C) -> Result<(PeerId, PeerConnId), Error>
    where
        C: TunnelConnector + Debug,
    {
        let ns = self.global_ctx.net_ns.clone();
        let t = ns
            .run_async(|| async move { connector.connect().await })
            .await?;
        self.add_client_tunnel(t).await
    }

    #[tracing::instrument]
    pub async fn add_tunnel_as_server(&self, tunnel: Box<dyn Tunnel>) -> Result<(), Error> {
        tracing::info!("add tunnel as server start");
        let mut peer = PeerConn::new(self.my_peer_id, self.global_ctx.clone(), tunnel);
        peer.do_handshake_as_server().await?;
        if peer.get_network_identity() == self.global_ctx.get_network_identity() {
            self.peers.add_new_peer_conn(peer).await;
        } else {
            self.foreign_network_manager.add_peer_conn(peer).await?;
        }
        tracing::info!("add tunnel as server done");
        Ok(())
    }

    async fn start_peer_recv(&self) {
        let mut recv = ReceiverStream::new(self.packet_recv.lock().await.take().unwrap());
        let my_peer_id = self.my_peer_id;
        let peers = self.peers.clone();
        let pipe_line = self.peer_packet_process_pipeline.clone();
        self.tasks.lock().await.spawn(async move {
            log::trace!("start_peer_recv");
            while let Some(ret) = recv.next().await {
                log::trace!("peer recv a packet...: {:?}", ret);
                let packet = packet::Packet::decode(&ret);
                let from_peer_id: PeerId = packet.from_peer.into();
                let to_peer_id: PeerId = packet.to_peer.into();
                if to_peer_id != my_peer_id {
                    log::trace!(
                        "need forward: to_peer_id: {:?}, my_peer_id: {:?}",
                        to_peer_id,
                        my_peer_id
                    );
                    let ret = peers.send_msg(ret.clone(), to_peer_id).await;
                    if ret.is_err() {
                        log::error!(
                            "forward packet error: {:?}, dst: {:?}, from: {:?}",
                            ret,
                            to_peer_id,
                            from_peer_id
                        );
                    }
                } else {
                    let mut processed = false;
                    for pipeline in pipe_line.read().await.iter().rev() {
                        if let Some(_) = pipeline.try_process_packet_from_peer(&packet, &ret).await
                        {
                            processed = true;
                            break;
                        }
                    }
                    if !processed {
                        tracing::error!("unexpected packet: {:?}", ret);
                    }
                }
            }
            panic!("done_peer_recv");
        });
    }

    pub async fn add_packet_process_pipeline(&self, pipeline: BoxPeerPacketFilter) {
        // newest pipeline will be executed first
        self.peer_packet_process_pipeline
            .write()
            .await
            .push(pipeline);
    }

    pub async fn add_nic_packet_process_pipeline(&self, pipeline: BoxNicPacketFilter) {
        // newest pipeline will be executed first
        self.nic_packet_process_pipeline
            .write()
            .await
            .push(pipeline);
    }

    async fn init_packet_process_pipeline(&self) {
        // for tun/tap ip/eth packet.
        struct NicPacketProcessor {
            nic_channel: mpsc::Sender<SinkItem>,
        }
        #[async_trait::async_trait]
        impl PeerPacketFilter for NicPacketProcessor {
            async fn try_process_packet_from_peer(
                &self,
                packet: &packet::ArchivedPacket,
                data: &Bytes,
            ) -> Option<()> {
                if packet.packet_type == packet::PacketType::Data {
                    // TODO: use a function to get the body ref directly for zero copy
                    self.nic_channel
                        .send(extract_bytes_from_archived_string(data, &packet.payload))
                        .await
                        .unwrap();
                    Some(())
                } else {
                    None
                }
            }
        }
        self.add_packet_process_pipeline(Box::new(NicPacketProcessor {
            nic_channel: self.nic_channel.clone(),
        }))
        .await;

        // for peer rpc packet
        struct PeerRpcPacketProcessor {
            peer_rpc_tspt_sender: UnboundedSender<Bytes>,
        }

        #[async_trait::async_trait]
        impl PeerPacketFilter for PeerRpcPacketProcessor {
            async fn try_process_packet_from_peer(
                &self,
                packet: &packet::ArchivedPacket,
                data: &Bytes,
            ) -> Option<()> {
                if packet.packet_type == packet::PacketType::TaRpc {
                    self.peer_rpc_tspt_sender.send(data.clone()).unwrap();
                    Some(())
                } else {
                    None
                }
            }
        }
        self.add_packet_process_pipeline(Box::new(PeerRpcPacketProcessor {
            peer_rpc_tspt_sender: self.peer_rpc_tspt.peer_rpc_tspt_sender.clone(),
        }))
        .await;
    }

    pub async fn add_route<T>(&self, route: T)
    where
        T: Route + PeerPacketFilter + Send + Sync + Clone + 'static,
    {
        // for route
        self.add_packet_process_pipeline(Box::new(route.clone()))
            .await;

        struct Interface {
            my_peer_id: PeerId,
            peers: Weak<PeerMap>,
            foreign_network_client: Weak<ForeignNetworkClient>,
        }

        #[async_trait]
        impl RouteInterface for Interface {
            async fn list_peers(&self) -> Vec<PeerId> {
                let Some(foreign_client) = self.foreign_network_client.upgrade() else {
                    return vec![];
                };

                let Some(peer_map) = self.peers.upgrade() else {
                    return vec![];
                };

                let mut peers = foreign_client.list_foreign_peers();
                peers.extend(peer_map.list_peers_with_conn().await);
                peers
            }
            async fn send_route_packet(
                &self,
                msg: Bytes,
                route_id: u8,
                dst_peer_id: PeerId,
            ) -> Result<(), Error> {
                let foreign_client = self
                    .foreign_network_client
                    .upgrade()
                    .ok_or(Error::Unknown)?;
                let peer_map = self.peers.upgrade().ok_or(Error::Unknown)?;

                let packet_bytes: Bytes =
                    packet::Packet::new_route_packet(self.my_peer_id, dst_peer_id, route_id, &msg)
                        .into();
                if foreign_client.has_next_hop(dst_peer_id) {
                    return foreign_client.send_msg(packet_bytes, dst_peer_id).await;
                }

                peer_map.send_msg_directly(packet_bytes, dst_peer_id).await
            }
            fn my_peer_id(&self) -> PeerId {
                self.my_peer_id
            }
        }

        let my_peer_id = self.my_peer_id;
        let _route_id = route
            .open(Box::new(Interface {
                my_peer_id,
                peers: Arc::downgrade(&self.peers),
                foreign_network_client: Arc::downgrade(&self.foreign_network_client),
            }))
            .await
            .unwrap();

        let arc_route: ArcRoute = Arc::new(Box::new(route));
        self.peers.add_route(arc_route).await;
    }

    pub fn get_route(&self) -> Box<dyn Route + Send + Sync + 'static> {
        match &self.route_algo_inst {
            RouteAlgoInst::Rip(route) => Box::new(route.clone()),
            RouteAlgoInst::Ospf(route) => Box::new(route.clone()),
            RouteAlgoInst::None => panic!("no route"),
        }
    }

    pub async fn list_routes(&self) -> Vec<crate::rpc::Route> {
        self.get_route().list_routes().await
    }

    async fn run_nic_packet_process_pipeline(&self, mut data: BytesMut) -> BytesMut {
        for pipeline in self.nic_packet_process_pipeline.read().await.iter().rev() {
            data = pipeline.try_process_packet_from_nic(data).await;
        }
        data
    }

    pub async fn send_msg(&self, msg: Bytes, dst_peer_id: PeerId) -> Result<(), Error> {
        self.peers.send_msg(msg, dst_peer_id).await
    }

    pub async fn send_msg_ipv4(&self, msg: BytesMut, ipv4_addr: Ipv4Addr) -> Result<(), Error> {
        log::trace!(
            "do send_msg in peer manager, msg: {:?}, ipv4_addr: {}",
            msg,
            ipv4_addr
        );

        let mut dst_peers = vec![];
        // NOTE: currently we only support ipv4 and cidr is 24
        if ipv4_addr.is_broadcast() || ipv4_addr.is_multicast() || ipv4_addr.octets()[3] == 255 {
            dst_peers.extend(
                self.peers
                    .list_routes()
                    .await
                    .iter()
                    .map(|x| x.key().clone()),
            );
        } else if let Some(peer_id) = self.peers.get_peer_id_by_ipv4(&ipv4_addr).await {
            dst_peers.push(peer_id);
        }

        if dst_peers.is_empty() {
            tracing::info!("no peer id for ipv4: {}", ipv4_addr);
            return Ok(());
        }

        let msg = self.run_nic_packet_process_pipeline(msg).await;
        let mut errs: Vec<Error> = vec![];

        for peer_id in dst_peers.iter() {
            let send_ret = self
                .peers
                .send_msg(
                    packet::Packet::new_data_packet(self.my_peer_id, peer_id.clone(), &msg).into(),
                    *peer_id,
                )
                .await;

            if let Err(send_ret) = send_ret {
                errs.push(send_ret);
            }
        }

        tracing::trace!(?dst_peers, "do send_msg in peer manager done");

        if errs.is_empty() {
            Ok(())
        } else {
            tracing::error!(?errs, "send_msg has error");
            Err(anyhow::anyhow!("send_msg has error: {:?}", errs).into())
        }
    }

    async fn run_clean_peer_without_conn_routine(&self) {
        let peer_map = self.peers.clone();
        self.tasks.lock().await.spawn(async move {
            loop {
                peer_map.clean_peer_without_conn().await;
                tokio::time::sleep(std::time::Duration::from_secs(3)).await;
            }
        });
    }

    async fn run_foriegn_network(&self) {
        self.peer_rpc_tspt
            .foreign_peers
            .lock()
            .await
            .replace(Arc::downgrade(&self.foreign_network_client));

        self.foreign_network_manager.run().await;
        self.foreign_network_client.run().await;
    }

    pub async fn run(&self) -> Result<(), Error> {
        match &self.route_algo_inst {
            RouteAlgoInst::Ospf(route) => self.add_route(route.clone()).await,
            RouteAlgoInst::Rip(route) => self.add_route(route.clone()).await,
            RouteAlgoInst::None => {}
        };

        self.init_packet_process_pipeline().await;
        self.peer_rpc_mgr.run();

        self.start_peer_recv().await;
        self.run_clean_peer_without_conn_routine().await;

        self.run_foriegn_network().await;

        Ok(())
    }

    pub fn get_peer_map(&self) -> Arc<PeerMap> {
        self.peers.clone()
    }

    pub fn get_peer_rpc_mgr(&self) -> Arc<PeerRpcManager> {
        self.peer_rpc_mgr.clone()
    }

    pub fn my_node_id(&self) -> uuid::Uuid {
        self.global_ctx.get_id()
    }

    pub fn my_peer_id(&self) -> PeerId {
        self.my_peer_id
    }

    pub fn get_global_ctx(&self) -> ArcGlobalCtx {
        self.global_ctx.clone()
    }

    pub fn get_nic_channel(&self) -> mpsc::Sender<SinkItem> {
        self.nic_channel.clone()
    }

    pub fn get_basic_route(&self) -> Arc<BasicRoute> {
        match &self.route_algo_inst {
            RouteAlgoInst::Rip(route) => route.clone(),
            _ => panic!("not rip route"),
        }
    }

    pub fn get_foreign_network_manager(&self) -> Arc<ForeignNetworkManager> {
        self.foreign_network_manager.clone()
    }

    pub fn get_foreign_network_client(&self) -> Arc<ForeignNetworkClient> {
        self.foreign_network_client.clone()
    }
}

#[cfg(test)]
mod tests {

    use crate::{
        connector::udp_hole_punch::tests::create_mock_peer_manager_with_mock_stun,
        peers::tests::{connect_peer_manager, wait_for_condition, wait_route_appear},
        rpc::NatType,
    };

    #[tokio::test]
    async fn drop_peer_manager() {
        let peer_mgr_a = create_mock_peer_manager_with_mock_stun(NatType::Unknown).await;
        let peer_mgr_b = create_mock_peer_manager_with_mock_stun(NatType::Unknown).await;
        let peer_mgr_c = create_mock_peer_manager_with_mock_stun(NatType::Unknown).await;
        connect_peer_manager(peer_mgr_a.clone(), peer_mgr_b.clone()).await;
        connect_peer_manager(peer_mgr_b.clone(), peer_mgr_c.clone()).await;
        connect_peer_manager(peer_mgr_a.clone(), peer_mgr_c.clone()).await;

        wait_route_appear(peer_mgr_a.clone(), peer_mgr_b.clone())
            .await
            .unwrap();
        wait_route_appear(peer_mgr_a.clone(), peer_mgr_c.clone())
            .await
            .unwrap();

        // wait mgr_a have 2 peers
        wait_for_condition(
            || async { peer_mgr_a.get_peer_map().list_peers_with_conn().await.len() == 2 },
            std::time::Duration::from_secs(5),
        )
        .await;

        drop(peer_mgr_b);

        wait_for_condition(
            || async { peer_mgr_a.get_peer_map().list_peers_with_conn().await.len() == 1 },
            std::time::Duration::from_secs(5),
        )
        .await;
    }
}
