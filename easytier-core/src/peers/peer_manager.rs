use std::{fmt::Debug, net::Ipv4Addr, sync::Arc};

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
        error::Error, global_ctx::ArcGlobalCtx, rkyv_util::extract_bytes_from_archived_vec, PeerId,
    },
    peers::{
        packet, peer_conn::PeerConn, peer_rpc::PeerRpcManagerTransport, route_trait::RouteInterface,
    },
    tunnels::{SinkItem, Tunnel, TunnelConnector},
};

use super::{
    foreign_network_client::ForeignNetworkClient,
    foreign_network_manager::ForeignNetworkManager,
    peer_conn::PeerConnId,
    peer_map::PeerMap,
    peer_rip_route::BasicRoute,
    peer_rpc::PeerRpcManager,
    route_trait::{ArcRoute, Route},
};

struct RpcTransport {
    my_peer_id: PeerId,
    peers: Arc<PeerMap>,
    foreign_peers: Mutex<Option<Arc<PeerMap>>>,

    packet_recv: Mutex<UnboundedReceiver<Bytes>>,
    peer_rpc_tspt_sender: UnboundedSender<Bytes>,
}

#[async_trait::async_trait]
impl PeerRpcManagerTransport for RpcTransport {
    fn my_peer_id(&self) -> PeerId {
        self.my_peer_id
    }

    async fn send(&self, msg: Bytes, dst_peer_id: PeerId) -> Result<(), Error> {
        if let Some(foreign_peers) = self.foreign_peers.lock().await.as_ref() {
            if foreign_peers.has_peer(dst_peer_id) {
                return foreign_peers.send_msg(msg, dst_peer_id).await;
            }
        }
        self.peers
            .send_msg(msg, dst_peer_id)
            .map_err(|e| e.into())
            .await
    }

    async fn recv(&self) -> Result<Bytes, Error> {
        if let Some(o) = self.packet_recv.lock().await.recv().await {
            Ok(o)
        } else {
            Err(Error::Unknown)
        }
    }
}

#[async_trait::async_trait]
#[auto_impl::auto_impl(Arc)]
pub trait PeerPacketFilter {
    async fn try_process_packet_from_peer(
        &self,
        packet: &packet::ArchivedPacket,
        data: &Bytes,
    ) -> Option<()>;
}

#[async_trait::async_trait]
#[auto_impl::auto_impl(Arc)]
pub trait NicPacketFilter {
    async fn try_process_packet_from_nic(&self, data: BytesMut) -> BytesMut;
}

type BoxPeerPacketFilter = Box<dyn PeerPacketFilter + Send + Sync>;
type BoxNicPacketFilter = Box<dyn NicPacketFilter + Send + Sync>;

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

    basic_route: Arc<BasicRoute>,

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
    pub fn new(global_ctx: ArcGlobalCtx, nic_channel: mpsc::Sender<SinkItem>) -> Self {
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
            peers: peers.clone(),
            foreign_peers: Mutex::new(None),
            packet_recv: Mutex::new(peer_rpc_tspt_recv),
            peer_rpc_tspt_sender,
        });
        let peer_rpc_mgr = Arc::new(PeerRpcManager::new(rpc_tspt.clone()));

        let basic_route = Arc::new(BasicRoute::new(my_peer_id, global_ctx.clone()));

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

            basic_route,

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
        use packet::ArchivedPacketBody;

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
                if let packet::ArchivedPacketBody::Data(x) = &packet.body {
                    // TODO: use a function to get the body ref directly for zero copy
                    self.nic_channel
                        .send(extract_bytes_from_archived_vec(&data, &x))
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

        // for route
        self.add_packet_process_pipeline(Box::new(self.basic_route.clone()))
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
                if let ArchivedPacketBody::TaRpc(..) = &packet.body {
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
        T: Route + Send + Sync + 'static,
    {
        struct Interface {
            my_peer_id: PeerId,
            peers: Arc<PeerMap>,
            foreign_network_client: Arc<ForeignNetworkClient>,
        }

        #[async_trait]
        impl RouteInterface for Interface {
            async fn list_peers(&self) -> Vec<PeerId> {
                let mut peers = self.foreign_network_client.list_foreign_peers();
                peers.extend(self.peers.list_peers_with_conn().await);
                peers
            }
            async fn send_route_packet(
                &self,
                msg: Bytes,
                route_id: u8,
                dst_peer_id: PeerId,
            ) -> Result<(), Error> {
                let packet_bytes: Bytes =
                    packet::Packet::new_route_packet(self.my_peer_id, dst_peer_id, route_id, &msg)
                        .into();
                if self.foreign_network_client.has_next_hop(dst_peer_id) {
                    return self
                        .foreign_network_client
                        .send_msg(packet_bytes, dst_peer_id)
                        .await;
                }

                self.peers
                    .send_msg_directly(packet_bytes, dst_peer_id)
                    .await
            }
            fn my_peer_id(&self) -> PeerId {
                self.my_peer_id
            }
        }

        let my_peer_id = self.my_peer_id;
        let _route_id = route
            .open(Box::new(Interface {
                my_peer_id,
                peers: self.peers.clone(),
                foreign_network_client: self.foreign_network_client.clone(),
            }))
            .await
            .unwrap();

        let arc_route: ArcRoute = Arc::new(Box::new(route));
        self.peers.add_route(arc_route).await;
    }

    pub async fn list_routes(&self) -> Vec<crate::rpc::Route> {
        self.basic_route.list_routes().await
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
            .replace(self.foreign_network_client.get_peer_map().clone());

        self.foreign_network_manager.run().await;
        self.foreign_network_client.run().await;
    }

    pub async fn run(&self) -> Result<(), Error> {
        self.add_route(self.basic_route.clone()).await;

        self.init_packet_process_pipeline().await;
        self.start_peer_recv().await;
        self.peer_rpc_mgr.run();
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
        self.basic_route.clone()
    }

    pub fn get_foreign_network_manager(&self) -> Arc<ForeignNetworkManager> {
        self.foreign_network_manager.clone()
    }

    pub fn get_foreign_network_client(&self) -> Arc<ForeignNetworkClient> {
        self.foreign_network_client.clone()
    }
}
