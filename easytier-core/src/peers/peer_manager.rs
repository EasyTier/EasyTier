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

use uuid::Uuid;

use crate::{
    common::{error::Error, global_ctx::ArcGlobalCtx, rkyv_util::extract_bytes_from_archived_vec},
    peers::{
        packet::{self},
        peer_conn::PeerConn,
        peer_rpc::PeerRpcManagerTransport,
        route_trait::RouteInterface,
    },
    tunnels::{SinkItem, Tunnel, TunnelConnector},
};

use super::{
    peer_map::PeerMap,
    peer_rip_route::BasicRoute,
    peer_rpc::PeerRpcManager,
    route_trait::{ArcRoute, Route},
    PeerId,
};

struct RpcTransport {
    my_peer_id: uuid::Uuid,
    peers: Arc<PeerMap>,

    packet_recv: Mutex<UnboundedReceiver<Bytes>>,
    peer_rpc_tspt_sender: UnboundedSender<Bytes>,
}

#[async_trait::async_trait]
impl PeerRpcManagerTransport for RpcTransport {
    fn my_peer_id(&self) -> Uuid {
        self.my_peer_id
    }

    async fn send(&self, msg: Bytes, dst_peer_id: &uuid::Uuid) -> Result<(), Error> {
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
    my_node_id: uuid::Uuid,
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
}

impl Debug for PeerManager {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PeerManager")
            .field("my_node_id", &self.my_node_id)
            .field("instance_name", &self.global_ctx.inst_name)
            .field("net_ns", &self.global_ctx.net_ns.name())
            .finish()
    }
}

impl PeerManager {
    pub fn new(global_ctx: ArcGlobalCtx, nic_channel: mpsc::Sender<SinkItem>) -> Self {
        let (packet_send, packet_recv) = mpsc::channel(100);
        let peers = Arc::new(PeerMap::new(packet_send.clone(), global_ctx.clone()));

        // TODO: remove these because we have impl pipeline processor.
        let (peer_rpc_tspt_sender, peer_rpc_tspt_recv) = mpsc::unbounded_channel();
        let rpc_tspt = Arc::new(RpcTransport {
            my_peer_id: global_ctx.get_id(),
            peers: peers.clone(),
            packet_recv: Mutex::new(peer_rpc_tspt_recv),
            peer_rpc_tspt_sender,
        });

        let basic_route = Arc::new(BasicRoute::new(global_ctx.get_id(), global_ctx.clone()));

        PeerManager {
            my_node_id: global_ctx.get_id(),
            global_ctx,
            nic_channel,

            tasks: Arc::new(Mutex::new(JoinSet::new())),

            packet_recv: Arc::new(Mutex::new(Some(packet_recv))),

            peers: peers.clone(),

            peer_rpc_mgr: Arc::new(PeerRpcManager::new(rpc_tspt.clone())),
            peer_rpc_tspt: rpc_tspt,

            peer_packet_process_pipeline: Arc::new(RwLock::new(Vec::new())),
            nic_packet_process_pipeline: Arc::new(RwLock::new(Vec::new())),

            basic_route,
        }
    }

    pub async fn add_client_tunnel(&self, tunnel: Box<dyn Tunnel>) -> Result<(Uuid, Uuid), Error> {
        let mut peer = PeerConn::new(self.my_node_id, self.global_ctx.clone(), tunnel);
        peer.do_handshake_as_client().await?;
        let conn_id = peer.get_conn_id();
        let peer_id = peer.get_peer_id();
        self.peers.add_new_peer_conn(peer).await;
        Ok((peer_id, conn_id))
    }

    #[tracing::instrument]
    pub async fn try_connect<C>(&self, mut connector: C) -> Result<(Uuid, Uuid), Error>
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
        let mut peer = PeerConn::new(self.my_node_id, self.global_ctx.clone(), tunnel);
        peer.do_handshake_as_server().await?;
        self.peers.add_new_peer_conn(peer).await;
        tracing::info!("add tunnel as server done");
        Ok(())
    }

    async fn start_peer_recv(&self) {
        let mut recv = ReceiverStream::new(self.packet_recv.lock().await.take().unwrap());
        let my_node_id = self.my_node_id;
        let peers = self.peers.clone();
        let pipe_line = self.peer_packet_process_pipeline.clone();
        self.tasks.lock().await.spawn(async move {
            log::trace!("start_peer_recv");
            while let Some(ret) = recv.next().await {
                log::trace!("peer recv a packet...: {:?}", ret);
                let packet = packet::Packet::decode(&ret);
                let from_peer_uuid = packet.from_peer.to_uuid();
                let to_peer_uuid = packet.to_peer.as_ref().unwrap().to_uuid();
                if to_peer_uuid != my_node_id {
                    log::trace!(
                        "need forward: to_peer_uuid: {:?}, my_uuid: {:?}",
                        to_peer_uuid,
                        my_node_id
                    );
                    let ret = peers.send_msg(ret.clone(), &to_peer_uuid).await;
                    if ret.is_err() {
                        log::error!(
                            "forward packet error: {:?}, dst: {:?}, from: {:?}",
                            ret,
                            to_peer_uuid,
                            from_peer_uuid
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
                        .send(extract_bytes_from_archived_vec(&data, &x.data))
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
                if let ArchivedPacketBody::Ctrl(packet::ArchivedCtrlPacketBody::TaRpc(..)) =
                    &packet.body
                {
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
            my_node_id: uuid::Uuid,
            peers: Arc<PeerMap>,
        }

        #[async_trait]
        impl RouteInterface for Interface {
            async fn list_peers(&self) -> Vec<PeerId> {
                self.peers.list_peers_with_conn().await
            }
            async fn send_route_packet(
                &self,
                msg: Bytes,
                route_id: u8,
                dst_peer_id: &PeerId,
            ) -> Result<(), Error> {
                self.peers
                    .send_msg_directly(
                        packet::Packet::new_route_packet(
                            self.my_node_id,
                            *dst_peer_id,
                            route_id,
                            &msg,
                        )
                        .into(),
                        dst_peer_id,
                    )
                    .await
            }
        }

        let my_node_id = self.my_node_id;
        let _route_id = route
            .open(Box::new(Interface {
                my_node_id,
                peers: self.peers.clone(),
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

    pub async fn send_msg(&self, msg: Bytes, dst_peer_id: &PeerId) -> Result<(), Error> {
        self.peers.send_msg(msg, dst_peer_id).await
    }

    pub async fn send_msg_ipv4(&self, msg: BytesMut, ipv4_addr: Ipv4Addr) -> Result<(), Error> {
        log::trace!(
            "do send_msg in peer manager, msg: {:?}, ipv4_addr: {}",
            msg,
            ipv4_addr
        );

        let Some(peer_id) = self.peers.get_peer_id_by_ipv4(&ipv4_addr).await else {
            log::trace!("no peer id for ipv4: {}", ipv4_addr);
            return Ok(());
        };

        let msg = self.run_nic_packet_process_pipeline(msg).await;
        self.peers
            .send_msg(
                packet::Packet::new_data_packet(self.my_node_id, peer_id, &msg).into(),
                &peer_id,
            )
            .await?;

        log::trace!(
            "do send_msg in peer manager done, dst_peer_id: {:?}",
            peer_id
        );

        Ok(())
    }

    async fn run_clean_peer_without_conn_routine(&self) {
        let peer_map = self.peers.clone();
        self.tasks.lock().await.spawn(async move {
            loop {
                let mut to_remove = vec![];

                for peer_id in peer_map.list_peers().await {
                    let conns = peer_map.list_peer_conns(&peer_id).await;
                    if conns.is_none() || conns.as_ref().unwrap().is_empty() {
                        to_remove.push(peer_id);
                    }
                }

                for peer_id in to_remove {
                    peer_map.close_peer(&peer_id).await.unwrap();
                }

                tokio::time::sleep(std::time::Duration::from_secs(3)).await;
            }
        });
    }

    pub async fn run(&self) -> Result<(), Error> {
        self.add_route(self.basic_route.clone()).await;

        self.init_packet_process_pipeline().await;
        self.start_peer_recv().await;
        self.peer_rpc_mgr.run();
        self.run_clean_peer_without_conn_routine().await;
        Ok(())
    }

    pub fn get_peer_map(&self) -> Arc<PeerMap> {
        self.peers.clone()
    }

    pub fn get_peer_rpc_mgr(&self) -> Arc<PeerRpcManager> {
        self.peer_rpc_mgr.clone()
    }

    pub fn my_node_id(&self) -> uuid::Uuid {
        self.my_node_id
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
}
