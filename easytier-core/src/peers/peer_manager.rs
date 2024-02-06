use std::{
    fmt::Debug,
    net::Ipv4Addr,
    sync::{atomic::AtomicU8, Arc},
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
    peer_rpc::PeerRpcManager,
    route_trait::{ArcRoute, Route},
    PeerId,
};

struct RpcTransport {
    my_peer_id: uuid::Uuid,
    peers: Arc<PeerMap>,

    packet_recv: Mutex<UnboundedReceiver<Bytes>>,
    peer_rpc_tspt_sender: UnboundedSender<Bytes>,

    route: Arc<Mutex<Option<ArcRoute>>>,
}

#[async_trait::async_trait]
impl PeerRpcManagerTransport for RpcTransport {
    fn my_peer_id(&self) -> Uuid {
        self.my_peer_id
    }

    async fn send(&self, msg: Bytes, dst_peer_id: &uuid::Uuid) -> Result<(), Error> {
        let route = self.route.lock().await;
        if route.is_none() {
            log::error!("no route info when send rpc msg");
            return Err(Error::RouteError("No route info".to_string()));
        }

        self.peers
            .send_msg(msg, dst_peer_id, route.as_ref().unwrap().clone())
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
    route: Arc<Mutex<Option<ArcRoute>>>,
    cur_route_id: AtomicU8,

    peer_rpc_mgr: Arc<PeerRpcManager>,
    peer_rpc_tspt: Arc<RpcTransport>,

    peer_packet_process_pipeline: Arc<RwLock<Vec<BoxPeerPacketFilter>>>,
    nic_packet_process_pipeline: Arc<RwLock<Vec<BoxNicPacketFilter>>>,
}

impl Debug for PeerManager {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PeerManager")
            .field("my_node_id", &self.my_node_id)
            .field("instance_name", &self.global_ctx.inst_name)
            .field("net_ns", &self.global_ctx.net_ns.name())
            .field("cur_route_id", &self.cur_route_id)
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
            route: Arc::new(Mutex::new(None)),
        });

        PeerManager {
            my_node_id: global_ctx.get_id(),
            global_ctx,
            nic_channel,

            tasks: Arc::new(Mutex::new(JoinSet::new())),

            packet_recv: Arc::new(Mutex::new(Some(packet_recv))),

            peers: peers.clone(),
            route: Arc::new(Mutex::new(None)),
            cur_route_id: AtomicU8::new(0),

            peer_rpc_mgr: Arc::new(PeerRpcManager::new(rpc_tspt.clone())),
            peer_rpc_tspt: rpc_tspt,

            peer_packet_process_pipeline: Arc::new(RwLock::new(Vec::new())),
            nic_packet_process_pipeline: Arc::new(RwLock::new(Vec::new())),
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
        let arc_route = self.route.clone();
        let pipe_line = self.peer_packet_process_pipeline.clone();
        self.tasks.lock().await.spawn(async move {
            log::trace!("start_peer_recv");
            while let Some(ret) = recv.next().await {
                log::trace!("peer recv a packet...: {:?}", ret);
                let packet = packet::Packet::decode(&ret);
                let from_peer_uuid = packet.from_peer.to_uuid();
                let to_peer_uuid = packet.to_peer.as_ref().unwrap().to_uuid();
                if to_peer_uuid != my_node_id {
                    let locked_arc_route = arc_route.lock().await;
                    if locked_arc_route.is_none() {
                        log::error!("no route info after recv a packet");
                        continue;
                    }

                    let route = locked_arc_route.as_ref().unwrap().clone();
                    drop(locked_arc_route);
                    log::trace!(
                        "need forward: to_peer_uuid: {:?}, my_uuid: {:?}",
                        to_peer_uuid,
                        my_node_id
                    );
                    let ret = peers
                        .send_msg(ret.clone(), &to_peer_uuid, route.clone())
                        .await;
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

        // for peer manager router packet
        struct RoutePacketProcessor {
            route: Arc<Mutex<Option<ArcRoute>>>,
        }
        #[async_trait::async_trait]
        impl PeerPacketFilter for RoutePacketProcessor {
            async fn try_process_packet_from_peer(
                &self,
                packet: &packet::ArchivedPacket,
                data: &Bytes,
            ) -> Option<()> {
                if let ArchivedPacketBody::Ctrl(packet::ArchivedCtrlPacketBody::RoutePacket(
                    route_packet,
                )) = &packet.body
                {
                    let r = self.route.lock().await;
                    match r.as_ref() {
                        Some(x) => {
                            let x = x.clone();
                            drop(r);
                            x.handle_route_packet(
                                packet.from_peer.to_uuid(),
                                extract_bytes_from_archived_vec(&data, &route_packet.body),
                            )
                            .await;
                        }
                        None => {
                            log::error!("no route info when handle route packet");
                        }
                    }
                    Some(())
                } else {
                    None
                }
            }
        }
        self.add_packet_process_pipeline(Box::new(RoutePacketProcessor {
            route: self.route.clone(),
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

    pub async fn set_route<T>(&self, route: T)
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
        let route_id = route
            .open(Box::new(Interface {
                my_node_id,
                peers: self.peers.clone(),
            }))
            .await
            .unwrap();

        self.cur_route_id
            .store(route_id, std::sync::atomic::Ordering::Relaxed);
        let arc_route: ArcRoute = Arc::new(Box::new(route));

        self.route.lock().await.replace(arc_route.clone());

        self.peer_rpc_tspt
            .route
            .lock()
            .await
            .replace(arc_route.clone());
    }

    pub async fn list_routes(&self) -> Vec<easytier_rpc::Route> {
        let route_info = self.route.lock().await;
        if route_info.is_none() {
            return Vec::new();
        }

        let route = route_info.as_ref().unwrap().clone();
        drop(route_info);
        route.list_routes().await
    }

    async fn run_nic_packet_process_pipeline(&self, mut data: BytesMut) -> BytesMut {
        for pipeline in self.nic_packet_process_pipeline.read().await.iter().rev() {
            data = pipeline.try_process_packet_from_nic(data).await;
        }
        data
    }

    pub async fn send_msg(&self, msg: Bytes, dst_peer_id: &PeerId) -> Result<(), Error> {
        self.peer_rpc_tspt.send(msg, dst_peer_id).await
    }

    pub async fn send_msg_ipv4(&self, msg: BytesMut, ipv4_addr: Ipv4Addr) -> Result<(), Error> {
        let route_info = self.route.lock().await;
        if route_info.is_none() {
            log::error!("no route info");
            return Err(Error::RouteError("No route info".to_string()));
        }

        let route = route_info.as_ref().unwrap().clone();
        drop(route_info);

        log::trace!(
            "do send_msg in peer manager, msg: {:?}, ipv4_addr: {}",
            msg,
            ipv4_addr
        );

        match route.get_peer_id_by_ipv4(&ipv4_addr).await {
            Some(peer_id) => {
                let msg = self.run_nic_packet_process_pipeline(msg).await;
                self.peers
                    .send_msg(
                        packet::Packet::new_data_packet(self.my_node_id, peer_id, &msg).into(),
                        &peer_id,
                        route.clone(),
                    )
                    .await?;
                log::trace!(
                    "do send_msg in peer manager done, dst_peer_id: {:?}",
                    peer_id
                );
            }
            None => {
                log::trace!("no peer id for ipv4: {}", ipv4_addr);
                return Ok(());
            }
        }

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

                tokio::time::sleep(std::time::Duration::from_secs(10)).await;
            }
        });
    }

    pub async fn run(&self) -> Result<(), Error> {
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
}
