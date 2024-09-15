use std::{
    fmt::Debug,
    net::Ipv4Addr,
    sync::{Arc, Weak},
};

use anyhow::Context;
use async_trait::async_trait;

use futures::StreamExt;

use tokio::{
    sync::{
        mpsc::{self, UnboundedReceiver, UnboundedSender},
        Mutex, RwLock,
    },
    task::JoinSet,
};
use tokio_stream::wrappers::ReceiverStream;
use tokio_util::bytes::Bytes;

use crate::{
    common::{error::Error, global_ctx::ArcGlobalCtx, stun::StunInfoCollectorTrait, PeerId},
    peers::{
        peer_conn::PeerConn,
        peer_rpc::PeerRpcManagerTransport,
        route_trait::{NextHopPolicy, RouteInterface},
        PeerPacketFilter,
    },
    tunnel::{
        self,
        packet_def::{PacketType, ZCPacket},
        SinkItem, Tunnel, TunnelConnector,
    },
};

use super::{
    encrypt::{Encryptor, NullCipher},
    foreign_network_client::ForeignNetworkClient,
    foreign_network_manager::ForeignNetworkManager,
    peer_conn::PeerConnId,
    peer_map::PeerMap,
    peer_ospf_route::PeerRoute,
    peer_rpc::PeerRpcManager,
    route_trait::{ArcRoute, Route},
    BoxNicPacketFilter, BoxPeerPacketFilter, PacketRecvChanReceiver,
};

struct RpcTransport {
    my_peer_id: PeerId,
    peers: Weak<PeerMap>,
    foreign_peers: Mutex<Option<Weak<ForeignNetworkClient>>>,

    packet_recv: Mutex<UnboundedReceiver<ZCPacket>>,
    peer_rpc_tspt_sender: UnboundedSender<ZCPacket>,

    encryptor: Arc<Box<dyn Encryptor>>,
}

#[async_trait::async_trait]
impl PeerRpcManagerTransport for RpcTransport {
    fn my_peer_id(&self) -> PeerId {
        self.my_peer_id
    }

    async fn send(&self, mut msg: ZCPacket, dst_peer_id: PeerId) -> Result<(), Error> {
        let foreign_peers = self
            .foreign_peers
            .lock()
            .await
            .as_ref()
            .ok_or(Error::Unknown)?
            .upgrade()
            .ok_or(Error::Unknown)?;
        let peers = self.peers.upgrade().ok_or(Error::Unknown)?;

        if let Some(gateway_id) = peers
            .get_gateway_peer_id(dst_peer_id, NextHopPolicy::LeastHop)
            .await
        {
            tracing::trace!(
                ?dst_peer_id,
                ?gateway_id,
                ?self.my_peer_id,
                "send msg to peer via gateway",
            );
            self.encryptor
                .encrypt(&mut msg)
                .with_context(|| "encrypt failed")?;
            peers.send_msg_directly(msg, gateway_id).await
        } else if foreign_peers.has_next_hop(dst_peer_id) {
            if !foreign_peers.is_peer_public_node(&dst_peer_id) {
                // do not encrypt for msg sending to public node
                self.encryptor
                    .encrypt(&mut msg)
                    .with_context(|| "encrypt failed")?;
            }
            tracing::debug!(
                ?dst_peer_id,
                ?self.my_peer_id,
                "failed to send msg to peer, try foreign network",
            );
            foreign_peers.send_msg(msg, dst_peer_id).await
        } else {
            Err(Error::RouteError(Some(format!(
                "peermgr RpcTransport no route for dst_peer_id: {}",
                dst_peer_id
            ))))
        }
    }

    async fn recv(&self) -> Result<ZCPacket, Error> {
        if let Some(o) = self.packet_recv.lock().await.recv().await {
            Ok(o)
        } else {
            Err(Error::Unknown)
        }
    }
}

pub enum RouteAlgoType {
    Ospf,
    None,
}

enum RouteAlgoInst {
    Ospf(Arc<PeerRoute>),
    None,
}

pub struct PeerManager {
    my_peer_id: PeerId,

    global_ctx: ArcGlobalCtx,
    nic_channel: mpsc::Sender<SinkItem>,

    tasks: Arc<Mutex<JoinSet<()>>>,

    packet_recv: Arc<Mutex<Option<PacketRecvChanReceiver>>>,

    peers: Arc<PeerMap>,

    peer_rpc_mgr: Arc<PeerRpcManager>,
    peer_rpc_tspt: Arc<RpcTransport>,

    peer_packet_process_pipeline: Arc<RwLock<Vec<BoxPeerPacketFilter>>>,
    nic_packet_process_pipeline: Arc<RwLock<Vec<BoxNicPacketFilter>>>,

    route_algo_inst: RouteAlgoInst,

    foreign_network_manager: Arc<ForeignNetworkManager>,
    foreign_network_client: Arc<ForeignNetworkClient>,

    encryptor: Arc<Box<dyn Encryptor>>,

    exit_nodes: Vec<Ipv4Addr>,
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

        let mut encryptor: Arc<Box<dyn Encryptor>> = Arc::new(Box::new(NullCipher));
        if global_ctx.get_flags().enable_encryption {
            #[cfg(feature = "wireguard")]
            {
                use super::encrypt::ring_aes_gcm::AesGcmCipher;
                encryptor = Arc::new(Box::new(AesGcmCipher::new_128(global_ctx.get_128_key())));
            }

            #[cfg(all(feature = "aes-gcm", not(feature = "wireguard")))]
            {
                use super::encrypt::aes_gcm::AesGcmCipher;
                encryptor = Arc::new(Box::new(AesGcmCipher::new_128(global_ctx.get_128_key())));
            }

            #[cfg(all(not(feature = "wireguard"), not(feature = "aes-gcm")))]
            {
                compile_error!("wireguard or aes-gcm feature must be enabled for encryption");
            }
        }

        // TODO: remove these because we have impl pipeline processor.
        let (peer_rpc_tspt_sender, peer_rpc_tspt_recv) = mpsc::unbounded_channel();
        let rpc_tspt = Arc::new(RpcTransport {
            my_peer_id,
            peers: Arc::downgrade(&peers),
            foreign_peers: Mutex::new(None),
            packet_recv: Mutex::new(peer_rpc_tspt_recv),
            peer_rpc_tspt_sender,
            encryptor: encryptor.clone(),
        });
        let peer_rpc_mgr = Arc::new(PeerRpcManager::new(rpc_tspt.clone()));

        let route_algo_inst = match route_algo {
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

        let exit_nodes = global_ctx.config.get_exit_nodes();

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

            encryptor,
            exit_nodes,
        }
    }

    async fn add_new_peer_conn(&self, peer_conn: PeerConn) -> Result<(), Error> {
        if self.global_ctx.get_network_identity() != peer_conn.get_network_identity() {
            return Err(Error::SecretKeyError(
                "network identity not match".to_string(),
            ));
        }
        Ok(self.peers.add_new_peer_conn(peer_conn).await)
    }

    pub async fn add_client_tunnel(
        &self,
        tunnel: Box<dyn Tunnel>,
    ) -> Result<(PeerId, PeerConnId), Error> {
        let mut peer = PeerConn::new(self.my_peer_id, self.global_ctx.clone(), tunnel);
        peer.do_handshake_as_client().await?;
        let conn_id = peer.get_conn_id();
        let peer_id = peer.get_peer_id();
        if peer.get_network_identity().network_name
            == self.global_ctx.get_network_identity().network_name
        {
            self.add_new_peer_conn(peer).await?;
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
        if peer.get_network_identity().network_name
            == self.global_ctx.get_network_identity().network_name
        {
            self.add_new_peer_conn(peer).await?;
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
        let foreign_client = self.foreign_network_client.clone();
        let encryptor = self.encryptor.clone();
        self.tasks.lock().await.spawn(async move {
            tracing::trace!("start_peer_recv");
            while let Some(mut ret) = recv.next().await {
                let Some(hdr) = ret.mut_peer_manager_header() else {
                    tracing::warn!(?ret, "invalid packet, skip");
                    continue;
                };
                tracing::trace!(?hdr, "peer recv a packet...");
                let from_peer_id = hdr.from_peer_id.get();
                let to_peer_id = hdr.to_peer_id.get();
                if to_peer_id != my_peer_id {
                    if hdr.forward_counter > 7 {
                        tracing::warn!(?hdr, "forward counter exceed, drop packet");
                        continue;
                    }

                    if hdr.forward_counter > 2 && hdr.is_latency_first() {
                        tracing::trace!(?hdr, "set_latency_first false because too many hop");
                        hdr.set_latency_first(false);
                    }

                    hdr.forward_counter += 1;
                    tracing::trace!(?to_peer_id, ?my_peer_id, "need forward");
                    let ret =
                        Self::send_msg_internal(&peers, &foreign_client, ret, to_peer_id).await;
                    if ret.is_err() {
                        tracing::error!(?ret, ?to_peer_id, ?from_peer_id, "forward packet error");
                    }
                } else {
                    if let Err(e) = encryptor.decrypt(&mut ret) {
                        tracing::error!(?e, "decrypt failed");
                        continue;
                    }

                    let mut processed = false;
                    let mut zc_packet = Some(ret);
                    let mut idx = 0;
                    for pipeline in pipe_line.read().await.iter().rev() {
                        tracing::trace!(?zc_packet, ?idx, "try_process_packet_from_peer");
                        idx += 1;
                        zc_packet = pipeline
                            .try_process_packet_from_peer(zc_packet.unwrap())
                            .await;
                        if zc_packet.is_none() {
                            processed = true;
                            break;
                        }
                    }
                    if !processed {
                        tracing::error!(?zc_packet, "unhandled packet");
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
            async fn try_process_packet_from_peer(&self, packet: ZCPacket) -> Option<ZCPacket> {
                let hdr = packet.peer_manager_header().unwrap();
                if hdr.packet_type == PacketType::Data as u8 {
                    tracing::trace!(?packet, "send packet to nic channel");
                    // TODO: use a function to get the body ref directly for zero copy
                    let _ = self.nic_channel.send(packet).await;
                    None
                } else {
                    Some(packet)
                }
            }
        }
        self.add_packet_process_pipeline(Box::new(NicPacketProcessor {
            nic_channel: self.nic_channel.clone(),
        }))
        .await;

        // for peer rpc packet
        struct PeerRpcPacketProcessor {
            peer_rpc_tspt_sender: UnboundedSender<ZCPacket>,
        }

        #[async_trait::async_trait]
        impl PeerPacketFilter for PeerRpcPacketProcessor {
            async fn try_process_packet_from_peer(&self, packet: ZCPacket) -> Option<ZCPacket> {
                let hdr = packet.peer_manager_header().unwrap();
                if hdr.packet_type == PacketType::TaRpc as u8
                    || hdr.packet_type == PacketType::RpcReq as u8
                    || hdr.packet_type == PacketType::RpcResp as u8
                {
                    self.peer_rpc_tspt_sender.send(packet).unwrap();
                    None
                } else {
                    Some(packet)
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
                _route_id: u8,
                dst_peer_id: PeerId,
            ) -> Result<(), Error> {
                let foreign_client = self
                    .foreign_network_client
                    .upgrade()
                    .ok_or(Error::Unknown)?;
                let peer_map = self.peers.upgrade().ok_or(Error::Unknown)?;
                let mut zc_packet = ZCPacket::new_with_payload(&msg);
                zc_packet.fill_peer_manager_hdr(
                    self.my_peer_id,
                    dst_peer_id,
                    PacketType::Route as u8,
                );
                if foreign_client.has_next_hop(dst_peer_id) {
                    foreign_client.send_msg(zc_packet, dst_peer_id).await
                } else {
                    peer_map.send_msg_directly(zc_packet, dst_peer_id).await
                }
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
            RouteAlgoInst::Ospf(route) => Box::new(route.clone()),
            RouteAlgoInst::None => panic!("no route"),
        }
    }

    pub async fn list_routes(&self) -> Vec<crate::rpc::Route> {
        self.get_route().list_routes().await
    }

    pub async fn dump_route(&self) -> String {
        self.get_route().dump().await
    }

    async fn run_nic_packet_process_pipeline(&self, data: &mut ZCPacket) {
        for pipeline in self.nic_packet_process_pipeline.read().await.iter().rev() {
            pipeline.try_process_packet_from_nic(data).await;
        }
    }

    fn get_next_hop_policy(is_first_latency: bool) -> NextHopPolicy {
        if is_first_latency {
            NextHopPolicy::LeastCost
        } else {
            NextHopPolicy::LeastHop
        }
    }

    pub async fn send_msg(&self, msg: ZCPacket, dst_peer_id: PeerId) -> Result<(), Error> {
        Self::send_msg_internal(&self.peers, &self.foreign_network_client, msg, dst_peer_id).await
    }

    async fn send_msg_internal(
        peers: &Arc<PeerMap>,
        foreign_network_client: &Arc<ForeignNetworkClient>,
        msg: ZCPacket,
        dst_peer_id: PeerId,
    ) -> Result<(), Error> {
        let policy =
            Self::get_next_hop_policy(msg.peer_manager_header().unwrap().is_latency_first());

        if let Some(gateway) = peers.get_gateway_peer_id(dst_peer_id, policy).await {
            peers.send_msg_directly(msg, gateway).await
        } else if foreign_network_client.has_next_hop(dst_peer_id) {
            foreign_network_client.send_msg(msg, dst_peer_id).await
        } else {
            Err(Error::RouteError(None))
        }
    }

    pub async fn send_msg_ipv4(&self, mut msg: ZCPacket, ipv4_addr: Ipv4Addr) -> Result<(), Error> {
        tracing::trace!(
            "do send_msg in peer manager, msg: {:?}, ipv4_addr: {}",
            msg,
            ipv4_addr
        );

        let mut is_exit_node = false;
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
        } else {
            for exit_node in &self.exit_nodes {
                if let Some(peer_id) = self.peers.get_peer_id_by_ipv4(exit_node).await {
                    dst_peers.push(peer_id);
                    is_exit_node = true;
                    break;
                }
            }
        }

        if dst_peers.is_empty() {
            tracing::info!("no peer id for ipv4: {}", ipv4_addr);
            return Ok(());
        }

        msg.fill_peer_manager_hdr(
            self.my_peer_id,
            0,
            tunnel::packet_def::PacketType::Data as u8,
        );
        self.run_nic_packet_process_pipeline(&mut msg).await;
        self.encryptor
            .encrypt(&mut msg)
            .with_context(|| "encrypt failed")?;

        let is_latency_first = self.global_ctx.get_flags().latency_first;
        msg.mut_peer_manager_header()
            .unwrap()
            .set_latency_first(is_latency_first)
            .set_exit_node(is_exit_node);
        let next_hop_policy = Self::get_next_hop_policy(is_latency_first);

        let mut errs: Vec<Error> = vec![];

        let mut msg = Some(msg);
        let total_dst_peers = dst_peers.len();
        for i in 0..total_dst_peers {
            let mut msg = if i == total_dst_peers - 1 {
                msg.take().unwrap()
            } else {
                msg.clone().unwrap()
            };

            let peer_id = &dst_peers[i];
            msg.mut_peer_manager_header()
                .unwrap()
                .to_peer_id
                .set(*peer_id);

            if let Some(gateway) = self
                .peers
                .get_gateway_peer_id(*peer_id, next_hop_policy.clone())
                .await
            {
                if let Err(e) = self.peers.send_msg_directly(msg, gateway).await {
                    errs.push(e);
                }
            } else if self.foreign_network_client.has_next_hop(*peer_id) {
                if let Err(e) = self.foreign_network_client.send_msg(msg, *peer_id).await {
                    errs.push(e);
                }
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

    pub fn get_foreign_network_manager(&self) -> Arc<ForeignNetworkManager> {
        self.foreign_network_manager.clone()
    }

    pub fn get_foreign_network_client(&self) -> Arc<ForeignNetworkClient> {
        self.foreign_network_client.clone()
    }

    pub fn get_my_info(&self) -> crate::rpc::NodeInfo {
        crate::rpc::NodeInfo {
            peer_id: self.my_peer_id,
            ipv4_addr: self
                .global_ctx
                .get_ipv4()
                .map(|x| x.to_string())
                .unwrap_or_default(),
            proxy_cidrs: self
                .global_ctx
                .get_proxy_cidrs()
                .into_iter()
                .map(|x| x.to_string())
                .collect(),
            hostname: self.global_ctx.get_hostname(),
            stun_info: Some(self.global_ctx.get_stun_info_collector().get_stun_info()),
            inst_id: self.global_ctx.get_id().to_string(),
            listeners: self
                .global_ctx
                .get_running_listeners()
                .iter()
                .map(|x| x.to_string())
                .collect(),
            config: self.global_ctx.config.dump(),
            version: env!("CARGO_PKG_VERSION").to_string(),
        }
    }
}

#[cfg(test)]
mod tests {

    use std::{fmt::Debug, sync::Arc, time::Duration};

    use crate::{
        common::{config::Flags, global_ctx::tests::get_mock_global_ctx},
        connector::{
            create_connector_by_url, udp_hole_punch::tests::create_mock_peer_manager_with_mock_stun,
        },
        instance::listeners::get_listener_by_url,
        peers::{
            peer_manager::RouteAlgoType,
            peer_rpc::tests::{MockService, TestRpcService, TestRpcServiceClient},
            tests::{connect_peer_manager, wait_route_appear},
        },
        rpc::NatType,
        tunnel::common::tests::wait_for_condition,
        tunnel::{TunnelConnector, TunnelListener},
    };

    use super::PeerManager;

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

    async fn connect_peer_manager_with<C: TunnelConnector + Debug + 'static, L: TunnelListener>(
        client_mgr: Arc<PeerManager>,
        server_mgr: &Arc<PeerManager>,
        mut client: C,
        server: &mut L,
    ) {
        server.listen().await.unwrap();

        tokio::spawn(async move {
            client.set_bind_addrs(vec![]);
            client_mgr.try_connect(client).await.unwrap();
        });

        server_mgr
            .add_client_tunnel(server.accept().await.unwrap())
            .await
            .unwrap();
    }

    #[rstest::rstest]
    #[tokio::test]
    #[serial_test::serial(forward_packet_test)]
    async fn forward_packet(
        #[values("tcp", "udp", "wg", "quic")] proto1: &str,
        #[values("tcp", "udp", "wg", "quic")] proto2: &str,
    ) {
        let peer_mgr_a = create_mock_peer_manager_with_mock_stun(NatType::Unknown).await;
        peer_mgr_a.get_peer_rpc_mgr().run_service(
            100,
            MockService {
                prefix: "hello a".to_owned(),
            }
            .serve(),
        );

        let peer_mgr_b = create_mock_peer_manager_with_mock_stun(NatType::Unknown).await;

        let peer_mgr_c = create_mock_peer_manager_with_mock_stun(NatType::Unknown).await;
        peer_mgr_c.get_peer_rpc_mgr().run_service(
            100,
            MockService {
                prefix: "hello c".to_owned(),
            }
            .serve(),
        );

        let mut listener1 = get_listener_by_url(
            &format!("{}://0.0.0.0:31013", proto1).parse().unwrap(),
            peer_mgr_b.get_global_ctx(),
        )
        .unwrap();
        let connector1 = create_connector_by_url(
            format!("{}://127.0.0.1:31013", proto1).as_str(),
            &peer_mgr_a.get_global_ctx(),
        )
        .await
        .unwrap();
        connect_peer_manager_with(peer_mgr_a.clone(), &peer_mgr_b, connector1, &mut listener1)
            .await;

        wait_route_appear(peer_mgr_a.clone(), peer_mgr_b.clone())
            .await
            .unwrap();

        let mut listener2 = get_listener_by_url(
            &format!("{}://0.0.0.0:31014", proto2).parse().unwrap(),
            peer_mgr_c.get_global_ctx(),
        )
        .unwrap();
        let connector2 = create_connector_by_url(
            format!("{}://127.0.0.1:31014", proto2).as_str(),
            &peer_mgr_b.get_global_ctx(),
        )
        .await
        .unwrap();
        connect_peer_manager_with(peer_mgr_b.clone(), &peer_mgr_c, connector2, &mut listener2)
            .await;

        wait_route_appear(peer_mgr_a.clone(), peer_mgr_c.clone())
            .await
            .unwrap();

        let ret = peer_mgr_a
            .get_peer_rpc_mgr()
            .do_client_rpc_scoped(100, peer_mgr_c.my_peer_id(), |c| async {
                let c = TestRpcServiceClient::new(tarpc::client::Config::default(), c).spawn();
                let ret = c.hello(tarpc::context::current(), "abc".to_owned()).await;
                ret
            })
            .await
            .unwrap();
        assert_eq!(ret, "hello c abc");
    }

    #[tokio::test]
    async fn communicate_between_enc_and_non_enc() {
        let create_mgr = |enable_encryption| async move {
            let (s, _r) = tokio::sync::mpsc::channel(1000);
            let mock_global_ctx = get_mock_global_ctx();
            mock_global_ctx.config.set_flags(Flags {
                enable_encryption,
                ..Default::default()
            });
            let peer_mgr = Arc::new(PeerManager::new(RouteAlgoType::Ospf, mock_global_ctx, s));
            peer_mgr.run().await.unwrap();
            peer_mgr
        };

        let peer_mgr_a = create_mgr(true).await;
        let peer_mgr_b = create_mgr(false).await;

        connect_peer_manager(peer_mgr_a.clone(), peer_mgr_b.clone()).await;

        // wait 5sec should not crash.
        tokio::time::sleep(Duration::from_secs(5)).await;

        // both mgr should alive
        let mgr_c = create_mgr(true).await;
        connect_peer_manager(peer_mgr_a.clone(), mgr_c.clone()).await;
        wait_route_appear(mgr_c, peer_mgr_a).await.unwrap();

        let mgr_d = create_mgr(false).await;
        connect_peer_manager(peer_mgr_b.clone(), mgr_d.clone()).await;
        wait_route_appear(mgr_d, peer_mgr_b).await.unwrap();
    }
}
