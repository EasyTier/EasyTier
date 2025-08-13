use std::{
    fmt::Debug,
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
    sync::{atomic::AtomicBool, Arc, Weak},
    time::{Instant, SystemTime},
};

use anyhow::Context;
use async_trait::async_trait;

use dashmap::DashMap;

use tokio::{
    sync::{
        mpsc::{self, UnboundedReceiver, UnboundedSender},
        Mutex, RwLock,
    },
    task::JoinSet,
};

use crate::{
    common::{
        compressor::{Compressor as _, DefaultCompressor},
        constants::EASYTIER_VERSION,
        error::Error,
        global_ctx::{ArcGlobalCtx, NetworkIdentity},
        stats_manager::{CounterHandle, LabelSet, LabelType, MetricName},
        stun::StunInfoCollectorTrait,
        PeerId,
    },
    peers::{
        peer_conn::PeerConn,
        peer_rpc::PeerRpcManagerTransport,
        recv_packet_from_chan,
        route_trait::{ForeignNetworkRouteInfoMap, NextHopPolicy, RouteInterface},
        PeerPacketFilter,
    },
    proto::{
        cli::{
            self, list_global_foreign_network_response::OneForeignNetwork,
            ListGlobalForeignNetworkResponse,
        },
        peer_rpc::{ForeignNetworkRouteInfoEntry, ForeignNetworkRouteInfoKey},
    },
    tunnel::{
        self,
        packet_def::{CompressorAlgo, PacketType, ZCPacket},
        Tunnel, TunnelConnector,
    },
};

use super::{
    create_packet_recv_chan,
    encrypt::{Encryptor, NullCipher},
    foreign_network_client::ForeignNetworkClient,
    foreign_network_manager::{ForeignNetworkManager, GlobalForeignNetworkAccessor},
    peer_conn::PeerConnId,
    peer_map::PeerMap,
    peer_ospf_route::PeerRoute,
    peer_rpc::PeerRpcManager,
    route_trait::{ArcRoute, Route},
    BoxNicPacketFilter, BoxPeerPacketFilter, PacketRecvChan, PacketRecvChanReceiver,
};

struct RpcTransport {
    my_peer_id: PeerId,
    peers: Weak<PeerMap>,
    // TODO: this seems can be removed
    foreign_peers: Mutex<Option<Weak<ForeignNetworkClient>>>,

    packet_recv: Mutex<UnboundedReceiver<ZCPacket>>,
    peer_rpc_tspt_sender: UnboundedSender<ZCPacket>,

    encryptor: Arc<dyn Encryptor>,
}

#[async_trait::async_trait]
impl PeerRpcManagerTransport for RpcTransport {
    fn my_peer_id(&self) -> PeerId {
        self.my_peer_id
    }

    async fn send(&self, mut msg: ZCPacket, dst_peer_id: PeerId) -> Result<(), Error> {
        let peers = self.peers.upgrade().ok_or(Error::Unknown)?;
        // NOTE: if route info is not exchanged, this will return None. treat it as public server.
        let is_dst_peer_public_server = peers
            .get_route_peer_info(dst_peer_id)
            .await
            .and_then(|x| x.feature_flag.map(|x| x.is_public_server))
            // if dst is directly connected, it's must not public server
            .unwrap_or(!peers.has_peer(dst_peer_id));
        if !is_dst_peer_public_server {
            self.encryptor
                .encrypt(&mut msg)
                .with_context(|| "encrypt failed")?;
        }
        // send to self and this packet will be forwarded in peer_recv loop
        peers.send_msg_directly(msg, self.my_peer_id).await
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

struct SelfTxCounters {
    self_tx_packets: CounterHandle,
    self_tx_bytes: CounterHandle,
    compress_tx_bytes_before: CounterHandle,
    compress_tx_bytes_after: CounterHandle,
}

pub struct PeerManager {
    my_peer_id: PeerId,

    global_ctx: ArcGlobalCtx,
    nic_channel: PacketRecvChan,

    tasks: Mutex<JoinSet<()>>,

    packet_recv: Arc<Mutex<Option<PacketRecvChanReceiver>>>,

    peers: Arc<PeerMap>,

    peer_rpc_mgr: Arc<PeerRpcManager>,
    peer_rpc_tspt: Arc<RpcTransport>,

    peer_packet_process_pipeline: Arc<RwLock<Vec<BoxPeerPacketFilter>>>,
    nic_packet_process_pipeline: Arc<RwLock<Vec<BoxNicPacketFilter>>>,

    route_algo_inst: RouteAlgoInst,

    foreign_network_manager: Arc<ForeignNetworkManager>,
    foreign_network_client: Arc<ForeignNetworkClient>,

    encryptor: Arc<dyn Encryptor + 'static>,
    data_compress_algo: CompressorAlgo,

    exit_nodes: Vec<IpAddr>,

    reserved_my_peer_id_map: DashMap<String, PeerId>,

    allow_loopback_tunnel: AtomicBool,

    self_tx_counters: SelfTxCounters,
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
        nic_channel: PacketRecvChan,
    ) -> Self {
        let my_peer_id = rand::random();

        let (packet_send, packet_recv) = create_packet_recv_chan();
        let peers = Arc::new(PeerMap::new(
            packet_send.clone(),
            global_ctx.clone(),
            my_peer_id,
        ));

        let encryptor = if global_ctx.get_flags().enable_encryption {
            // 只有在启用加密时才使用工厂函数选择算法
            let algorithm = &global_ctx.get_flags().encryption_algorithm;
            super::encrypt::create_encryptor(
                algorithm,
                global_ctx.get_128_key(),
                global_ctx.get_256_key(),
            )
        } else {
            // disable_encryption = true 时使用 NullCipher
            Arc::new(NullCipher)
        };

        if global_ctx
            .check_network_in_whitelist(&global_ctx.get_network_name())
            .is_err()
        {
            // if local network is not in whitelist, avoid relay data when exist any other route path
            let mut f = global_ctx.get_feature_flags();
            f.avoid_relay_data = true;
            global_ctx.set_feature_flags(f);
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
        let peer_rpc_mgr = Arc::new(PeerRpcManager::new_with_stats_manager(
            rpc_tspt.clone(),
            global_ctx.stats_manager().clone(),
        ));

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
            Self::build_foreign_network_manager_accessor(&peers),
        ));
        let foreign_network_client = Arc::new(ForeignNetworkClient::new(
            global_ctx.clone(),
            packet_send.clone(),
            peer_rpc_mgr.clone(),
            my_peer_id,
        ));

        let data_compress_algo = global_ctx
            .get_flags()
            .data_compress_algo()
            .try_into()
            .expect("invalid data compress algo, maybe some features not enabled");

        let exit_nodes = global_ctx.config.get_exit_nodes();

        let stats_manager = global_ctx.stats_manager();
        let self_tx_counters = SelfTxCounters {
            self_tx_packets: stats_manager.get_counter(
                MetricName::TrafficPacketsSelfTx,
                LabelSet::new()
                    .with_label_type(LabelType::NetworkName(global_ctx.get_network_name())),
            ),
            self_tx_bytes: stats_manager.get_counter(
                MetricName::TrafficBytesSelfTx,
                LabelSet::new()
                    .with_label_type(LabelType::NetworkName(global_ctx.get_network_name())),
            ),
            compress_tx_bytes_before: stats_manager.get_counter(
                MetricName::CompressionBytesTxBefore,
                LabelSet::new()
                    .with_label_type(LabelType::NetworkName(global_ctx.get_network_name())),
            ),
            compress_tx_bytes_after: stats_manager.get_counter(
                MetricName::CompressionBytesTxAfter,
                LabelSet::new()
                    .with_label_type(LabelType::NetworkName(global_ctx.get_network_name())),
            ),
        };

        PeerManager {
            my_peer_id,

            global_ctx,
            nic_channel,

            tasks: Mutex::new(JoinSet::new()),

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
            data_compress_algo,

            exit_nodes,

            reserved_my_peer_id_map: DashMap::new(),

            allow_loopback_tunnel: AtomicBool::new(true),

            self_tx_counters,
        }
    }

    pub fn set_allow_loopback_tunnel(&self, allow_loopback_tunnel: bool) {
        self.allow_loopback_tunnel
            .store(allow_loopback_tunnel, std::sync::atomic::Ordering::Relaxed);
    }

    fn build_foreign_network_manager_accessor(
        peer_map: &Arc<PeerMap>,
    ) -> Box<dyn GlobalForeignNetworkAccessor> {
        struct T {
            peer_map: Weak<PeerMap>,
        }

        #[async_trait::async_trait]
        impl GlobalForeignNetworkAccessor for T {
            async fn list_global_foreign_peer(
                &self,
                network_identity: &NetworkIdentity,
            ) -> Vec<PeerId> {
                let Some(peer_map) = self.peer_map.upgrade() else {
                    return vec![];
                };

                peer_map
                    .list_peers_own_foreign_network(network_identity)
                    .await
            }
        }

        Box::new(T {
            peer_map: Arc::downgrade(peer_map),
        })
    }

    async fn add_new_peer_conn(&self, peer_conn: PeerConn) -> Result<(), Error> {
        if self.global_ctx.get_network_identity() != peer_conn.get_network_identity() {
            return Err(Error::SecretKeyError(
                "network identity not match".to_string(),
            ));
        }
        self.peers.add_new_peer_conn(peer_conn).await;
        Ok(())
    }

    pub async fn add_client_tunnel(
        &self,
        tunnel: Box<dyn Tunnel>,
        is_directly_connected: bool,
    ) -> Result<(PeerId, PeerConnId), Error> {
        let mut peer = PeerConn::new(self.my_peer_id, self.global_ctx.clone(), tunnel);
        peer.set_is_hole_punched(!is_directly_connected);
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

    pub fn has_directly_connected_conn(&self, peer_id: PeerId) -> bool {
        if let Some(peer) = self.peers.get_peer_by_id(peer_id) {
            peer.has_directly_connected_conn()
        } else {
            self.foreign_network_client.get_peer_map().has_peer(peer_id)
        }
    }

    #[tracing::instrument]
    pub async fn try_direct_connect<C>(
        &self,
        mut connector: C,
    ) -> Result<(PeerId, PeerConnId), Error>
    where
        C: TunnelConnector + Debug,
    {
        let ns = self.global_ctx.net_ns.clone();
        let t = ns
            .run_async(|| async move { connector.connect().await })
            .await?;
        self.add_client_tunnel(t, true).await
    }

    // avoid loop back to virtual network
    fn check_remote_addr_not_from_virtual_network(
        &self,
        tunnel: &dyn Tunnel,
    ) -> Result<(), anyhow::Error> {
        tracing::info!("check remote addr not from virtual network");
        let Some(tunnel_info) = tunnel.info() else {
            anyhow::bail!("tunnel info is not set");
        };
        let Some(src) = tunnel_info.remote_addr.map(url::Url::from) else {
            anyhow::bail!("tunnel info remote addr is not set");
        };
        if src.scheme() == "ring" {
            return Ok(());
        }
        let src_host = match src.socket_addrs(|| Some(1)) {
            Ok(addrs) => addrs,
            Err(_) => {
                // if the tunnel is not rely on ip address, skip check
                return Ok(());
            }
        };
        let virtual_ipv4 = self.global_ctx.get_ipv4().map(|ip| ip.network());
        let virtual_ipv6 = self.global_ctx.get_ipv6().map(|ip| ip.network());
        tracing::info!(
            ?virtual_ipv4,
            ?virtual_ipv6,
            "check remote addr not from virtual network"
        );
        for addr in src_host {
            // if no-tun is enabled, the src ip of packet in virtual network is converted to loopback address
            if addr.ip().is_loopback()
                && !self
                    .allow_loopback_tunnel
                    .load(std::sync::atomic::Ordering::Relaxed)
            {
                anyhow::bail!("tunnel src host is loopback address");
            }

            match addr {
                SocketAddr::V4(addr) => {
                    if let Some(virtual_ipv4) = virtual_ipv4 {
                        if virtual_ipv4.contains(addr.ip()) {
                            anyhow::bail!("tunnel src host is from the virtual network (ignore this error please)");
                        }
                    }
                }
                SocketAddr::V6(addr) => {
                    if let Some(virtual_ipv6) = virtual_ipv6 {
                        if virtual_ipv6.contains(addr.ip()) {
                            anyhow::bail!("tunnel src host is from the virtual network (ignore this error please)");
                        }
                    }
                }
            }
        }
        Ok(())
    }

    #[tracing::instrument(ret)]
    pub async fn add_tunnel_as_server(
        &self,
        tunnel: Box<dyn Tunnel>,
        is_directly_connected: bool,
    ) -> Result<(), Error> {
        tracing::info!("add tunnel as server start");
        self.check_remote_addr_not_from_virtual_network(&tunnel)?;

        let mut conn = PeerConn::new(self.my_peer_id, self.global_ctx.clone(), tunnel);
        conn.do_handshake_as_server_ext(|peer, msg| {
            if msg.network_name
                == self.global_ctx.get_network_identity().network_name
            {
                return Ok(());
            }

            if self.global_ctx.config.get_flags().private_mode {
                return Err(Error::SecretKeyError(
                    "private mode is turned on, network identity not match".to_string(),
                ));
            }

            let mut peer_id = self
                .foreign_network_manager
                .get_network_peer_id(&msg.network_name);
            if peer_id.is_none() {
                peer_id = Some(*self.reserved_my_peer_id_map.entry(msg.network_name.clone()).or_insert_with(|| {
                    rand::random::<PeerId>()
                }).value());
            }
            peer.set_peer_id(peer_id.unwrap());

            tracing::info!(
                ?peer_id,
                ?msg.network_name,
                "handshake as server with foreign network, new peer id: {}, peer id in foreign manager: {:?}",
                peer.get_my_peer_id(), peer_id
            );

            Ok(())
        })
        .await?;

        let peer_network_name = conn.get_network_identity().network_name.clone();

        conn.set_is_hole_punched(!is_directly_connected);

        if peer_network_name == self.global_ctx.get_network_identity().network_name {
            self.add_new_peer_conn(conn).await?;
        } else {
            self.foreign_network_manager.add_peer_conn(conn).await?;
        }

        self.reserved_my_peer_id_map.remove(&peer_network_name);

        tracing::info!("add tunnel as server done");
        Ok(())
    }

    async fn try_handle_foreign_network_packet(
        mut packet: ZCPacket,
        my_peer_id: PeerId,
        peer_map: &PeerMap,
        foreign_network_mgr: &ForeignNetworkManager,
    ) -> Result<(), ZCPacket> {
        let pm_header = packet.peer_manager_header().unwrap();
        if pm_header.packet_type != PacketType::ForeignNetworkPacket as u8 {
            return Err(packet);
        }

        let from_peer_id = pm_header.from_peer_id.get();
        let to_peer_id = pm_header.to_peer_id.get();

        let foreign_hdr = packet.foreign_network_hdr().unwrap();
        let foreign_network_name = foreign_hdr.get_network_name(packet.payload());
        let foreign_peer_id = foreign_hdr.get_dst_peer_id();

        let foreign_network_my_peer_id =
            foreign_network_mgr.get_network_peer_id(&foreign_network_name);

        let buf_len = packet.buf_len();
        let stats_manager = peer_map.get_global_ctx().stats_manager().clone();
        let label_set =
            LabelSet::new().with_label_type(LabelType::NetworkName(foreign_network_name.clone()));
        let add_counter = move |bytes_metric, packets_metric| {
            stats_manager
                .get_counter(bytes_metric, label_set.clone())
                .add(buf_len as u64);
            stats_manager.get_counter(packets_metric, label_set).inc();
        };

        // NOTICE: the to peer id is modified by the src from foreign network my peer id to the origin my peer id
        if to_peer_id == my_peer_id {
            // packet sent from other peer to me, extract the inner packet and forward it
            add_counter(
                MetricName::TrafficBytesForeignForwardRx,
                MetricName::TrafficPacketsForeignForwardRx,
            );
            if let Err(e) = foreign_network_mgr
                .send_msg_to_peer(
                    &foreign_network_name,
                    foreign_peer_id,
                    packet.foreign_network_packet(),
                )
                .await
            {
                tracing::debug!(
                    ?e,
                    ?foreign_network_name,
                    ?foreign_peer_id,
                    "foreign network mgr send_msg_to_peer failed"
                );
            }
            Ok(())
        } else if Some(from_peer_id) == foreign_network_my_peer_id {
            // to_peer_id is my peer id for the foreign network, need to convert to the origin my_peer_id of dst
            let Some(to_peer_id) = peer_map
                .get_origin_my_peer_id(&foreign_network_name, to_peer_id)
                .await
            else {
                tracing::debug!(
                    ?foreign_network_name,
                    ?to_peer_id,
                    "cannot find origin my peer id for foreign network."
                );
                return Err(packet);
            };

            add_counter(
                MetricName::TrafficBytesForeignForwardTx,
                MetricName::TrafficPacketsForeignForwardTx,
            );

            // modify the to_peer id from foreign network my peer id to the origin my peer id
            packet
                .mut_peer_manager_header()
                .unwrap()
                .to_peer_id
                .set(to_peer_id);

            // packet is generated from foreign network mgr and should be forward to other peer
            if let Err(e) = peer_map
                .send_msg(packet, to_peer_id, NextHopPolicy::LeastHop)
                .await
            {
                tracing::debug!(
                    ?e,
                    ?to_peer_id,
                    "send_msg_directly failed when forward local generated foreign network packet"
                );
            }
            Ok(())
        } else {
            // target is not me, forward it. try get origin peer id
            add_counter(
                MetricName::TrafficBytesForeignForwardForwarded,
                MetricName::TrafficPacketsForeignForwardForwarded,
            );
            Err(packet)
        }
    }

    async fn start_peer_recv(&self) {
        let mut recv = self.packet_recv.lock().await.take().unwrap();
        let my_peer_id = self.my_peer_id;
        let peers = self.peers.clone();
        let pipe_line = self.peer_packet_process_pipeline.clone();
        let foreign_client = self.foreign_network_client.clone();
        let foreign_mgr = self.foreign_network_manager.clone();
        let encryptor = self.encryptor.clone();
        let compress_algo = self.data_compress_algo;
        let acl_filter = self.global_ctx.get_acl_filter().clone();
        let global_ctx = self.global_ctx.clone();
        let stats_mgr = self.global_ctx.stats_manager().clone();

        let label_set =
            LabelSet::new().with_label_type(LabelType::NetworkName(global_ctx.get_network_name()));

        let self_tx_bytes = self.self_tx_counters.self_tx_bytes.clone();
        let self_tx_packets = self.self_tx_counters.self_tx_packets.clone();
        let self_rx_bytes =
            stats_mgr.get_counter(MetricName::TrafficBytesSelfRx, label_set.clone());
        let self_rx_packets =
            stats_mgr.get_counter(MetricName::TrafficPacketsSelfRx, label_set.clone());
        let forward_tx_bytes =
            stats_mgr.get_counter(MetricName::TrafficBytesForwarded, label_set.clone());
        let forward_tx_packets =
            stats_mgr.get_counter(MetricName::TrafficPacketsForwarded, label_set.clone());

        let compress_tx_bytes_before = self.self_tx_counters.compress_tx_bytes_before.clone();
        let compress_tx_bytes_after = self.self_tx_counters.compress_tx_bytes_after.clone();
        let compress_rx_bytes_before =
            stats_mgr.get_counter(MetricName::CompressionBytesRxBefore, label_set.clone());
        let compress_rx_bytes_after =
            stats_mgr.get_counter(MetricName::CompressionBytesRxAfter, label_set.clone());

        self.tasks.lock().await.spawn(async move {
            tracing::trace!("start_peer_recv");
            while let Ok(ret) = recv_packet_from_chan(&mut recv).await {
                let Err(mut ret) =
                    Self::try_handle_foreign_network_packet(ret, my_peer_id, &peers, &foreign_mgr)
                        .await
                else {
                    continue;
                };

                let buf_len = ret.buf_len();
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

                    if from_peer_id == my_peer_id {
                        compress_tx_bytes_before.add(buf_len as u64);

                        if hdr.packet_type == PacketType::Data as u8
                            || hdr.packet_type == PacketType::KcpSrc as u8
                            || hdr.packet_type == PacketType::KcpDst as u8
                        {
                            let _ =
                                Self::try_compress_and_encrypt(compress_algo, &encryptor, &mut ret)
                                    .await;
                        }

                        compress_tx_bytes_after.add(ret.buf_len() as u64);
                        self_tx_bytes.add(ret.buf_len() as u64);
                        self_tx_packets.inc();
                    } else {
                        forward_tx_bytes.add(buf_len as u64);
                        forward_tx_packets.inc();
                    }

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

                    self_rx_bytes.add(buf_len as u64);
                    self_rx_packets.inc();
                    compress_rx_bytes_before.add(buf_len as u64);

                    let compressor = DefaultCompressor {};
                    if let Err(e) = compressor.decompress(&mut ret).await {
                        tracing::error!(?e, "decompress failed");
                        continue;
                    }

                    compress_rx_bytes_after.add(ret.buf_len() as u64);

                    if !acl_filter.process_packet_with_acl(
                        &ret,
                        true,
                        global_ctx.get_ipv4().map(|x| x.address()),
                        global_ctx.get_ipv6().map(|x| x.address()),
                    ) {
                        continue;
                    }

                    let mut processed = false;
                    let mut zc_packet = Some(ret);
                    for (idx, pipeline) in pipe_line.read().await.iter().rev().enumerate() {
                        tracing::trace!(?zc_packet, ?idx, "try_process_packet_from_peer");
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
            nic_channel: PacketRecvChan,
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
            foreign_network_manager: Weak<ForeignNetworkManager>,
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

                let mut peers = foreign_client.list_public_peers().await;
                peers.extend(peer_map.list_peers_with_conn().await);
                peers
            }

            fn my_peer_id(&self) -> PeerId {
                self.my_peer_id
            }

            async fn list_foreign_networks(&self) -> ForeignNetworkRouteInfoMap {
                let ret = DashMap::new();
                let Some(foreign_mgr) = self.foreign_network_manager.upgrade() else {
                    return ret;
                };

                let networks = foreign_mgr.list_foreign_networks().await;
                for (network_name, info) in networks.foreign_networks.iter() {
                    if info.peers.is_empty() {
                        continue;
                    }

                    let last_update = foreign_mgr
                        .get_foreign_network_last_update(network_name)
                        .unwrap_or(SystemTime::now());
                    ret.insert(
                        ForeignNetworkRouteInfoKey {
                            peer_id: self.my_peer_id,
                            network_name: network_name.clone(),
                        },
                        ForeignNetworkRouteInfoEntry {
                            foreign_peer_ids: info.peers.iter().map(|x| x.peer_id).collect(),
                            last_update: Some(last_update.into()),
                            version: 0,
                            network_secret_digest: info.network_secret_digest.clone(),
                            my_peer_id_for_this_network: info.my_peer_id_for_this_network,
                        },
                    );
                }
                ret
            }
        }

        let my_peer_id = self.my_peer_id;
        let _route_id = route
            .open(Box::new(Interface {
                my_peer_id,
                peers: Arc::downgrade(&self.peers),
                foreign_network_client: Arc::downgrade(&self.foreign_network_client),
                foreign_network_manager: Arc::downgrade(&self.foreign_network_manager),
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

    pub async fn list_routes(&self) -> Vec<cli::Route> {
        self.get_route().list_routes().await
    }

    pub async fn get_route_peer_info_last_update_time(&self) -> Instant {
        self.get_route().get_peer_info_last_update_time().await
    }

    pub async fn dump_route(&self) -> String {
        self.get_route().dump().await
    }

    pub async fn list_global_foreign_network(&self) -> ListGlobalForeignNetworkResponse {
        let mut resp = ListGlobalForeignNetworkResponse::default();
        let ret = self.get_route().list_foreign_network_info().await;
        for info in ret.infos.iter() {
            let entry = resp
                .foreign_networks
                .entry(info.key.as_ref().unwrap().peer_id)
                .or_insert_with(Default::default);
            let Some(route_info) = info.value.as_ref() else {
                continue;
            };

            let f = OneForeignNetwork {
                network_name: info.key.as_ref().unwrap().network_name.clone(),
                peer_ids: route_info.foreign_peer_ids.clone(),
                last_updated: format!("{}", route_info.last_update.unwrap()),
                version: route_info.version,
            };

            entry.foreign_networks.push(f);
        }

        resp
    }

    async fn run_nic_packet_process_pipeline(&self, data: &mut ZCPacket) {
        if !self
            .global_ctx
            .get_acl_filter()
            .process_packet_with_acl(data, false, None, None)
        {
            return;
        }

        for pipeline in self.nic_packet_process_pipeline.read().await.iter().rev() {
            let _ = pipeline.try_process_packet_from_nic(data).await;
        }
    }

    pub async fn remove_nic_packet_process_pipeline(&self, id: String) -> Result<(), Error> {
        let mut pipelines = self.nic_packet_process_pipeline.write().await;
        if let Some(pos) = pipelines.iter().position(|x| x.id() == id) {
            pipelines.remove(pos);
            Ok(())
        } else {
            Err(Error::NotFound)
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
        self.self_tx_counters
            .self_tx_bytes
            .add(msg.buf_len() as u64);
        self.self_tx_counters.self_tx_packets.inc();
        let msg_len = msg.buf_len() as u64;
        let result =
            Self::send_msg_internal(&self.peers, &self.foreign_network_client, msg, dst_peer_id)
                .await;
        if result.is_ok() {
            self.self_tx_counters.self_tx_bytes.add(msg_len);
            self.self_tx_counters.self_tx_packets.inc();
        }
        result
    }

    async fn send_msg_internal(
        peers: &Arc<PeerMap>,
        foreign_network_client: &Arc<ForeignNetworkClient>,
        msg: ZCPacket,
        dst_peer_id: PeerId,
    ) -> Result<(), Error> {
        let policy =
            Self::get_next_hop_policy(msg.peer_manager_header().unwrap().is_latency_first());

        if let Some(gateway) = peers.get_gateway_peer_id(dst_peer_id, policy.clone()).await {
            if peers.has_peer(gateway) {
                peers.send_msg_directly(msg, gateway).await
            } else if foreign_network_client.has_next_hop(gateway) {
                foreign_network_client.send_msg(msg, gateway).await
            } else {
                tracing::warn!(
                    ?gateway,
                    ?dst_peer_id,
                    "cannot send msg to peer through gateway"
                );
                Err(Error::RouteError(None))
            }
        } else if foreign_network_client.has_next_hop(dst_peer_id) {
            // check foreign network again. so in happy path we can avoid extra check
            foreign_network_client.send_msg(msg, dst_peer_id).await
        } else {
            tracing::debug!(?dst_peer_id, "no gateway for peer");
            Err(Error::RouteError(None))
        }
    }

    pub async fn get_msg_dst_peer(&self, ipv4_addr: &Ipv4Addr) -> (Vec<PeerId>, bool) {
        let mut is_exit_node = false;
        let mut dst_peers = vec![];
        let network_length = self
            .global_ctx
            .get_ipv4()
            .map(|x| x.network_length())
            .unwrap_or(24);
        let ipv4_inet = cidr::Ipv4Inet::new(*ipv4_addr, network_length).unwrap();
        if ipv4_addr.is_broadcast()
            || ipv4_addr.is_multicast()
            || *ipv4_addr == ipv4_inet.last_address()
        {
            dst_peers.extend(self.peers.list_routes().await.iter().map(|x| *x.key()));
        } else if let Some(peer_id) = self.peers.get_peer_id_by_ipv4(ipv4_addr).await {
            dst_peers.push(peer_id);
        } else {
            for exit_node in &self.exit_nodes {
                let IpAddr::V4(exit_node) = exit_node else {
                    continue;
                };
                if let Some(peer_id) = self.peers.get_peer_id_by_ipv4(exit_node).await {
                    dst_peers.push(peer_id);
                    is_exit_node = true;
                    break;
                }
            }
        }
        #[cfg(target_env = "ohos")]
        {
            if dst_peers.is_empty() {
                tracing::info!("no peer id for ipv4: {}, set exit_node for ohos", ipv4_addr);
                dst_peers.push(self.my_peer_id.clone());
                is_exit_node = true;
            }
        }
        (dst_peers, is_exit_node)
    }

    pub async fn get_msg_dst_peer_ipv6(&self, ipv6_addr: &Ipv6Addr) -> (Vec<PeerId>, bool) {
        let mut is_exit_node = false;
        let mut dst_peers = vec![];
        let network_length = self
            .global_ctx
            .get_ipv6()
            .map(|x| x.network_length())
            .unwrap_or(64);
        let ipv6_inet = cidr::Ipv6Inet::new(*ipv6_addr, network_length).unwrap();
        if ipv6_addr.is_multicast() || *ipv6_addr == ipv6_inet.last_address() {
            dst_peers.extend(self.peers.list_routes().await.iter().map(|x| *x.key()));
        } else if let Some(peer_id) = self.peers.get_peer_id_by_ipv6(ipv6_addr).await {
            dst_peers.push(peer_id);
        } else if !ipv6_addr.is_unicast_link_local() {
            // NOTE: never route link local address to exit node.
            for exit_node in &self.exit_nodes {
                let IpAddr::V6(exit_node) = exit_node else {
                    continue;
                };
                if let Some(peer_id) = self.peers.get_peer_id_by_ipv6(exit_node).await {
                    dst_peers.push(peer_id);
                    is_exit_node = true;
                    break;
                }
            }
        }

        (dst_peers, is_exit_node)
    }

    pub async fn try_compress_and_encrypt(
        compress_algo: CompressorAlgo,
        encryptor: &Arc<dyn Encryptor + 'static>,
        msg: &mut ZCPacket,
    ) -> Result<(), Error> {
        let compressor = DefaultCompressor {};
        compressor
            .compress(msg, compress_algo)
            .await
            .with_context(|| "compress failed")?;
        encryptor.encrypt(msg).with_context(|| "encrypt failed")?;
        Ok(())
    }

    pub async fn send_msg_by_ip(&self, mut msg: ZCPacket, ip_addr: IpAddr) -> Result<(), Error> {
        tracing::trace!(
            "do send_msg in peer manager, msg: {:?}, ip_addr: {}",
            msg,
            ip_addr
        );

        msg.fill_peer_manager_hdr(
            self.my_peer_id,
            0,
            tunnel::packet_def::PacketType::Data as u8,
        );
        self.run_nic_packet_process_pipeline(&mut msg).await;
        let cur_to_peer_id = msg.peer_manager_header().unwrap().to_peer_id.into();
        if cur_to_peer_id != 0 {
            return Self::send_msg_internal(
                &self.peers,
                &self.foreign_network_client,
                msg,
                cur_to_peer_id,
            )
            .await;
        }

        let (dst_peers, is_exit_node) = match ip_addr {
            IpAddr::V4(ipv4_addr) => self.get_msg_dst_peer(&ipv4_addr).await,
            IpAddr::V6(ipv6_addr) => self.get_msg_dst_peer_ipv6(&ipv6_addr).await,
        };

        if dst_peers.is_empty() {
            tracing::info!("no peer id for ip: {}", ip_addr);
            return Ok(());
        }

        self.self_tx_counters
            .compress_tx_bytes_before
            .add(msg.buf_len() as u64);

        Self::try_compress_and_encrypt(self.data_compress_algo, &self.encryptor, &mut msg).await?;

        self.self_tx_counters
            .compress_tx_bytes_after
            .add(msg.buf_len() as u64);

        let is_latency_first = self.global_ctx.get_flags().latency_first;
        msg.mut_peer_manager_header()
            .unwrap()
            .set_latency_first(is_latency_first)
            .set_exit_node(is_exit_node);

        let mut errs: Vec<Error> = vec![];
        let mut msg = Some(msg);
        let total_dst_peers = dst_peers.len();
        for (i, peer_id) in dst_peers.iter().enumerate() {
            let mut msg = if i == total_dst_peers - 1 {
                msg.take().unwrap()
            } else {
                msg.clone().unwrap()
            };

            msg.mut_peer_manager_header()
                .unwrap()
                .to_peer_id
                .set(*peer_id);

            self.self_tx_counters
                .self_tx_bytes
                .add(msg.buf_len() as u64);
            self.self_tx_counters.self_tx_packets.inc();

            if let Err(e) =
                Self::send_msg_internal(&self.peers, &self.foreign_network_client, msg, *peer_id)
                    .await
            {
                errs.push(e);
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

    pub fn get_nic_channel(&self) -> PacketRecvChan {
        self.nic_channel.clone()
    }

    pub fn get_foreign_network_manager(&self) -> Arc<ForeignNetworkManager> {
        self.foreign_network_manager.clone()
    }

    pub fn get_foreign_network_client(&self) -> Arc<ForeignNetworkClient> {
        self.foreign_network_client.clone()
    }

    pub async fn get_my_info(&self) -> cli::NodeInfo {
        cli::NodeInfo {
            peer_id: self.my_peer_id,
            ipv4_addr: self
                .global_ctx
                .get_ipv4()
                .map(|x| x.to_string())
                .unwrap_or_default(),
            proxy_cidrs: self
                .global_ctx
                .config
                .get_proxy_cidrs()
                .into_iter()
                .map(|x| {
                    if x.mapped_cidr.is_none() {
                        x.cidr.to_string()
                    } else {
                        format!("{}->{}", x.cidr, x.mapped_cidr.unwrap())
                    }
                })
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
            version: EASYTIER_VERSION.to_string(),
            feature_flag: Some(self.global_ctx.get_feature_flags()),
            ip_list: Some(self.global_ctx.get_ip_collector().collect_ip_addrs().await),
        }
    }

    pub async fn wait(&self) {
        while !self.tasks.lock().await.is_empty() {
            tokio::time::sleep(std::time::Duration::from_secs(1)).await;
        }
    }

    pub async fn clear_resources(&self) {
        let mut peer_pipeline = self.peer_packet_process_pipeline.write().await;
        peer_pipeline.clear();
        let mut nic_pipeline = self.nic_packet_process_pipeline.write().await;
        nic_pipeline.clear();

        self.peer_rpc_mgr.rpc_server().registry().unregister_all();
    }

    pub async fn close_peer_conn(
        &self,
        peer_id: PeerId,
        conn_id: &PeerConnId,
    ) -> Result<(), Error> {
        let ret = self.peers.close_peer_conn(peer_id, conn_id).await;
        tracing::info!("close_peer_conn in peer map: {:?}", ret);
        if ret.is_ok() || !matches!(ret.as_ref().unwrap_err(), Error::NotFound) {
            return ret;
        }

        let ret = self
            .foreign_network_client
            .get_peer_map()
            .close_peer_conn(peer_id, conn_id)
            .await;
        tracing::info!("close_peer_conn in foreign network client: {:?}", ret);
        if ret.is_ok() || !matches!(ret.as_ref().unwrap_err(), Error::NotFound) {
            return ret;
        }

        let ret = self
            .foreign_network_manager
            .close_peer_conn(peer_id, conn_id)
            .await;
        tracing::info!("close_peer_conn in foreign network manager done: {:?}", ret);
        ret
    }

    pub async fn check_allow_kcp_to_dst(&self, dst_ip: &IpAddr) -> bool {
        let route = self.get_route();
        let Some(dst_peer_id) = route.get_peer_id_by_ip(dst_ip).await else {
            return false;
        };
        let Some(peer_info) = route.get_peer_info(dst_peer_id).await else {
            return false;
        };

        // check dst allow kcp input
        if !peer_info.feature_flag.map(|x| x.kcp_input).unwrap_or(false) {
            return false;
        }

        let next_hop_policy = Self::get_next_hop_policy(self.global_ctx.get_flags().latency_first);
        // check relay node allow relay kcp.
        let Some(next_hop_id) = route
            .get_next_hop_with_policy(dst_peer_id, next_hop_policy)
            .await
        else {
            return false;
        };

        let Some(next_hop_info) = route.get_peer_info(next_hop_id).await else {
            return false;
        };

        // check next hop allow kcp relay
        if next_hop_info
            .feature_flag
            .map(|x| x.no_relay_kcp)
            .unwrap_or(false)
        {
            return false;
        }

        true
    }
}

#[cfg(test)]
mod tests {

    use std::{fmt::Debug, sync::Arc, time::Duration};

    use crate::{
        common::{config::Flags, global_ctx::tests::get_mock_global_ctx},
        connector::{
            create_connector_by_url, direct::PeerManagerForDirectConnector,
            udp_hole_punch::tests::create_mock_peer_manager_with_mock_stun,
        },
        instance::listeners::get_listener_by_url,
        peers::{
            create_packet_recv_chan,
            peer_manager::RouteAlgoType,
            peer_rpc::tests::register_service,
            route_trait::NextHopPolicy,
            tests::{
                connect_peer_manager, create_mock_peer_manager_with_name, wait_route_appear,
                wait_route_appear_with_cost,
            },
        },
        proto::common::{CompressionAlgoPb, NatType, PeerFeatureFlag},
        tunnel::{
            common::tests::wait_for_condition,
            filter::{tests::DropSendTunnelFilter, TunnelWithFilter},
            ring::create_ring_tunnel_pair,
            TunnelConnector, TunnelListener,
        },
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
            client_mgr.try_direct_connect(client).await.unwrap();
        });

        server_mgr
            .add_client_tunnel(server.accept().await.unwrap(), false)
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
        use crate::proto::{
            rpc_impl::RpcController,
            tests::{GreetingClientFactory, SayHelloRequest},
        };

        let peer_mgr_a = create_mock_peer_manager_with_mock_stun(NatType::Unknown).await;
        register_service(&peer_mgr_a.peer_rpc_mgr, "", 0, "hello a");

        let peer_mgr_b = create_mock_peer_manager_with_mock_stun(NatType::Unknown).await;

        let peer_mgr_c = create_mock_peer_manager_with_mock_stun(NatType::Unknown).await;
        register_service(&peer_mgr_c.peer_rpc_mgr, "", 0, "hello c");

        let mut listener1 = get_listener_by_url(
            &format!("{}://0.0.0.0:31013", proto1).parse().unwrap(),
            peer_mgr_b.get_global_ctx(),
        )
        .unwrap();
        let connector1 = create_connector_by_url(
            format!("{}://127.0.0.1:31013", proto1).as_str(),
            &peer_mgr_a.get_global_ctx(),
            crate::tunnel::IpVersion::Both,
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
            crate::tunnel::IpVersion::Both,
        )
        .await
        .unwrap();
        connect_peer_manager_with(peer_mgr_b.clone(), &peer_mgr_c, connector2, &mut listener2)
            .await;

        wait_route_appear(peer_mgr_a.clone(), peer_mgr_c.clone())
            .await
            .unwrap();

        let stub = peer_mgr_a
            .peer_rpc_mgr
            .rpc_client()
            .scoped_client::<GreetingClientFactory<RpcController>>(
                peer_mgr_a.my_peer_id,
                peer_mgr_c.my_peer_id,
                "".to_string(),
            );

        let ret = stub
            .say_hello(
                RpcController::default(),
                SayHelloRequest {
                    name: "abc".to_string(),
                },
            )
            .await
            .unwrap();

        assert_eq!(ret.greeting, "hello c abc!");
    }

    #[tokio::test]
    async fn communicate_between_enc_and_non_enc() {
        let create_mgr = |enable_encryption| async move {
            let (s, _r) = create_packet_recv_chan();
            let mock_global_ctx = get_mock_global_ctx();
            mock_global_ctx.config.set_flags(Flags {
                enable_encryption,
                data_compress_algo: CompressionAlgoPb::Zstd.into(),
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

    #[tokio::test]
    async fn test_avoid_relay_data() {
        // a->b->c
        // a->d->e->c
        let peer_mgr_a = create_mock_peer_manager_with_mock_stun(NatType::Unknown).await;
        let peer_mgr_b = create_mock_peer_manager_with_mock_stun(NatType::Unknown).await;
        let peer_mgr_c = create_mock_peer_manager_with_mock_stun(NatType::Unknown).await;
        let peer_mgr_d = create_mock_peer_manager_with_mock_stun(NatType::Unknown).await;
        let peer_mgr_e = create_mock_peer_manager_with_mock_stun(NatType::Unknown).await;

        println!("peer_mgr_a: {}", peer_mgr_a.my_peer_id);
        println!("peer_mgr_b: {}", peer_mgr_b.my_peer_id);
        println!("peer_mgr_c: {}", peer_mgr_c.my_peer_id);
        println!("peer_mgr_d: {}", peer_mgr_d.my_peer_id);
        println!("peer_mgr_e: {}", peer_mgr_e.my_peer_id);

        connect_peer_manager(peer_mgr_a.clone(), peer_mgr_b.clone()).await;
        connect_peer_manager(peer_mgr_b.clone(), peer_mgr_c.clone()).await;

        connect_peer_manager(peer_mgr_a.clone(), peer_mgr_d.clone()).await;
        connect_peer_manager(peer_mgr_d.clone(), peer_mgr_e.clone()).await;
        connect_peer_manager(peer_mgr_e.clone(), peer_mgr_c.clone()).await;

        // when b's avoid_relay_data is false, a->c should route through b and cost is 2
        wait_route_appear_with_cost(peer_mgr_a.clone(), peer_mgr_c.my_peer_id, Some(2))
            .await
            .unwrap();
        let ret = peer_mgr_a
            .get_route()
            .get_next_hop_with_policy(peer_mgr_c.my_peer_id, NextHopPolicy::LeastCost)
            .await;
        assert_eq!(ret, Some(peer_mgr_b.my_peer_id));

        // when b's avoid_relay_data is true, a->c should route through d and e, cost is 3
        peer_mgr_b
            .get_global_ctx()
            .set_feature_flags(PeerFeatureFlag {
                avoid_relay_data: true,
                ..Default::default()
            });
        tokio::time::sleep(Duration::from_secs(2)).await;
        if wait_route_appear_with_cost(peer_mgr_a.clone(), peer_mgr_c.my_peer_id, Some(3))
            .await
            .is_err()
        {
            panic!(
                "route not appear, a route table: {}, table: {:#?}",
                peer_mgr_a.get_route().dump().await,
                peer_mgr_a.get_route().list_routes().await
            )
        }

        let ret = peer_mgr_a
            .get_route()
            .get_next_hop_with_policy(peer_mgr_c.my_peer_id, NextHopPolicy::LeastCost)
            .await;
        assert_eq!(ret, Some(peer_mgr_d.my_peer_id));

        println!("route table: {:#?}", peer_mgr_a.list_routes().await);

        // drop e, path should go back to through b
        drop(peer_mgr_e);
        wait_route_appear_with_cost(peer_mgr_a.clone(), peer_mgr_c.my_peer_id, Some(2))
            .await
            .unwrap();
        let ret = peer_mgr_a
            .get_route()
            .get_next_hop_with_policy(peer_mgr_c.my_peer_id, NextHopPolicy::LeastCost)
            .await;
        assert_eq!(ret, Some(peer_mgr_b.my_peer_id));
    }

    #[tokio::test]
    async fn test_client_inbound_blackhole() {
        let peer_mgr_a = create_mock_peer_manager_with_mock_stun(NatType::Unknown).await;
        let peer_mgr_b = create_mock_peer_manager_with_mock_stun(NatType::Unknown).await;

        // a is client, b is server

        let (a_ring, b_ring) = create_ring_tunnel_pair();
        let a_ring = Box::new(TunnelWithFilter::new(
            a_ring,
            DropSendTunnelFilter::new(2, 50000),
        ));

        let a_mgr_copy = peer_mgr_a.clone();
        tokio::spawn(async move {
            a_mgr_copy.add_client_tunnel(a_ring, false).await.unwrap();
        });
        let b_mgr_copy = peer_mgr_b.clone();
        tokio::spawn(async move {
            b_mgr_copy.add_tunnel_as_server(b_ring, true).await.unwrap();
        });

        wait_for_condition(
            || async {
                let peers = peer_mgr_a.list_peers().await;
                peers.is_empty()
            },
            Duration::from_secs(10),
        )
        .await;
    }

    #[tokio::test]
    async fn close_conn_in_peer_map() {
        let peer_mgr_a = create_mock_peer_manager_with_mock_stun(NatType::Unknown).await;
        let peer_mgr_b = create_mock_peer_manager_with_mock_stun(NatType::Unknown).await;
        connect_peer_manager(peer_mgr_a.clone(), peer_mgr_b.clone()).await;
        wait_route_appear(peer_mgr_a.clone(), peer_mgr_b.clone())
            .await
            .unwrap();

        let conns = peer_mgr_a
            .get_peer_map()
            .list_peer_conns(peer_mgr_b.my_peer_id)
            .await;
        assert!(conns.is_some());
        let conn_info = conns.as_ref().unwrap().first().unwrap();

        peer_mgr_a
            .close_peer_conn(peer_mgr_b.my_peer_id, &conn_info.conn_id.parse().unwrap())
            .await
            .unwrap();

        wait_for_condition(
            || async {
                let peers = peer_mgr_a.list_peers().await;
                peers.is_empty()
            },
            Duration::from_secs(10),
        )
        .await;
        // a is client, b is server
    }

    #[tokio::test]
    async fn close_conn_in_foreign_network_client() {
        let peer_mgr_server = create_mock_peer_manager_with_name("server".to_string()).await;
        let peer_mgr_client = create_mock_peer_manager_with_name("client".to_string()).await;
        connect_peer_manager(peer_mgr_client.clone(), peer_mgr_server.clone()).await;
        wait_for_condition(
            || async {
                peer_mgr_client
                    .get_foreign_network_client()
                    .list_public_peers()
                    .await
                    .len()
                    == 1
            },
            Duration::from_secs(3),
        )
        .await;

        let peer_id = peer_mgr_client
            .foreign_network_client
            .list_public_peers()
            .await[0];
        let conns = peer_mgr_client
            .foreign_network_client
            .get_peer_map()
            .list_peer_conns(peer_id)
            .await;
        assert!(conns.is_some());
        let conn_info = conns.as_ref().unwrap().first().unwrap();
        peer_mgr_client
            .close_peer_conn(peer_id, &conn_info.conn_id.parse().unwrap())
            .await
            .unwrap();

        wait_for_condition(
            || async {
                peer_mgr_client
                    .get_foreign_network_client()
                    .list_public_peers()
                    .await
                    .is_empty()
            },
            Duration::from_secs(10),
        )
        .await;
    }

    #[tokio::test]
    async fn close_conn_in_foreign_network_manager() {
        let peer_mgr_server = create_mock_peer_manager_with_name("server".to_string()).await;
        let peer_mgr_client = create_mock_peer_manager_with_name("client".to_string()).await;
        connect_peer_manager(peer_mgr_client.clone(), peer_mgr_server.clone()).await;
        wait_for_condition(
            || async {
                peer_mgr_client
                    .get_foreign_network_client()
                    .list_public_peers()
                    .await
                    .len()
                    == 1
            },
            Duration::from_secs(3),
        )
        .await;

        let conns = peer_mgr_server
            .foreign_network_manager
            .list_foreign_networks()
            .await;
        let client_info = conns.foreign_networks["client"].peers[0].clone();
        let conn_info = client_info.conns[0].clone();
        peer_mgr_server
            .close_peer_conn(client_info.peer_id, &conn_info.conn_id.parse().unwrap())
            .await
            .unwrap();

        wait_for_condition(
            || async {
                peer_mgr_client
                    .get_foreign_network_client()
                    .list_public_peers()
                    .await
                    .is_empty()
            },
            Duration::from_secs(10),
        )
        .await;
    }
}
