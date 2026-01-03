use crate::common::global_ctx::GlobalCtx;
use crate::common::PeerId;
use crate::gateway::kcp_proxy::TcpProxyForKcpSrcTrait;
use crate::gateway::quic::{
    QuicController, QuicEndpoint, QuicPacket, QuicPacketRx, QuicStream, QuicStreamRx,
};
use crate::gateway::tcp_proxy::{NatDstConnector, TcpProxy};
use crate::gateway::CidrSet;
use crate::peers::peer_manager::PeerManager;
use crate::peers::PeerPacketFilter;
use crate::proto::api::instance::{TcpProxyEntry, TcpProxyEntryTransportType};
use crate::proto::peer_rpc::KcpConnData;
use crate::tunnel::packet_def::{PacketType, PeerManagerHeader, ZCPacket, ZCPacketType};
use anyhow::{anyhow, Context, Error};
use bytes::{BufMut, Bytes, BytesMut};
use dashmap::DashMap;
use pnet::packet::ipv4::Ipv4Packet;
use prost::Message;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::{Arc, Weak};
use std::time::Duration;
use tokio::io::AsyncWriteExt;
use tokio::select;
use tokio::task::JoinSet;
use tracing::error;

#[derive(Debug)]
struct QuicPacketMeta {
    peer_id: PeerId,
    packet_type: PacketType,
}

impl QuicPacketMeta {
    fn new(peer_id: PeerId, packet_type: PacketType) -> Self {
        Self {
            peer_id,
            packet_type,
        }
    }

    fn pack(self, data: BytesMut) -> QuicPacket {
        QuicPacket {
            addr: self.into(),
            payload: data,
        }
    }

    fn unpack(packet: QuicPacket) -> Option<(Self, BytesMut)> {
        let packet_info = packet.addr.try_into().ok()?;
        Some((packet_info, packet.payload))
    }
}

impl From<QuicPacketMeta> for SocketAddr {
    fn from(meta: QuicPacketMeta) -> Self {
        SocketAddr::new(IpAddr::V4(meta.peer_id.into()), meta.packet_type as u16)
    }
}

impl TryFrom<SocketAddr> for QuicPacketMeta {
    type Error = ();

    fn try_from(value: SocketAddr) -> Result<Self, Self::Error> {
        let IpAddr::V4(ipv4) = value.ip() else {
            return Err(());
        };
        let peer_id = ipv4.into();

        let packet_type = match value.port() {
            p if p == PacketType::QuicSrc as u16 => PacketType::QuicSrc,
            p if p == PacketType::QuicDst as u16 => PacketType::QuicDst,
            _ => return Err(()),
        };

        Ok(Self {
            peer_id,
            packet_type,
        })
    }
}

#[derive(Debug)]
enum QuicProxyRole {
    Src,
    Dst,
}

impl QuicProxyRole {
    const fn incoming(&self) -> PacketType {
        match self {
            QuicProxyRole::Src => PacketType::QuicDst,
            QuicProxyRole::Dst => PacketType::QuicSrc,
        }
    }
    const fn outgoing(&self) -> PacketType {
        match self {
            QuicProxyRole::Src => PacketType::QuicSrc,
            QuicProxyRole::Dst => PacketType::QuicDst,
        }
    }
}

// Receive packets from peers and forward them to the QUIC endpoint
#[derive(Debug)]
struct QuicPacketReceiver {
    quic_ctrl: Arc<QuicController>,
    role: QuicProxyRole,
}

#[async_trait::async_trait]
impl PeerPacketFilter for QuicPacketReceiver {
    async fn try_process_packet_from_peer(&self, packet: ZCPacket) -> Option<ZCPacket> {
        let header = packet.peer_manager_header().unwrap();

        if header.packet_type != self.role.incoming() as u8 {
            return Some(packet);
        }

        let _ = self
            .quic_ctrl
            .send(
                QuicPacketMeta::new(header.from_peer_id.get().into(), self.role.outgoing())
                    .pack(packet.payload_bytes()),
            )
            .await;

        None
    }
}

// Receive packets from QUIC endpoint and forward them to peers
#[derive(Debug)]
struct QuicPacketSender {
    peer_mgr: Arc<PeerManager>,
    packet_rx: QuicPacketRx,

    header: Bytes,
    zc_packet_type: ZCPacketType,
}

impl QuicPacketSender {
    #[tracing::instrument]
    pub async fn run(&mut self) {
        while let Some(packet) = self.packet_rx.recv().await {
            let (packet_info, mut payload) = QuicPacketMeta::unpack(packet).unwrap();

            payload[..self.header.len()].copy_from_slice(&*self.header);
            let mut packet = ZCPacket::new_from_buf(payload, self.zc_packet_type);

            let peer_id = packet_info.peer_id;
            let packet_type = packet_info.packet_type;
            packet.fill_peer_manager_hdr(self.peer_mgr.my_peer_id(), peer_id, packet_type as u8);

            if let Err(e) = self.peer_mgr.send_msg_for_proxy(packet, peer_id).await {
                error!("failed to send QUIC packet to peer: {:?}", e);
            }
        }
    }
}

type QuicConnData = KcpConnData;

#[derive(Debug, Clone)]
pub struct NatDstQuicConnector {
    pub(crate) quic_ctrl: Arc<QuicController>,
    pub(crate) peer_mgr: Weak<PeerManager>,
}

#[async_trait::async_trait]
impl NatDstConnector for NatDstQuicConnector {
    type DstStream = QuicStream;

    async fn connect(
        &self,
        src: SocketAddr,
        nat_dst: SocketAddr,
    ) -> crate::common::error::Result<Self::DstStream> {
        let Some(peer_mgr) = self.peer_mgr.upgrade() else {
            return Err(anyhow::anyhow!("peer manager is not available").into());
        };

        let Some(dst_peer_id) = (match nat_dst {
            SocketAddr::V4(addr) => peer_mgr.get_peer_map().get_peer_id_by_ipv4(addr.ip()).await,
            SocketAddr::V6(_) => return Err(anyhow::anyhow!("ipv6 is not supported").into()),
        }) else {
            return Err(anyhow::anyhow!("no peer found for nat dst: {}", nat_dst).into());
        };

        tracing::trace!("kcp nat dst: {:?}, dst peers: {:?}", nat_dst, dst_peer_id);

        let header = {
            let conn_data = QuicConnData {
                src: Some(src.into()),
                dst: Some(nat_dst.into()),
            };

            let len = conn_data.encoded_len();
            if len > (u16::MAX as usize) {
                return Err(anyhow!("conn data too large: {:?}", len).into());
            }

            let mut buf = BytesMut::with_capacity(2 + len);

            buf.put_u16(len as u16);
            conn_data.encode(&mut buf).unwrap();

            buf.freeze()
        };

        let mut connect_tasks: JoinSet<Result<QuicStream, Error>> = JoinSet::new();
        let mut retry_remain = 5;
        loop {
            select! {
                Some(Ok(Ok(stream))) = connect_tasks.join_next() => {
                    // just wait for the previous connection to finish
                    return Ok(stream);
                }
                _ = tokio::time::sleep(Duration::from_millis(200)), if !connect_tasks.is_empty() && retry_remain > 0 => {
                    // no successful connection yet, trigger another connection attempt
                }
                else => {
                    // got error in connect_tasks, continue to retry
                    if retry_remain == 0 && connect_tasks.is_empty() {
                        break;
                    }
                }
            }

            // create a new connection task
            if retry_remain == 0 {
                continue;
            }
            retry_remain -= 1;

            let quic_ctrl = self.quic_ctrl.clone();
            let conn_data = header.clone();

            connect_tasks.spawn(async move {
                let mut stream = quic_ctrl
                    .connect(QuicPacketMeta::new(dst_peer_id, PacketType::QuicSrc).into())
                    .await
                    .with_context(|| format!("failed to connect to nat dst: {}", nat_dst))?;

                stream.write_all(&conn_data).await?;

                Ok(stream)
            });
        }

        Err(anyhow!("failed to connect to nat dst: {}", nat_dst).into())
    }

    fn check_packet_from_peer_fast(&self, _cidr_set: &CidrSet, _global_ctx: &GlobalCtx) -> bool {
        true
    }

    fn check_packet_from_peer(
        &self,
        _cidr_set: &CidrSet,
        _global_ctx: &GlobalCtx,
        hdr: &PeerManagerHeader,
        _ipv4: &Ipv4Packet,
        _real_dst_ip: &mut Ipv4Addr,
    ) -> bool {
        hdr.from_peer_id == hdr.to_peer_id && hdr.is_kcp_src_modified()
    } //TODO: Can we use the same flag?

    fn transport_type(&self) -> TcpProxyEntryTransportType {
        TcpProxyEntryTransportType::Quic
    }
}

#[derive(Clone)]
struct TcpProxyForQuicSrc(Arc<TcpProxy<NatDstQuicConnector>>);

//TODO: rename & move this trait
#[async_trait::async_trait]
impl TcpProxyForKcpSrcTrait for TcpProxyForQuicSrc {
    type Connector = NatDstQuicConnector;

    fn get_tcp_proxy(&self) -> &Arc<TcpProxy<Self::Connector>> {
        &self.0
    }

    async fn check_dst_allow_kcp_input(&self, dst_ip: &Ipv4Addr) -> bool {
        self.0
            .get_peer_manager()
            .check_allow_quic_to_dst(&IpAddr::V4(*dst_ip))
            .await
    }
}

pub struct QuicProxy {
    endpoint: QuicEndpoint,
    peer_mgr: Arc<PeerManager>,

    src: Option<QuicProxySrc>,
    dst: Option<QuicProxyDst>,
    stream_rx: Option<QuicStreamRx>,

    tasks: JoinSet<()>,
}

impl QuicProxy {
    pub fn new(peer_mgr: Arc<PeerManager>) -> Self {
        let (header, zc_packet_type) = {
            let header = ZCPacket::new_with_payload(&[]);
            let zc_packet_type = header.packet_type();
            let payload_offset = header.payload_offset();
            (
                header.inner().split_to(payload_offset).freeze(),
                zc_packet_type,
            )
        };

        let mut endpoint = QuicEndpoint::new();
        let (packet_rx, stream_rx) = endpoint
            .run((header.len(), 0).into())
            .expect("failed to start quic endpoint");

        let mut tasks = JoinSet::new();
        {
            let peer_mgr = peer_mgr.clone();
            tasks.spawn(async move {
                QuicPacketSender {
                    peer_mgr,
                    packet_rx,
                    header,
                    zc_packet_type,
                }
                .run()
                .await;
            });
        }

        Self {
            endpoint: QuicEndpoint::new(),
            peer_mgr,
            src: None,
            dst: None,
            stream_rx: Some(stream_rx),
            tasks,
        }
    }

    pub fn run_src(&mut self) -> QuicProxySrc {
        let quic_ctrl = self.endpoint.ctrl().unwrap();
        let peer_mgr = self.peer_mgr.clone();

        let tcp_proxy = TcpProxyForQuicSrc(TcpProxy::new(
            peer_mgr.clone(),
            NatDstQuicConnector {
                quic_ctrl: quic_ctrl.clone(),
                peer_mgr: Arc::downgrade(&peer_mgr),
            },
        ));

        let src = QuicProxySrc {
            quic_ctrl,
            peer_mgr,

            tcp_proxy,
            tasks: JoinSet::new(),
        };

        src
    }
}

pub struct QuicProxySrc {
    quic_ctrl: Arc<QuicController>,
    peer_mgr: Arc<PeerManager>,

    tcp_proxy: TcpProxyForQuicSrc,
    tasks: JoinSet<()>,
}

pub struct QuicProxyDst {
    quic_ctrl: Arc<QuicController>,
    peer_mgr: Arc<PeerManager>,

    proxy_entries: Arc<DashMap<QuicStream, TcpProxyEntry>>,
    cidr_set: Arc<CidrSet>,
    tasks: JoinSet<()>,
}
