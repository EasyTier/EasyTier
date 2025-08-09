use std::{
    net::{IpAddr, Ipv4Addr, SocketAddr},
    sync::{Arc, Weak},
    time::Duration,
};

use anyhow::Context;
use bytes::Bytes;
use dashmap::DashMap;
use kcp_sys::{
    endpoint::{ConnId, KcpEndpoint, KcpPacketReceiver},
    ffi_safe::KcpConfig,
    packet_def::KcpPacket,
    stream::KcpStream,
};
use pnet::packet::{
    ip::IpNextHeaderProtocols,
    ipv4::Ipv4Packet,
    tcp::{TcpFlags, TcpPacket},
    Packet as _,
};
use prost::Message;
use tokio::{
    io::{copy_bidirectional, AsyncRead, AsyncWrite},
    select,
    task::JoinSet,
};
use tokio_util::io::InspectReader;

use super::{
    tcp_proxy::{NatDstConnector, NatDstTcpConnector, TcpProxy},
    CidrSet,
};
use crate::{
    common::{
        acl_processor::PacketInfo,
        error::Result,
        global_ctx::{ArcGlobalCtx, GlobalCtx},
    },
    peers::{acl_filter::AclFilter, peer_manager::PeerManager, NicPacketFilter, PeerPacketFilter},
    proto::{
        acl::{Action, ChainType, Protocol},
        cli::{
            ListTcpProxyEntryRequest, ListTcpProxyEntryResponse, TcpProxyEntry, TcpProxyEntryState,
            TcpProxyEntryTransportType, TcpProxyRpc,
        },
        peer_rpc::KcpConnData,
        rpc_types::{self, controller::BaseController},
    },
    tunnel::packet_def::{PacketType, PeerManagerHeader, ZCPacket},
};

fn create_kcp_endpoint() -> KcpEndpoint {
    let mut kcp_endpoint = KcpEndpoint::new();
    kcp_endpoint.set_kcp_config_factory(Box::new(|conv| {
        let mut cfg = KcpConfig::new_turbo(conv);
        cfg.interval = Some(5);
        cfg
    }));
    kcp_endpoint
}

struct KcpEndpointFilter {
    kcp_endpoint: Arc<KcpEndpoint>,
    is_src: bool,
}

#[async_trait::async_trait]
impl PeerPacketFilter for KcpEndpointFilter {
    async fn try_process_packet_from_peer(&self, packet: ZCPacket) -> Option<ZCPacket> {
        let t = packet.peer_manager_header().unwrap().packet_type;
        if t == PacketType::KcpSrc as u8 && !self.is_src {
        } else if t == PacketType::KcpDst as u8 && self.is_src {
        } else {
            return Some(packet);
        }

        let _ = self
            .kcp_endpoint
            .input_sender_ref()
            .send(KcpPacket::from(packet.payload_bytes()))
            .await;

        None
    }
}

#[tracing::instrument]
async fn handle_kcp_output(
    peer_mgr: Arc<PeerManager>,
    mut output_receiver: KcpPacketReceiver,
    is_src: bool,
) {
    while let Some(packet) = output_receiver.recv().await {
        let dst_peer_id = if is_src {
            packet.header().dst_session_id()
        } else {
            packet.header().src_session_id()
        };
        let packet_type = if is_src {
            PacketType::KcpSrc as u8
        } else {
            PacketType::KcpDst as u8
        };
        let mut packet = ZCPacket::new_with_payload(&packet.inner().freeze());
        packet.fill_peer_manager_hdr(peer_mgr.my_peer_id(), dst_peer_id, packet_type as u8);

        if let Err(e) = peer_mgr.send_msg(packet, dst_peer_id).await {
            tracing::error!("failed to send kcp packet to peer: {:?}", e);
        }
    }
}

#[derive(Debug, Clone)]
pub struct NatDstKcpConnector {
    pub(crate) kcp_endpoint: Arc<KcpEndpoint>,
    pub(crate) peer_mgr: Weak<PeerManager>,
}

#[async_trait::async_trait]
impl NatDstConnector for NatDstKcpConnector {
    type DstStream = KcpStream;

    async fn connect(&self, src: SocketAddr, nat_dst: SocketAddr) -> Result<Self::DstStream> {
        let conn_data = KcpConnData {
            src: Some(src.into()),
            dst: Some(nat_dst.into()),
        };

        let Some(peer_mgr) = self.peer_mgr.upgrade() else {
            return Err(anyhow::anyhow!("peer manager is not available").into());
        };

        let dst_peer_id = match nat_dst {
            SocketAddr::V4(addr) => peer_mgr.get_peer_map().get_peer_id_by_ipv4(addr.ip()).await,
            SocketAddr::V6(_) => return Err(anyhow::anyhow!("ipv6 is not supported").into()),
        };

        let Some(dst_peer) = dst_peer_id else {
            return Err(anyhow::anyhow!("no peer found for nat dst: {}", nat_dst).into());
        };

        tracing::trace!("kcp nat dst: {:?}, dst peers: {:?}", nat_dst, dst_peer);

        let mut connect_tasks: JoinSet<std::result::Result<ConnId, anyhow::Error>> = JoinSet::new();
        let mut retry_remain = 5;
        loop {
            select! {
                Some(Ok(Ok(ret))) = connect_tasks.join_next() => {
                    // just wait for the previous connection to finish
                    let stream = KcpStream::new(&self.kcp_endpoint, ret)
                        .ok_or(anyhow::anyhow!("failed to create kcp stream"))?;
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

            let kcp_endpoint = self.kcp_endpoint.clone();
            let my_peer_id = peer_mgr.my_peer_id();
            let conn_data_clone = conn_data.clone();

            connect_tasks.spawn(async move {
                kcp_endpoint
                    .connect(
                        Duration::from_secs(10),
                        my_peer_id,
                        dst_peer,
                        Bytes::from(conn_data_clone.encode_to_vec()),
                    )
                    .await
                    .with_context(|| {
                        format!("failed to connect to nat dst: {}", nat_dst.to_string())
                    })
            });
        }

        Err(anyhow::anyhow!("failed to connect to nat dst: {}", nat_dst).into())
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
        return hdr.from_peer_id == hdr.to_peer_id && hdr.is_kcp_src_modified();
    }

    fn transport_type(&self) -> TcpProxyEntryTransportType {
        TcpProxyEntryTransportType::Kcp
    }
}

#[derive(Clone)]
struct TcpProxyForKcpSrc(Arc<TcpProxy<NatDstKcpConnector>>);

#[async_trait::async_trait]
pub(crate) trait TcpProxyForKcpSrcTrait: Send + Sync + 'static {
    type Connector: NatDstConnector;
    fn get_tcp_proxy(&self) -> &Arc<TcpProxy<Self::Connector>>;
    async fn check_dst_allow_kcp_input(&self, dst_ip: &Ipv4Addr) -> bool;
}

#[async_trait::async_trait]
impl TcpProxyForKcpSrcTrait for TcpProxyForKcpSrc {
    type Connector = NatDstKcpConnector;

    fn get_tcp_proxy(&self) -> &Arc<TcpProxy<Self::Connector>> {
        &self.0
    }

    async fn check_dst_allow_kcp_input(&self, dst_ip: &Ipv4Addr) -> bool {
        self.0.get_peer_manager().check_allow_kcp_to_dst(&IpAddr::V4(*dst_ip)).await
    }
}

#[async_trait::async_trait]
impl<C: NatDstConnector, T: TcpProxyForKcpSrcTrait<Connector = C>> NicPacketFilter for T {
    async fn try_process_packet_from_nic(&self, zc_packet: &mut ZCPacket) -> bool {
        let ret = self
            .get_tcp_proxy()
            .try_process_packet_from_nic(zc_packet)
            .await;
        if ret {
            return true;
        }

        let data = zc_packet.payload();
        let ip_packet = Ipv4Packet::new(data).unwrap();
        if ip_packet.get_version() != 4
            || ip_packet.get_next_level_protocol() != IpNextHeaderProtocols::Tcp
        {
            return false;
        }

        // if no connection is established, only allow SYN packet
        let tcp_packet = TcpPacket::new(ip_packet.payload()).unwrap();
        let is_syn = tcp_packet.get_flags() & TcpFlags::SYN != 0
            && tcp_packet.get_flags() & TcpFlags::ACK == 0;
        if is_syn {
            // only check dst feature flag when SYN packet
            if !self
                .check_dst_allow_kcp_input(&ip_packet.get_destination())
                .await
            {
                return false;
            }
        } else {
            // if not syn packet, only allow established connection
            if !self
                .get_tcp_proxy()
                .is_tcp_proxy_connection(SocketAddr::new(
                    IpAddr::V4(ip_packet.get_source()),
                    tcp_packet.get_source(),
                ))
            {
                return false;
            }
        }

        if let Some(my_ipv4) = self.get_tcp_proxy().get_global_ctx().get_ipv4() {
            // this is a net-to-net packet, only allow it when smoltcp is enabled
            // because the syn-ack packet will not be through and handled by the tun device when
            // the source ip is in the local network
            if ip_packet.get_source() != my_ipv4.address()
                && !self.get_tcp_proxy().is_smoltcp_enabled()
            {
                return false;
            }
        };

        let hdr = zc_packet.mut_peer_manager_header().unwrap();
        hdr.to_peer_id = self.get_tcp_proxy().get_my_peer_id().into();
        if self.get_tcp_proxy().get_transport_type() == TcpProxyEntryTransportType::Kcp {
            hdr.set_kcp_src_modified(true);
        }
        true
    }
}

pub struct KcpProxySrc {
    kcp_endpoint: Arc<KcpEndpoint>,
    peer_manager: Arc<PeerManager>,

    tcp_proxy: TcpProxyForKcpSrc,
    tasks: JoinSet<()>,
}

impl KcpProxySrc {
    pub async fn new(peer_manager: Arc<PeerManager>) -> Self {
        let mut kcp_endpoint = create_kcp_endpoint();
        kcp_endpoint.run().await;

        let output_receiver = kcp_endpoint.output_receiver().unwrap();
        let mut tasks = JoinSet::new();

        tasks.spawn(handle_kcp_output(
            peer_manager.clone(),
            output_receiver,
            true,
        ));

        let kcp_endpoint = Arc::new(kcp_endpoint);

        let tcp_proxy = TcpProxy::new(
            peer_manager.clone(),
            NatDstKcpConnector {
                kcp_endpoint: kcp_endpoint.clone(),
                peer_mgr: Arc::downgrade(&peer_manager),
            },
        );

        Self {
            kcp_endpoint,
            peer_manager,
            tcp_proxy: TcpProxyForKcpSrc(tcp_proxy),
            tasks,
        }
    }

    pub async fn start(&self) {
        self.peer_manager
            .add_nic_packet_process_pipeline(Box::new(self.tcp_proxy.clone()))
            .await;
        self.peer_manager
            .add_packet_process_pipeline(Box::new(self.tcp_proxy.0.clone()))
            .await;
        self.peer_manager
            .add_packet_process_pipeline(Box::new(KcpEndpointFilter {
                kcp_endpoint: self.kcp_endpoint.clone(),
                is_src: true,
            }))
            .await;
        self.tcp_proxy.0.start(false).await.unwrap();
    }

    pub fn get_tcp_proxy(&self) -> Arc<TcpProxy<NatDstKcpConnector>> {
        self.tcp_proxy.0.clone()
    }

    pub fn get_kcp_endpoint(&self) -> Arc<KcpEndpoint> {
        self.kcp_endpoint.clone()
    }
}

pub struct KcpProxyDst {
    kcp_endpoint: Arc<KcpEndpoint>,
    peer_manager: Arc<PeerManager>,
    proxy_entries: Arc<DashMap<ConnId, TcpProxyEntry>>,
    cidr_set: Arc<CidrSet>,
    tasks: JoinSet<()>,
}

#[derive(Clone)]
pub struct ProxyAclHandler {
    pub acl_filter: Arc<AclFilter>,
    pub packet_info: PacketInfo,
    pub chain_type: ChainType,
}

impl ProxyAclHandler {
    pub fn handle_packet(&self, buf: &[u8]) -> Result<()> {
        let mut packet_info = self.packet_info.clone();
        packet_info.packet_size = buf.len();
        let ret = self
            .acl_filter
            .get_processor()
            .process_packet(&packet_info, self.chain_type);
        self.acl_filter.handle_acl_result(
            &ret,
            &packet_info,
            self.chain_type,
            &self.acl_filter.get_processor(),
        );
        if !matches!(ret.action, Action::Allow) {
            return Err(anyhow::anyhow!("acl denied").into());
        }

        Ok(())
    }

    pub async fn copy_bidirection_with_acl(
        &self,
        src: impl AsyncRead + AsyncWrite + Unpin,
        mut dst: impl AsyncRead + AsyncWrite + Unpin,
    ) -> Result<()> {
        let (src_reader, src_writer) = tokio::io::split(src);
        let src_reader = InspectReader::new(src_reader, |buf| {
            let _ = self.handle_packet(buf);
        });
        let mut src = tokio::io::join(src_reader, src_writer);

        copy_bidirectional(&mut src, &mut dst).await?;
        Ok(())
    }
}

impl KcpProxyDst {
    pub async fn new(peer_manager: Arc<PeerManager>) -> Self {
        let mut kcp_endpoint = create_kcp_endpoint();
        kcp_endpoint.run().await;

        let mut tasks = JoinSet::new();
        let output_receiver = kcp_endpoint.output_receiver().unwrap();
        tasks.spawn(handle_kcp_output(
            peer_manager.clone(),
            output_receiver,
            false,
        ));
        let cidr_set = CidrSet::new(peer_manager.get_global_ctx());
        Self {
            kcp_endpoint: Arc::new(kcp_endpoint),
            peer_manager,
            proxy_entries: Arc::new(DashMap::new()),
            cidr_set: Arc::new(cidr_set),
            tasks,
        }
    }

    #[tracing::instrument(ret)]
    async fn handle_one_in_stream(
        kcp_stream: KcpStream,
        global_ctx: ArcGlobalCtx,
        proxy_entries: Arc<DashMap<ConnId, TcpProxyEntry>>,
        cidr_set: Arc<CidrSet>,
    ) -> Result<()> {
        let mut conn_data = kcp_stream.conn_data().clone();
        let parsed_conn_data = KcpConnData::decode(&mut conn_data)
            .with_context(|| format!("failed to decode kcp conn data: {:?}", conn_data))?;
        let mut dst_socket: SocketAddr = parsed_conn_data
            .dst
            .ok_or(anyhow::anyhow!(
                "failed to get dst socket from kcp conn data: {:?}",
                parsed_conn_data
            ))?
            .into();
        let src_socket: SocketAddr = parsed_conn_data.src.unwrap_or_default().into();

        match dst_socket.ip() {
            IpAddr::V4(dst_v4_ip) => {
                let mut real_ip = dst_v4_ip;
                if cidr_set.contains_v4(dst_v4_ip, &mut real_ip) {
                    dst_socket.set_ip(real_ip.into());
                }
            }
            _ => {}
        };

        let conn_id = kcp_stream.conn_id();
        proxy_entries.insert(
            conn_id,
            TcpProxyEntry {
                src: parsed_conn_data.src,
                dst: parsed_conn_data.dst,
                start_time: chrono::Local::now().timestamp() as u64,
                state: TcpProxyEntryState::ConnectingDst.into(),
                transport_type: TcpProxyEntryTransportType::Kcp.into(),
            },
        );
        crate::defer! {
            proxy_entries.remove(&conn_id);
        }

        let send_to_self =
            Some(dst_socket.ip()) == global_ctx.get_ipv4().map(|ip| IpAddr::V4(ip.address()));

        if send_to_self && global_ctx.no_tun() {
            dst_socket = format!("127.0.0.1:{}", dst_socket.port()).parse().unwrap();
        }

        let acl_handler = ProxyAclHandler {
            acl_filter: global_ctx.get_acl_filter().clone(),
            packet_info: PacketInfo {
                src_ip: src_socket.ip(),
                dst_ip: dst_socket.ip(),
                src_port: Some(src_socket.port()),
                dst_port: Some(dst_socket.port()),
                protocol: Protocol::Tcp,
                packet_size: conn_data.len(),
            },
            chain_type: if send_to_self {
                ChainType::Inbound
            } else {
                ChainType::Forward
            },
        };
        acl_handler.handle_packet(&conn_data)?;

        tracing::debug!("kcp connect to dst socket: {:?}", dst_socket);

        let _g = global_ctx.net_ns.guard();
        let connector = NatDstTcpConnector {};
        let ret = connector
            .connect("0.0.0.0:0".parse().unwrap(), dst_socket)
            .await?;

        if let Some(mut e) = proxy_entries.get_mut(&kcp_stream.conn_id()) {
            e.state = TcpProxyEntryState::Connected.into();
        }

        acl_handler
            .copy_bidirection_with_acl(kcp_stream, ret)
            .await?;

        Ok(())
    }

    async fn run_accept_task(&mut self) {
        let kcp_endpoint = self.kcp_endpoint.clone();
        let global_ctx = self.peer_manager.get_global_ctx().clone();
        let proxy_entries = self.proxy_entries.clone();
        let cidr_set = self.cidr_set.clone();
        self.tasks.spawn(async move {
            while let Ok(conn) = kcp_endpoint.accept().await {
                let stream = KcpStream::new(&kcp_endpoint, conn)
                    .ok_or(anyhow::anyhow!("failed to create kcp stream"))
                    .unwrap();

                let global_ctx = global_ctx.clone();
                let proxy_entries = proxy_entries.clone();
                let cidr_set = cidr_set.clone();
                tokio::spawn(async move {
                    let _ = Self::handle_one_in_stream(stream, global_ctx, proxy_entries, cidr_set)
                        .await;
                });
            }
        });
    }

    pub async fn start(&mut self) {
        self.run_accept_task().await;
        self.peer_manager
            .add_packet_process_pipeline(Box::new(KcpEndpointFilter {
                kcp_endpoint: self.kcp_endpoint.clone(),
                is_src: false,
            }))
            .await;
    }
}

#[derive(Clone)]
pub struct KcpProxyDstRpcService(Weak<DashMap<ConnId, TcpProxyEntry>>);

impl KcpProxyDstRpcService {
    pub fn new(kcp_proxy_dst: &KcpProxyDst) -> Self {
        Self(Arc::downgrade(&kcp_proxy_dst.proxy_entries))
    }
}

#[async_trait::async_trait]
impl TcpProxyRpc for KcpProxyDstRpcService {
    type Controller = BaseController;
    async fn list_tcp_proxy_entry(
        &self,
        _: BaseController,
        _request: ListTcpProxyEntryRequest, // Accept request of type HelloRequest
    ) -> std::result::Result<ListTcpProxyEntryResponse, rpc_types::error::Error> {
        let mut reply = ListTcpProxyEntryResponse::default();
        if let Some(tcp_proxy) = self.0.upgrade() {
            for item in tcp_proxy.iter() {
                reply.entries.push(item.value().clone());
            }
        }
        Ok(reply)
    }
}
