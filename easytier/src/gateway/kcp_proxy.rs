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
use pnet::packet::ipv4::Ipv4Packet;
use prost::Message;
use tokio::{select, task::JoinSet};

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
    gateway::wrapped_proxy::{ProxyAclHandler, TcpProxyForWrappedSrcTrait},
    peers::{peer_manager::PeerManager, PeerPacketFilter},
    proto::{
        acl::{ChainType, Protocol},
        api::instance::{
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
            // src packet, but we are dst
        } else if t == PacketType::KcpDst as u8 && self.is_src {
            // dst packet, but we are src
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
        packet.fill_peer_manager_hdr(peer_mgr.my_peer_id(), dst_peer_id, packet_type);

        if let Err(e) = peer_mgr.send_msg_for_proxy(packet, dst_peer_id).await {
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
            let conn_data_clone = conn_data;

            connect_tasks.spawn(async move {
                kcp_endpoint
                    .connect(
                        Duration::from_secs(10),
                        my_peer_id,
                        dst_peer,
                        Bytes::from(conn_data_clone.encode_to_vec()),
                    )
                    .await
                    .with_context(|| format!("failed to connect to nat dst: {}", nat_dst))
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
        hdr.from_peer_id == hdr.to_peer_id && hdr.is_kcp_src_modified()
    }

    fn transport_type(&self) -> TcpProxyEntryTransportType {
        TcpProxyEntryTransportType::Kcp
    }
}

#[derive(Clone)]
struct TcpProxyForKcpSrc(Arc<TcpProxy<NatDstKcpConnector>>);

#[async_trait::async_trait]
impl TcpProxyForWrappedSrcTrait for TcpProxyForKcpSrc {
    type Connector = NatDstKcpConnector;

    fn get_tcp_proxy(&self) -> &Arc<TcpProxy<Self::Connector>> {
        &self.0
    }

    fn set_src_modified(hdr: &mut PeerManagerHeader, modified: bool) -> &mut PeerManagerHeader {
        hdr.set_kcp_src_modified(modified)
    }

    async fn check_dst_allow_wrapped_input(&self, dst_ip: &Ipv4Addr) -> bool {
        let Some(peer_manager) = self.0.get_peer_manager() else {
            return false;
        };
        peer_manager
            .check_allow_kcp_to_dst(&IpAddr::V4(*dst_ip))
            .await
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

    #[tracing::instrument(ret, skip(route))]
    async fn handle_one_in_stream(
        kcp_stream: KcpStream,
        global_ctx: ArcGlobalCtx,
        proxy_entries: Arc<DashMap<ConnId, TcpProxyEntry>>,
        cidr_set: Arc<CidrSet>,
        route: Arc<dyn crate::peers::route_trait::Route + Send + Sync + 'static>,
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

        if let IpAddr::V4(dst_v4_ip) = dst_socket.ip() {
            let mut real_ip = dst_v4_ip;
            if cidr_set.contains_v4(dst_v4_ip, &mut real_ip) {
                dst_socket.set_ip(real_ip.into());
            }
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
            if proxy_entries.capacity() - proxy_entries.len() > 16 {
                proxy_entries.shrink_to_fit();
            }
        }

        let src_ip = src_socket.ip();
        let dst_ip = dst_socket.ip();
        let (src_groups, dst_groups) = tokio::join!(
            route.get_peer_groups_by_ip(&src_ip),
            route.get_peer_groups_by_ip(&dst_ip)
        );

        if global_ctx.should_deny_proxy(&dst_socket, false) {
            return Err(anyhow::anyhow!(
                "dst socket {:?} is in running listeners, ignore it",
                dst_socket
            )
            .into());
        }

        let send_to_self = global_ctx.is_ip_local_virtual_ip(&dst_ip);
        if send_to_self && global_ctx.no_tun() {
            dst_socket = format!("127.0.0.1:{}", dst_socket.port()).parse().unwrap();
        }

        let acl_handler = ProxyAclHandler {
            acl_filter: global_ctx.get_acl_filter().clone(),
            packet_info: PacketInfo {
                src_ip,
                dst_ip,
                src_port: Some(src_socket.port()),
                dst_port: Some(dst_socket.port()),
                protocol: Protocol::Tcp,
                packet_size: conn_data.len(),
                src_groups,
                dst_groups,
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
        let global_ctx = self.peer_manager.get_global_ctx();
        let proxy_entries = self.proxy_entries.clone();
        let cidr_set = self.cidr_set.clone();
        let route = Arc::new(self.peer_manager.get_route());
        self.tasks.spawn(async move {
            while let Ok(conn) = kcp_endpoint.accept().await {
                let stream = KcpStream::new(&kcp_endpoint, conn)
                    .ok_or(anyhow::anyhow!("failed to create kcp stream"))
                    .unwrap();

                let global_ctx = global_ctx.clone();
                let proxy_entries = proxy_entries.clone();
                let cidr_set = cidr_set.clone();
                let route = route.clone();
                tokio::spawn(async move {
                    let _ = Self::handle_one_in_stream(
                        stream,
                        global_ctx,
                        proxy_entries,
                        cidr_set,
                        route,
                    )
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
                reply.entries.push(*item.value());
            }
        }
        Ok(reply)
    }
}
