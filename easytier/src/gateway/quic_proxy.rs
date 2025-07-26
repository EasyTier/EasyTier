use std::net::{IpAddr, Ipv4Addr};
use std::sync::{Arc, Mutex, Weak};
use std::{net::SocketAddr, pin::Pin};

use anyhow::Context;
use dashmap::DashMap;
use pnet::packet::ipv4::Ipv4Packet;
use prost::Message as _;
use quinn::{Endpoint, Incoming};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite};
use tokio::net::TcpStream;
use tokio::task::JoinSet;
use tokio::time::timeout;

use crate::common::acl_processor::PacketInfo;
use crate::common::error::Result;
use crate::common::global_ctx::{ArcGlobalCtx, GlobalCtx};
use crate::common::join_joinset_background;
use crate::defer;
use crate::gateway::kcp_proxy::{ProxyAclHandler, TcpProxyForKcpSrcTrait};
use crate::gateway::tcp_proxy::{NatDstConnector, NatDstTcpConnector, TcpProxy};
use crate::gateway::CidrSet;
use crate::peers::peer_manager::PeerManager;
use crate::proto::acl::{ChainType, Protocol};
use crate::proto::cli::{
    ListTcpProxyEntryRequest, ListTcpProxyEntryResponse, TcpProxyEntry, TcpProxyEntryState,
    TcpProxyEntryTransportType, TcpProxyRpc,
};
use crate::proto::common::ProxyDstInfo;
use crate::proto::rpc_types;
use crate::proto::rpc_types::controller::BaseController;
use crate::tunnel::packet_def::PeerManagerHeader;
use crate::tunnel::quic::{configure_client, make_server_endpoint};

pub struct QUICStream {
    endpoint: Option<quinn::Endpoint>,
    connection: Option<quinn::Connection>,
    sender: quinn::SendStream,
    receiver: quinn::RecvStream,
}

impl AsyncRead for QUICStream {
    fn poll_read(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        let this = self.get_mut();
        Pin::new(&mut this.receiver).poll_read(cx, buf)
    }
}

impl AsyncWrite for QUICStream {
    fn poll_write(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &[u8],
    ) -> std::task::Poll<std::io::Result<usize>> {
        let this = self.get_mut();
        AsyncWrite::poll_write(Pin::new(&mut this.sender), cx, buf)
    }

    fn poll_flush(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        let this = self.get_mut();
        Pin::new(&mut this.sender).poll_flush(cx)
    }

    fn poll_shutdown(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        let this = self.get_mut();
        Pin::new(&mut this.sender).poll_shutdown(cx)
    }
}

#[derive(Debug, Clone)]
pub struct NatDstQUICConnector {
    pub(crate) peer_mgr: Weak<PeerManager>,
}

#[async_trait::async_trait]
impl NatDstConnector for NatDstQUICConnector {
    type DstStream = QUICStream;

    #[tracing::instrument(skip(self), level = "debug", name = "NatDstQUICConnector::connect")]
    async fn connect(&self, src: SocketAddr, nat_dst: SocketAddr) -> Result<Self::DstStream> {
        let Some(peer_mgr) = self.peer_mgr.upgrade() else {
            return Err(anyhow::anyhow!("peer manager is not available").into());
        };

        let IpAddr::V4(dst_ipv4) = nat_dst.ip() else {
            return Err(anyhow::anyhow!("src must be an IPv4 address").into());
        };

        let Some(dst_peer) = peer_mgr.get_peer_map().get_peer_id_by_ipv4(&dst_ipv4).await else {
            return Err(anyhow::anyhow!("no peer found for dst: {}", nat_dst).into());
        };

        let Some(dst_peer_info) = peer_mgr.get_peer_map().get_route_peer_info(dst_peer).await
        else {
            return Err(anyhow::anyhow!("no peer info found for dst peer: {}", dst_peer).into());
        };

        let Some(dst_ipv4): Option<Ipv4Addr> = dst_peer_info.ipv4_addr.map(Into::into) else {
            return Err(anyhow::anyhow!("no ipv4 found for dst peer: {}", dst_peer).into());
        };

        let Some(quic_port) = dst_peer_info.quic_port else {
            return Err(anyhow::anyhow!("no quic port found for dst peer: {}", dst_peer).into());
        };

        let mut endpoint = Endpoint::client("0.0.0.0:0".parse().unwrap())
            .with_context(|| format!("failed to create QUIC endpoint for src: {}", src))?;
        endpoint.set_default_client_config(configure_client());

        // connect to server
        let connection = {
            let _g = peer_mgr.get_global_ctx().net_ns.guard();
            endpoint
                .connect(
                    SocketAddr::new(dst_ipv4.into(), quic_port as u16),
                    "localhost",
                )
                .unwrap()
                .await
                .with_context(|| {
                    format!(
                        "failed to connect to NAT destination {} from {}, real dst: {}",
                        nat_dst, src, dst_ipv4
                    )
                })?
        };

        let (mut w, r) = connection
            .open_bi()
            .await
            .with_context(|| "open_bi failed")?;

        let proxy_dst_info = ProxyDstInfo {
            dst_addr: Some(nat_dst.into()),
        };
        let proxy_dst_info_buf = proxy_dst_info.encode_to_vec();
        let buf_len = proxy_dst_info_buf.len() as u8;
        w.write(&buf_len.to_le_bytes())
            .await
            .with_context(|| "failed to write proxy dst info buf len to QUIC stream")?;
        w.write(&proxy_dst_info_buf)
            .await
            .with_context(|| "failed to write proxy dst info to QUIC stream")?;

        Ok(QUICStream {
            endpoint: Some(endpoint),
            connection: Some(connection),
            sender: w,
            receiver: r,
        })
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
        return hdr.from_peer_id == hdr.to_peer_id && !hdr.is_kcp_src_modified();
    }

    fn transport_type(&self) -> TcpProxyEntryTransportType {
        TcpProxyEntryTransportType::Quic
    }
}

#[derive(Clone)]
struct TcpProxyForQUICSrc(Arc<TcpProxy<NatDstQUICConnector>>);

#[async_trait::async_trait]
impl TcpProxyForKcpSrcTrait for TcpProxyForQUICSrc {
    type Connector = NatDstQUICConnector;

    fn get_tcp_proxy(&self) -> &Arc<TcpProxy<Self::Connector>> {
        &self.0
    }

    async fn check_dst_allow_kcp_input(&self, dst_ip: &Ipv4Addr) -> bool {
        let peer_map: Arc<crate::peers::peer_map::PeerMap> =
            self.0.get_peer_manager().get_peer_map();
        let Some(dst_peer_id) = peer_map.get_peer_id_by_ipv4(dst_ip).await else {
            return false;
        };
        let Some(peer_info) = peer_map.get_route_peer_info(dst_peer_id).await else {
            return false;
        };
        let Some(quic_port) = peer_info.quic_port else {
            return false;
        };
        quic_port > 0
    }
}

pub struct QUICProxySrc {
    peer_manager: Arc<PeerManager>,
    tcp_proxy: TcpProxyForQUICSrc,
}

impl QUICProxySrc {
    pub async fn new(peer_manager: Arc<PeerManager>) -> Self {
        let tcp_proxy = TcpProxy::new(
            peer_manager.clone(),
            NatDstQUICConnector {
                peer_mgr: Arc::downgrade(&peer_manager),
            },
        );

        Self {
            peer_manager,
            tcp_proxy: TcpProxyForQUICSrc(tcp_proxy),
        }
    }

    pub async fn start(&self) {
        self.peer_manager
            .add_nic_packet_process_pipeline(Box::new(self.tcp_proxy.clone()))
            .await;
        self.peer_manager
            .add_packet_process_pipeline(Box::new(self.tcp_proxy.0.clone()))
            .await;
        self.tcp_proxy.0.start(false).await.unwrap();
    }

    pub fn get_tcp_proxy(&self) -> Arc<TcpProxy<NatDstQUICConnector>> {
        self.tcp_proxy.0.clone()
    }
}

pub struct QUICProxyDst {
    global_ctx: Arc<GlobalCtx>,
    endpoint: Arc<quinn::Endpoint>,
    proxy_entries: Arc<DashMap<SocketAddr, TcpProxyEntry>>,
    tasks: Arc<Mutex<JoinSet<()>>>,
}

impl QUICProxyDst {
    pub fn new(global_ctx: ArcGlobalCtx) -> Result<Self> {
        let _g = global_ctx.net_ns.guard();
        let (endpoint, _) = make_server_endpoint("0.0.0.0:0".parse().unwrap())
            .map_err(|e| anyhow::anyhow!("failed to create QUIC endpoint: {}", e))?;
        let tasks = Arc::new(Mutex::new(JoinSet::new()));
        join_joinset_background(tasks.clone(), "QUICProxyDst tasks".to_string());
        Ok(Self {
            global_ctx,
            endpoint: Arc::new(endpoint),
            proxy_entries: Arc::new(DashMap::new()),
            tasks,
        })
    }

    pub async fn start(&self) -> Result<()> {
        let endpoint = self.endpoint.clone();
        let tasks = Arc::downgrade(&self.tasks.clone());
        let ctx = self.global_ctx.clone();
        let cidr_set = Arc::new(CidrSet::new(ctx.clone()));
        let proxy_entries = self.proxy_entries.clone();

        let task = async move {
            loop {
                match endpoint.accept().await {
                    Some(conn) => {
                        let Some(tasks) = tasks.upgrade() else {
                            tracing::warn!(
                                "QUICProxyDst tasks is not available, stopping accept loop"
                            );
                            return;
                        };
                        tasks
                            .lock()
                            .unwrap()
                            .spawn(Self::handle_connection_with_timeout(
                                conn,
                                ctx.clone(),
                                cidr_set.clone(),
                                proxy_entries.clone(),
                            ));
                    }
                    None => {
                        return;
                    }
                }
            }
        };

        self.tasks.lock().unwrap().spawn(task);

        Ok(())
    }

    pub fn local_addr(&self) -> Result<SocketAddr> {
        self.endpoint.local_addr().map_err(Into::into)
    }

    async fn handle_connection_with_timeout(
        conn: Incoming,
        ctx: Arc<GlobalCtx>,
        cidr_set: Arc<CidrSet>,
        proxy_entries: Arc<DashMap<SocketAddr, TcpProxyEntry>>,
    ) {
        let remote_addr = conn.remote_address();
        defer!(
            proxy_entries.remove(&remote_addr);
        );
        let ret = timeout(
            std::time::Duration::from_secs(10),
            Self::handle_connection(conn, ctx, cidr_set, remote_addr, proxy_entries.clone()),
        )
        .await;

        match ret {
            Ok(Ok((quic_stream, tcp_stream, acl))) => {
                let remote_addr = quic_stream.connection.as_ref().map(|c| c.remote_address());
                let ret = acl.copy_bidirection_with_acl(quic_stream, tcp_stream).await;
                tracing::info!(
                    "QUIC connection handled, result: {:?}, remote addr: {:?}",
                    ret,
                    remote_addr,
                );
            }
            Ok(Err(e)) => {
                tracing::error!("Failed to handle QUIC connection: {}", e);
            }
            Err(_) => {
                tracing::warn!("Timeout while handling QUIC connection");
            }
        }
    }

    async fn handle_connection(
        incoming: Incoming,
        ctx: ArcGlobalCtx,
        cidr_set: Arc<CidrSet>,
        proxy_entry_key: SocketAddr,
        proxy_entries: Arc<DashMap<SocketAddr, TcpProxyEntry>>,
    ) -> Result<(QUICStream, TcpStream, ProxyAclHandler)> {
        let conn = incoming.await.with_context(|| "accept failed")?;
        let addr = conn.remote_address();
        tracing::info!("Accepted QUIC connection from {}", addr);
        let (w, mut r) = conn.accept_bi().await.with_context(|| "accept_bi failed")?;
        let len = r
            .read_u8()
            .await
            .with_context(|| "failed to read proxy dst info buf len")?;
        let mut buf = vec![0u8; len as usize];
        r.read_exact(&mut buf)
            .await
            .with_context(|| "failed to read proxy dst info")?;

        let proxy_dst_info =
            ProxyDstInfo::decode(&buf[..]).with_context(|| "failed to decode proxy dst info")?;

        let dst_socket: SocketAddr = proxy_dst_info
            .dst_addr
            .map(Into::into)
            .ok_or_else(|| anyhow::anyhow!("no dst addr in proxy dst info"))?;

        let SocketAddr::V4(mut dst_socket) = dst_socket else {
            return Err(anyhow::anyhow!("NAT destination must be an IPv4 address").into());
        };

        let mut real_ip = *dst_socket.ip();
        if cidr_set.contains_v4(*dst_socket.ip(), &mut real_ip) {
            dst_socket.set_ip(real_ip);
        }

        let send_to_self = Some(*dst_socket.ip()) == ctx.get_ipv4().map(|ip| ip.address());
        if send_to_self && ctx.no_tun() {
            dst_socket = format!("127.0.0.1:{}", dst_socket.port()).parse().unwrap();
        }

        proxy_entries.insert(
            proxy_entry_key,
            TcpProxyEntry {
                src: Some(addr.into()),
                dst: Some(SocketAddr::V4(dst_socket).into()),
                start_time: chrono::Local::now().timestamp() as u64,
                state: TcpProxyEntryState::ConnectingDst.into(),
                transport_type: TcpProxyEntryTransportType::Quic.into(),
            },
        );

        let acl_handler = ProxyAclHandler {
            acl_filter: ctx.get_acl_filter().clone(),
            packet_info: PacketInfo {
                src_ip: addr.ip(),
                dst_ip: (*dst_socket.ip()).into(),
                src_port: Some(addr.port()),
                dst_port: Some(dst_socket.port()),
                protocol: Protocol::Tcp,
                packet_size: len as usize,
            },
            chain_type: if send_to_self {
                ChainType::Inbound
            } else {
                ChainType::Forward
            },
        };
        acl_handler.handle_packet(&buf)?;

        let connector = NatDstTcpConnector {};

        let dst_stream = {
            let _g = ctx.net_ns.guard();
            connector
                .connect("0.0.0.0:0".parse().unwrap(), dst_socket.into())
                .await?
        };

        if let Some(mut e) = proxy_entries.get_mut(&proxy_entry_key) {
            e.state = TcpProxyEntryState::Connected.into();
        }

        let quic_stream = QUICStream {
            endpoint: None,
            connection: Some(conn),
            sender: w,
            receiver: r,
        };

        Ok((quic_stream, dst_stream, acl_handler))
    }
}

#[derive(Clone)]
pub struct QUICProxyDstRpcService(Weak<DashMap<SocketAddr, TcpProxyEntry>>);

impl QUICProxyDstRpcService {
    pub fn new(quic_proxy_dst: &QUICProxyDst) -> Self {
        Self(Arc::downgrade(&quic_proxy_dst.proxy_entries))
    }
}

#[async_trait::async_trait]
impl TcpProxyRpc for QUICProxyDstRpcService {
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
