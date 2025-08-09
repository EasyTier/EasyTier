use std::{
    net::{IpAddr, Ipv4Addr, SocketAddr},
    sync::{Arc, Weak},
    time::{Duration, Instant},
};

use crossbeam::atomic::AtomicCell;
use kcp_sys::{endpoint::KcpEndpoint, stream::KcpStream};
use tokio_util::sync::{CancellationToken, DropGuard};

use crate::{
    common::{
        config::PortForwardConfig, global_ctx::GlobalCtxEvent, join_joinset_background,
        netns::NetNS, scoped_task::ScopedTask,
    },
    gateway::{
        fast_socks5::{
            server::{
                AcceptAuthentication, AsyncTcpConnector, Config, SimpleUserPassword, Socks5Socket,
            },
            util::stream::tcp_connect_with_timeout,
        },
        ip_reassembler::IpReassembler,
        kcp_proxy::NatDstKcpConnector,
        tokio_smoltcp::{channel_device, BufferSize, Net, NetConfig},
    },
    tunnel::{
        common::setup_sokcet2,
        packet_def::{PacketType, ZCPacket},
    },
};
use anyhow::Context;
use dashmap::DashMap;
use pnet::packet::{
    ip::IpNextHeaderProtocols, ipv4::Ipv4Packet, tcp::TcpPacket, udp::UdpPacket, Packet,
};
use tokio::{
    io::{AsyncRead, AsyncWrite},
    net::{TcpListener, TcpSocket, UdpSocket},
    select,
    sync::{mpsc, Mutex},
    task::JoinSet,
    time::timeout,
};

use crate::{
    common::{error::Error, global_ctx::GlobalCtx},
    peers::{peer_manager::PeerManager, PeerPacketFilter},
};

use super::tcp_proxy::NatDstConnector as _;

enum SocksUdpSocket {
    UdpSocket(Arc<tokio::net::UdpSocket>),
    SmolUdpSocket(super::tokio_smoltcp::UdpSocket),
}

impl SocksUdpSocket {
    pub async fn send_to(&self, buf: &[u8], addr: SocketAddr) -> Result<usize, std::io::Error> {
        match self {
            SocksUdpSocket::UdpSocket(socket) => socket.send_to(buf, addr).await,
            SocksUdpSocket::SmolUdpSocket(socket) => socket.send_to(buf, addr).await,
        }
    }

    pub async fn recv_from(&self, buf: &mut [u8]) -> Result<(usize, SocketAddr), std::io::Error> {
        match self {
            SocksUdpSocket::UdpSocket(socket) => socket.recv_from(buf).await,
            SocksUdpSocket::SmolUdpSocket(socket) => socket.recv_from(buf).await,
        }
    }
}

enum SocksTcpStream {
    TcpStream(tokio::net::TcpStream),
    SmolTcpStream(super::tokio_smoltcp::TcpStream),
    KcpStream(KcpStream),
}

impl AsyncRead for SocksTcpStream {
    fn poll_read(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        match self.get_mut() {
            SocksTcpStream::TcpStream(ref mut stream) => {
                std::pin::Pin::new(stream).poll_read(cx, buf)
            }
            SocksTcpStream::SmolTcpStream(ref mut stream) => {
                std::pin::Pin::new(stream).poll_read(cx, buf)
            }
            SocksTcpStream::KcpStream(ref mut stream) => {
                std::pin::Pin::new(stream).poll_read(cx, buf)
            }
        }
    }
}

impl AsyncWrite for SocksTcpStream {
    fn poll_write(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &[u8],
    ) -> std::task::Poll<Result<usize, std::io::Error>> {
        match self.get_mut() {
            SocksTcpStream::TcpStream(ref mut stream) => {
                std::pin::Pin::new(stream).poll_write(cx, buf)
            }
            SocksTcpStream::SmolTcpStream(ref mut stream) => {
                std::pin::Pin::new(stream).poll_write(cx, buf)
            }
            SocksTcpStream::KcpStream(ref mut stream) => {
                std::pin::Pin::new(stream).poll_write(cx, buf)
            }
        }
    }

    fn poll_flush(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Result<(), std::io::Error>> {
        match self.get_mut() {
            SocksTcpStream::TcpStream(ref mut stream) => std::pin::Pin::new(stream).poll_flush(cx),
            SocksTcpStream::SmolTcpStream(ref mut stream) => {
                std::pin::Pin::new(stream).poll_flush(cx)
            }
            SocksTcpStream::KcpStream(ref mut stream) => std::pin::Pin::new(stream).poll_flush(cx),
        }
    }

    fn poll_shutdown(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Result<(), std::io::Error>> {
        match self.get_mut() {
            SocksTcpStream::TcpStream(ref mut stream) => {
                std::pin::Pin::new(stream).poll_shutdown(cx)
            }
            SocksTcpStream::SmolTcpStream(ref mut stream) => {
                std::pin::Pin::new(stream).poll_shutdown(cx)
            }
            SocksTcpStream::KcpStream(ref mut stream) => {
                std::pin::Pin::new(stream).poll_shutdown(cx)
            }
        }
    }
}

enum Socks5EntryData {
    Tcp(TcpListener), // hold a binded socket to hold the tcp port
    Udp((Arc<SocksUdpSocket>, UdpClientKey)), // hold the socket to send data to dst
}

const UDP_ENTRY: u8 = 1;
const TCP_ENTRY: u8 = 2;

#[derive(Debug, Eq, PartialEq, Hash, Clone)]
struct Socks5Entry {
    src: SocketAddr,
    dst: SocketAddr,
    entry_type: u8,
}

type Socks5EntrySet = Arc<DashMap<Socks5Entry, Socks5EntryData>>;

struct SmolTcpConnector {
    net: Arc<Net>,
    entries: Socks5EntrySet,
    current_entry: std::sync::Mutex<Option<Socks5Entry>>,
}

#[async_trait::async_trait]
impl AsyncTcpConnector for SmolTcpConnector {
    type S = SocksTcpStream;

    async fn tcp_connect(
        &self,
        addr: SocketAddr,
        timeout_s: u64,
    ) -> crate::gateway::fast_socks5::Result<SocksTcpStream> {
        let tmp_listener = TcpListener::bind("0.0.0.0:0").await?;
        let local_addr = self.net.get_address();
        let port = tmp_listener.local_addr()?.port();

        let entry = Socks5Entry {
            src: SocketAddr::new(local_addr, port),
            dst: addr,
            entry_type: TCP_ENTRY,
        };
        *self.current_entry.lock().unwrap() = Some(entry.clone());
        self.entries
            .insert(entry, Socks5EntryData::Tcp(tmp_listener));

        if addr.ip() == local_addr {
            let modified_addr =
                SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), addr.port());

            Ok(SocksTcpStream::TcpStream(
                tcp_connect_with_timeout(modified_addr, timeout_s).await?,
            ))
        } else {
            let remote_socket = timeout(
                Duration::from_secs(timeout_s),
                self.net.tcp_connect(addr, port),
            )
            .await
            .with_context(|| "connect to remote timeout")?;

            Ok(SocksTcpStream::SmolTcpStream(remote_socket.map_err(
                |e| super::fast_socks5::SocksError::Other(e.into()),
            )?))
        }
    }
}

impl Drop for SmolTcpConnector {
    fn drop(&mut self) {
        if let Some(entry) = self.current_entry.lock().unwrap().take() {
            self.entries.remove(&entry);
        }
    }
}

struct Socks5KcpConnector {
    kcp_endpoint: Weak<KcpEndpoint>,
    peer_mgr: Weak<PeerManager>,
    src_addr: SocketAddr,
}

#[async_trait::async_trait]
impl AsyncTcpConnector for Socks5KcpConnector {
    type S = SocksTcpStream;

    async fn tcp_connect(
        &self,
        addr: SocketAddr,
        _timeout_s: u64,
    ) -> crate::gateway::fast_socks5::Result<SocksTcpStream> {
        let Some(kcp_endpoint) = self.kcp_endpoint.upgrade() else {
            return Err(anyhow::anyhow!("kcp endpoint is not ready").into());
        };
        let c = NatDstKcpConnector {
            kcp_endpoint,
            peer_mgr: self.peer_mgr.clone(),
        };
        println!("connect to kcp endpoint, addr = {:?}", addr);
        let ret = c
            .connect(self.src_addr, addr)
            .await
            .map_err(|e| super::fast_socks5::SocksError::Other(e.into()))?;
        Ok(SocksTcpStream::KcpStream(ret))
    }
}

fn bind_tcp_socket(addr: SocketAddr, net_ns: NetNS) -> Result<TcpListener, Error> {
    let _g = net_ns.guard();
    let socket2_socket = socket2::Socket::new(
        socket2::Domain::for_address(addr),
        socket2::Type::STREAM,
        Some(socket2::Protocol::TCP),
    )?;

    setup_sokcet2(&socket2_socket, &addr)?;

    let socket = TcpSocket::from_std_stream(socket2_socket.into());

    if let Err(e) = socket.set_nodelay(true) {
        tracing::warn!(?e, "set_nodelay fail in listen");
    }

    Ok(socket.listen(1024)?)
}

fn bind_udp_socket(addr: SocketAddr, net_ns: NetNS) -> Result<UdpSocket, Error> {
    let _g = net_ns.guard();
    let socket2_socket = socket2::Socket::new(
        socket2::Domain::for_address(addr),
        socket2::Type::DGRAM,
        Some(socket2::Protocol::UDP),
    )?;

    setup_sokcet2(&socket2_socket, &addr)?;

    Ok(UdpSocket::from_std(socket2_socket.into())?)
}

struct Socks5ServerNet {
    ipv4_addr: cidr::Ipv4Inet,
    auth: Option<SimpleUserPassword>,

    smoltcp_net: Arc<Net>,
    forward_tasks: Arc<std::sync::Mutex<JoinSet<()>>>,

    entries: Socks5EntrySet,
}

impl Socks5ServerNet {
    pub fn new(
        ipv4_addr: cidr::Ipv4Inet,
        auth: Option<SimpleUserPassword>,
        peer_manager: Arc<PeerManager>,
        packet_recv: Arc<Mutex<mpsc::Receiver<ZCPacket>>>,
        entries: Socks5EntrySet,
    ) -> Self {
        let mut forward_tasks = JoinSet::new();
        let mut cap = smoltcp::phy::DeviceCapabilities::default();
        cap.max_transmission_unit = 1284; // 1284 - 20 can be divided by 8 (fragment offset unit)
        cap.medium = smoltcp::phy::Medium::Ip;
        let (dev, stack_sink, mut stack_stream) = channel_device::ChannelDevice::new(cap);

        let packet_recv = packet_recv.clone();
        forward_tasks.spawn(async move {
            let mut smoltcp_stack_receiver = packet_recv.lock().await;
            while let Some(packet) = smoltcp_stack_receiver.recv().await {
                tracing::trace!(?packet, "receive from peer send to smoltcp packet");
                if let Err(e) = stack_sink.send(Ok(packet.payload().to_vec())).await {
                    tracing::error!("send to smoltcp stack failed: {:?}", e);
                }
            }
            tracing::error!("smoltcp stack sink exited");
            panic!("smoltcp stack sink exited");
        });

        forward_tasks.spawn(async move {
            while let Some(data) = stack_stream.recv().await {
                tracing::trace!(
                    ?data,
                    "receive from smoltcp stack and send to peer mgr packet, len = {}",
                    data.len()
                );
                let Some(ipv4) = Ipv4Packet::new(&data) else {
                    tracing::error!(?data, "smoltcp stack stream get non ipv4 packet");
                    continue;
                };

                let dst = ipv4.get_destination();
                let packet = ZCPacket::new_with_payload(&data);
                if let Err(e) = peer_manager.send_msg_by_ip(packet, IpAddr::V4(dst)).await {
                    tracing::error!("send to peer failed in smoltcp sender: {:?}", e);
                }
            }
            tracing::error!("smoltcp stack stream exited");
            panic!("smoltcp stack stream exited");
        });

        let interface_config = smoltcp::iface::Config::new(smoltcp::wire::HardwareAddress::Ip);
        let net = Net::new(
            dev,
            NetConfig::new(
                interface_config,
                format!("{}/{}", ipv4_addr.address(), ipv4_addr.network_length())
                    .parse()
                    .unwrap(),
                vec![format!("{}", ipv4_addr.address()).parse().unwrap()],
                Some(BufferSize {
                    tcp_rx_size: 1024 * 128,
                    tcp_tx_size: 1024 * 128,
                    ..Default::default()
                }),
            ),
        );

        Self {
            ipv4_addr,
            auth,

            smoltcp_net: Arc::new(net),
            forward_tasks: Arc::new(std::sync::Mutex::new(forward_tasks)),

            entries,
        }
    }

    fn handle_tcp_stream(&self, stream: tokio::net::TcpStream) {
        let mut config = Config::<AcceptAuthentication>::default();
        config.set_request_timeout(10);
        config.set_skip_auth(false);
        config.set_allow_no_auth(true);

        let socket = Socks5Socket::new(
            stream,
            Arc::new(config),
            SmolTcpConnector {
                net: self.smoltcp_net.clone(),
                entries: self.entries.clone(),
                current_entry: std::sync::Mutex::new(None),
            },
        );

        self.forward_tasks.lock().unwrap().spawn(async move {
            match socket.upgrade_to_socks5().await {
                Ok(_) => {
                    tracing::info!("socks5 handle success");
                }
                Err(e) => {
                    tracing::error!("socks5 handshake failed: {:?}", e);
                }
            };
        });
    }
}

struct UdpClientInfo {
    client_addr: SocketAddr,
    port_holder_socket: Arc<UdpSocket>,
    local_addr: SocketAddr,
    last_active: AtomicCell<Instant>,
    entries: Socks5EntrySet,
    entry_key: Socks5Entry,
}

#[derive(Debug, Eq, PartialEq, Hash, Clone)]
struct UdpClientKey {
    client_addr: SocketAddr,
    dst_addr: SocketAddr,
}

pub struct Socks5Server {
    global_ctx: Arc<GlobalCtx>,
    peer_manager: Arc<PeerManager>,
    auth: Option<SimpleUserPassword>,

    tasks: Arc<std::sync::Mutex<JoinSet<()>>>,
    packet_sender: mpsc::Sender<ZCPacket>,
    packet_recv: Arc<Mutex<mpsc::Receiver<ZCPacket>>>,

    net: Arc<Mutex<Option<Socks5ServerNet>>>,
    entries: Socks5EntrySet,

    tcp_forward_task: Arc<std::sync::Mutex<JoinSet<()>>>,
    udp_client_map: Arc<DashMap<UdpClientKey, Arc<UdpClientInfo>>>,
    udp_forward_task: Arc<DashMap<UdpClientKey, ScopedTask<()>>>,

    kcp_endpoint: Mutex<Option<Weak<KcpEndpoint>>>,

    cancel_tokens: DashMap<PortForwardConfig, DropGuard>,
}

#[async_trait::async_trait]
impl PeerPacketFilter for Socks5Server {
    async fn try_process_packet_from_peer(&self, packet: ZCPacket) -> Option<ZCPacket> {
        let hdr = packet.peer_manager_header().unwrap();
        if hdr.packet_type != PacketType::Data as u8 {
            return Some(packet);
        };

        let payload_bytes = packet.payload();

        let ipv4 = Ipv4Packet::new(payload_bytes).unwrap();
        if ipv4.get_version() != 4 {
            return Some(packet);
        }

        let entry_key = match ipv4.get_next_level_protocol() {
            IpNextHeaderProtocols::Tcp => {
                let tcp_packet = TcpPacket::new(ipv4.payload()).unwrap();
                Socks5Entry {
                    dst: SocketAddr::new(ipv4.get_source().into(), tcp_packet.get_source()),
                    src: SocketAddr::new(
                        ipv4.get_destination().into(),
                        tcp_packet.get_destination(),
                    ),
                    entry_type: TCP_ENTRY,
                }
            }

            IpNextHeaderProtocols::Udp => {
                if IpReassembler::is_packet_fragmented(&ipv4) && !self.entries.is_empty() {
                    let ipv4_src: IpAddr = ipv4.get_source().into();
                    // only send to smoltcp if the ipv4 src is in the entries
                    let is_in_entries = self.entries.iter().any(|x| x.key().dst.ip() == ipv4_src);
                    tracing::trace!(
                        ?is_in_entries,
                        "ipv4 src = {:?}, check need send both smoltcp and kernel tun",
                        ipv4_src
                    );
                    if is_in_entries {
                        // if the packet is fragmented, no matther what the payload is, need send it to both smoltcp and kernel tun. because
                        // we cannot determine the udp port of the packet.
                        let _ = self.packet_sender.try_send(packet.clone()).ok();
                    }
                    return Some(packet);
                }

                let udp_packet = UdpPacket::new(ipv4.payload()).unwrap();
                Socks5Entry {
                    dst: SocketAddr::new(ipv4.get_source().into(), udp_packet.get_source()),
                    src: SocketAddr::new(
                        ipv4.get_destination().into(),
                        udp_packet.get_destination(),
                    ),
                    entry_type: UDP_ENTRY,
                }
            }
            _ => {
                return Some(packet);
            }
        };

        if !self.entries.contains_key(&entry_key) {
            return Some(packet);
        }

        tracing::trace!(?entry_key, ?ipv4, "socks5 found entry for packet from peer");

        let _ = self.packet_sender.try_send(packet).ok();

        None
    }
}

impl Socks5Server {
    pub fn new(
        global_ctx: Arc<GlobalCtx>,
        peer_manager: Arc<PeerManager>,
        auth: Option<SimpleUserPassword>,
    ) -> Arc<Self> {
        let (packet_sender, packet_recv) = mpsc::channel(1024);
        Arc::new(Self {
            global_ctx,
            peer_manager,
            auth,

            tasks: Arc::new(std::sync::Mutex::new(JoinSet::new())),
            packet_recv: Arc::new(Mutex::new(packet_recv)),
            packet_sender,

            net: Arc::new(Mutex::new(None)),
            entries: Arc::new(DashMap::new()),

            tcp_forward_task: Arc::new(std::sync::Mutex::new(JoinSet::new())),
            udp_client_map: Arc::new(DashMap::new()),
            udp_forward_task: Arc::new(DashMap::new()),

            kcp_endpoint: Mutex::new(None),

            cancel_tokens: DashMap::new(),
        })
    }

    async fn run_net_update_task(self: &Arc<Self>) {
        let net = self.net.clone();
        let global_ctx = self.global_ctx.clone();
        let peer_manager = self.peer_manager.clone();
        let packet_recv = self.packet_recv.clone();
        let entries = self.entries.clone();
        let tcp_forward_task = self.tcp_forward_task.clone();
        let udp_client_map = self.udp_client_map.clone();
        self.tasks.lock().unwrap().spawn(async move {
            let mut prev_ipv4 = None;
            loop {
                let mut event_recv = global_ctx.subscribe();

                let cur_ipv4 = global_ctx.get_ipv4();
                if prev_ipv4 != cur_ipv4 {
                    prev_ipv4 = cur_ipv4;

                    entries.clear();
                    tcp_forward_task.lock().unwrap().abort_all();
                    udp_client_map.clear();

                    if cur_ipv4.is_none() {
                        let _ = net.lock().await.take();
                    } else {
                        net.lock().await.replace(Socks5ServerNet::new(
                            cur_ipv4.unwrap(),
                            None,
                            peer_manager.clone(),
                            packet_recv.clone(),
                            entries.clone(),
                        ));
                    }
                }

                select! {
                    _ = event_recv.recv() => {}
                    _ = tokio::time::sleep(Duration::from_secs(120)) => {}
                }
            }
        });
    }

    pub async fn run(
        self: &Arc<Self>,
        kcp_endpoint: Option<Weak<KcpEndpoint>>,
    ) -> Result<(), Error> {
        *self.kcp_endpoint.lock().await = kcp_endpoint;
        let mut need_start = false;
        if let Some(proxy_url) = self.global_ctx.config.get_socks5_portal() {
            let bind_addr = format!(
                "{}:{}",
                proxy_url.host_str().unwrap(),
                proxy_url.port().unwrap()
            );

            let listener = bind_tcp_socket(
                bind_addr.parse::<SocketAddr>().unwrap(),
                self.global_ctx.net_ns.clone(),
            )?;

            let net = self.net.clone();
            self.tasks.lock().unwrap().spawn(async move {
                loop {
                    match listener.accept().await {
                        Ok((socket, _addr)) => {
                            tracing::info!("accept a new connection, {:?}", socket);
                            if let Some(net) = net.lock().await.as_ref() {
                                net.handle_tcp_stream(socket);
                            }
                        }
                        Err(err) => tracing::error!("accept error = {:?}", err),
                    }
                }
            });

            join_joinset_background(self.tasks.clone(), "socks5 server".to_string());

            need_start = true;
        };

        let cfgs = self.global_ctx.config.get_port_forwards();
        self.reload_port_forwards(&cfgs).await?;
        need_start = need_start || cfgs.len() > 0;

        if need_start {
            self.peer_manager
                .add_packet_process_pipeline(Box::new(self.clone()))
                .await;

            self.run_net_update_task().await;
        }

        Ok(())
    }

    pub async fn reload_port_forwards(&self, cfgs: &Vec<PortForwardConfig>) -> Result<(), Error> {
        // remove entries not in new cfg
        self.cancel_tokens.retain(|k, _| {
            cfgs.iter().any(|cfg| {
                if cfg.dst_addr.ip().is_unspecified() {
                    k.bind_addr == cfg.bind_addr && k.proto == cfg.proto
                } else {
                    k == cfg
                }
            })
        });
        // add new ones
        for cfg in cfgs {
            if !self.cancel_tokens.contains_key(cfg) {
                self.add_port_forward(cfg.clone()).await?;
            }
        }
        Ok(())
    }

    async fn handle_port_forward_connection(
        mut incoming_socket: tokio::net::TcpStream,
        connector: Box<dyn AsyncTcpConnector<S = SocksTcpStream> + Send>,
        dst_addr: SocketAddr,
    ) {
        let outgoing_socket = match connector.tcp_connect(dst_addr, 10).await {
            Ok(socket) => socket,
            Err(e) => {
                tracing::error!("port forward: failed to connect to destination: {:?}", e);
                return;
            }
        };

        let mut outgoing_socket = outgoing_socket;
        match tokio::io::copy_bidirectional(&mut incoming_socket, &mut outgoing_socket).await {
            Ok((from_client, from_server)) => {
                tracing::info!(
                    "port forward connection finished: client->server: {} bytes, server->client: {} bytes",
                    from_client, from_server
                );
            }
            Err(e) => {
                tracing::error!("port forward connection error: {:?}", e);
            }
        }
    }

    pub async fn add_port_forward(&self, cfg: PortForwardConfig) -> Result<(), Error> {
        match cfg.proto.to_lowercase().as_str() {
            "tcp" => {
                self.add_tcp_port_forward(&cfg).await?;
            }
            "udp" => {
                self.add_udp_port_forward(&cfg).await?;
            }
            _ => {
                return Err(anyhow::anyhow!(
                    "unsupported protocol: {}, only support udp / tcp",
                    cfg.proto
                )
                .into());
            }
        }
        self.global_ctx
            .issue_event(GlobalCtxEvent::PortForwardAdded(cfg.clone().into()));
        Ok(())
    }

    pub fn remove_port_forward(&self, cfg: PortForwardConfig) {
        let _ = self.cancel_tokens.remove(&cfg);
    }

    pub async fn add_tcp_port_forward(&self, cfg: &PortForwardConfig) -> Result<(), Error> {
        let (bind_addr, dst_addr) = (cfg.bind_addr, cfg.dst_addr);
        let listener = bind_tcp_socket(bind_addr, self.global_ctx.net_ns.clone())?;

        let net = self.net.clone();
        let entries = self.entries.clone();
        let tasks = Arc::new(std::sync::Mutex::new(JoinSet::new()));
        let forward_tasks = tasks.clone();
        let kcp_endpoint = self.kcp_endpoint.lock().await.clone();
        let peer_mgr = Arc::downgrade(&self.peer_manager.clone());
        let cancel_token = CancellationToken::new();
        self.cancel_tokens
            .insert(cfg.clone(), cancel_token.clone().drop_guard());

        self.tasks.lock().unwrap().spawn(async move {
            loop {
                let (incoming_socket, addr) = select! {
                    biased;
                    _ = cancel_token.cancelled() => {
                        tracing::info!("port forward for {:?} cancelled", bind_addr);
                        break;
                    }
                    res = listener.accept() => {
                        match res {
                            Ok(result) => result,
                            Err(err) => {
                                tracing::error!("port forward accept error = {:?}", err);
                                continue;
                            }
                        }
                    }
                };

                tracing::info!(
                    "port forward: accept new connection from {:?} to {:?}",
                    bind_addr,
                    dst_addr
                );

                let net_guard = net.lock().await;
                let Some(net) = net_guard.as_ref() else {
                    tracing::error!("net is not ready");
                    continue;
                };

                let Some(peer_mgr_arc) = peer_mgr.upgrade() else {
                    tracing::error!("peer manager is dropped");
                    continue;
                };

                let dst_allow_kcp =  peer_mgr_arc.check_allow_kcp_to_dst(&dst_addr.ip()).await;
                tracing::debug!("dst_allow_kcp: {:?}", dst_allow_kcp);

                let connector: Box<dyn AsyncTcpConnector<S = SocksTcpStream> + Send> =
                    if kcp_endpoint.is_none() || !dst_allow_kcp {
                        Box::new(SmolTcpConnector {
                            net: net.smoltcp_net.clone(),
                            entries: entries.clone(),
                            current_entry: std::sync::Mutex::new(None),
                        })
                    } else {
                        let kcp_endpoint = kcp_endpoint.as_ref().unwrap().clone();
                        Box::new(Socks5KcpConnector {
                            kcp_endpoint,
                            peer_mgr: peer_mgr.clone(),
                            src_addr: addr,
                        })
                    };

                forward_tasks
                    .lock()
                    .unwrap()
                    .spawn(Self::handle_port_forward_connection(
                        incoming_socket,
                        connector,
                        dst_addr,
                    ));
            }
        });

        Ok(())
    }

    #[tracing::instrument(name = "add_udp_port_forward", skip(self))]
    pub async fn add_udp_port_forward(&self, cfg: &PortForwardConfig) -> Result<(), Error> {
        let (bind_addr, dst_addr) = (cfg.bind_addr, cfg.dst_addr);
        let socket = Arc::new(bind_udp_socket(bind_addr, self.global_ctx.net_ns.clone())?);

        let entries = self.entries.clone();
        let net_ns = self.global_ctx.net_ns.clone();
        let net = self.net.clone();
        let udp_client_map = self.udp_client_map.clone();
        let udp_forward_task = self.udp_forward_task.clone();
        let cancel_token = CancellationToken::new();
        self.cancel_tokens
            .insert(cfg.clone(), cancel_token.clone().drop_guard());

        self.tasks.lock().unwrap().spawn(async move {
            loop {
                // we set the max buffer size of smoltcp to 8192, so we need to use a buffer size that is less than 8192 here.
                let mut buf = vec![0u8; 8192];
                let (len, addr) = select! {
                    biased;
                    _ = cancel_token.cancelled() => {
                        tracing::info!("udp port forward for {:?} cancelled", bind_addr);
                        break;
                    }
                    res = socket.recv_from(&mut buf) => {
                        match res {
                            Ok(result) => result,
                            Err(err) => {
                                tracing::error!("udp port forward recv error = {:?}", err);
                                continue;
                            }
                        }
                    }
                };

                tracing::trace!(
                    "udp port forward recv packet from {:?}, len = {}",
                    addr,
                    len
                );

                let udp_client_key = UdpClientKey {
                    client_addr: addr,
                    dst_addr,
                };

                let binded_socket = udp_client_map.get(&udp_client_key);
                let client_info = match binded_socket {
                    Some(s) => s.clone(),
                    None => {
                        let _g = net_ns.guard();
                        // reserve a port so os will not use it to connect to the virtual network
                        let binded_socket = tokio::net::UdpSocket::bind("0.0.0.0:0").await;
                        if binded_socket.is_err() {
                            tracing::error!("udp port forward bind error = {:?}", binded_socket);
                            continue;
                        }
                        let binded_socket = binded_socket.unwrap();
                        let mut local_addr = binded_socket.local_addr().unwrap();
                        let Some(cur_ipv4) = net.lock().await.as_ref().map(|net| net.ipv4_addr) else {
                            continue;
                        };
                        local_addr.set_ip(cur_ipv4.address().into());

                        let entry_key = Socks5Entry {
                            src: local_addr,
                            dst: dst_addr,
                            entry_type: UDP_ENTRY,
                        };

                        tracing::debug!("udp port forward binded socket = {:?}, entry_key = {:?}", local_addr, entry_key);

                        let client_info = Arc::new(UdpClientInfo {
                            client_addr: addr,
                            port_holder_socket: Arc::new(binded_socket),
                            local_addr,
                            last_active: AtomicCell::new(Instant::now()),
                            entries: entries.clone(),
                            entry_key,
                        });
                        udp_client_map.insert(udp_client_key.clone(), client_info.clone());
                        client_info
                    }
                };

                client_info.last_active.store(Instant::now());

                let entry_data = match entries.get(&client_info.entry_key) {
                    Some(data) => data,
                    None => {
                        let guard = net.lock().await;
                        let Some(net) = guard.as_ref() else {
                            continue;
                        };
                        let local_addr = net.ipv4_addr;
                        let sokcs_udp = if dst_addr.ip() == local_addr.address() {
                            SocksUdpSocket::UdpSocket(client_info.port_holder_socket.clone())
                        } else {
                            tracing::debug!("udp port forward bind new smol udp socket, {:?}", local_addr);
                            SocksUdpSocket::SmolUdpSocket(
                                net.smoltcp_net
                                    .udp_bind(SocketAddr::new(
                                        IpAddr::V4(local_addr.address()),
                                        client_info.local_addr.port(),
                                    ))
                                    .await
                                    .unwrap(),
                            )
                        };
                        let socks_udp = Arc::new(sokcs_udp);
                        entries.insert(
                            client_info.entry_key.clone(),
                            Socks5EntryData::Udp((socks_udp.clone(), udp_client_key.clone())),
                        );

                        let socks = socket.clone();
                        let client_addr = addr;
                        udp_forward_task.insert(
                            udp_client_key.clone(),
                            ScopedTask::from(tokio::spawn(async move {
                                loop {
                                    let mut buf = vec![0u8; 8192];
                                    match socks_udp.recv_from(&mut buf).await {
                                        Ok((len, dst_addr)) => {
                                            tracing::trace!(
                                                "udp port forward recv response packet from {:?}, len = {}, client_addr = {:?}",
                                                dst_addr,
                                                len,
                                                client_addr
                                            );
                                            if let Err(e) = socks.send_to(&buf[..len], client_addr).await {
                                                tracing::error!("udp forward send error = {:?}", e);
                                            }
                                        }
                                        Err(e) => {
                                            tracing::error!("udp forward recv error = {:?}", e);
                                        }
                                    }
                                }
                            })),
                        );

                        entries.get(&client_info.entry_key).unwrap()
                    }
                };

                let s = match entry_data.value() {
                    Socks5EntryData::Udp((s, _)) => s.clone(),
                    _ => {
                        panic!("udp entry data is not udp entry data");
                    }
                };
                drop(entry_data);

                if let Err(e) = s.send_to(&buf[..len], dst_addr).await {
                    tracing::error!(?dst_addr, ?len, "udp port forward send error = {:?}", e);
                } else {
                    tracing::trace!(?dst_addr, ?len, "udp port forward send packet success");
                }
            }
        });

        // clean up task
        let udp_client_map = self.udp_client_map.clone();
        let udp_forward_task = self.udp_forward_task.clone();
        let entries = self.entries.clone();
        self.tasks.lock().unwrap().spawn(async move {
            loop {
                tokio::time::sleep(Duration::from_secs(30)).await;
                let now = Instant::now();
                udp_client_map.retain(|_, client_info| {
                    now.duration_since(client_info.last_active.load()).as_secs() < 600
                });
                udp_forward_task.retain(|k, _| udp_client_map.contains_key(&k));
                entries.retain(|_, data| match data {
                    Socks5EntryData::Udp((_, udp_client_key)) => {
                        udp_client_map.contains_key(&udp_client_key)
                    }
                    _ => true,
                });
            }
        });

        Ok(())
    }
}
