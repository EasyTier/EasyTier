use std::{
    net::{Ipv4Addr, SocketAddr},
    sync::Arc,
    time::Duration,
};

use crate::{
    gateway::{
        fast_socks5::server::{
            AcceptAuthentication, AsyncTcpConnector, Config, SimpleUserPassword, Socks5Socket,
        },
        tokio_smoltcp::TcpStream,
    },
    tunnel::packet_def::PacketType,
};
use anyhow::Context;
use dashmap::DashSet;
use pnet::packet::{ip::IpNextHeaderProtocols, ipv4::Ipv4Packet, tcp::TcpPacket, Packet};
use tokio::select;
use tokio::{
    net::TcpListener,
    sync::{mpsc, Mutex},
    task::JoinSet,
    time::timeout,
};

use crate::{
    common::{error::Error, global_ctx::GlobalCtx},
    gateway::tokio_smoltcp::{channel_device, Net, NetConfig},
    peers::{peer_manager::PeerManager, PeerPacketFilter},
    tunnel::packet_def::ZCPacket,
};

#[derive(Debug, Eq, PartialEq, Hash, Clone)]
struct Socks5Entry {
    src: SocketAddr,
    dst: SocketAddr,
}

type Socks5EntrySet = Arc<DashSet<Socks5Entry>>;

struct Socks5ServerNet {
    ipv4_addr: Ipv4Addr,
    auth: Option<SimpleUserPassword>,

    smoltcp_net: Arc<Net>,
    forward_tasks: Arc<std::sync::Mutex<JoinSet<()>>>,

    entries: Socks5EntrySet,
}

impl Socks5ServerNet {
    pub fn new(
        ipv4_addr: Ipv4Addr,
        auth: Option<SimpleUserPassword>,
        peer_manager: Arc<PeerManager>,
        packet_recv: Arc<Mutex<mpsc::Receiver<ZCPacket>>>,
        entries: Socks5EntrySet,
    ) -> Self {
        let mut forward_tasks = JoinSet::new();
        let mut cap = smoltcp::phy::DeviceCapabilities::default();
        cap.max_transmission_unit = 1280;
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
                    "receive from smoltcp stack and send to peer mgr packet"
                );
                let Some(ipv4) = Ipv4Packet::new(&data) else {
                    tracing::error!(?data, "smoltcp stack stream get non ipv4 packet");
                    continue;
                };

                let dst = ipv4.get_destination();
                let packet = ZCPacket::new_with_payload(&data);
                if let Err(e) = peer_manager.send_msg_ipv4(packet, dst).await {
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
                format!("{}/24", ipv4_addr).parse().unwrap(),
                vec![format!("{}", ipv4_addr).parse().unwrap()],
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

        struct SmolTcpConnector(
            Arc<Net>,
            Socks5EntrySet,
            std::sync::Mutex<Option<Socks5Entry>>,
        );

        #[async_trait::async_trait]
        impl AsyncTcpConnector for SmolTcpConnector {
            type S = TcpStream;

            async fn tcp_connect(
                &self,
                addr: SocketAddr,
                timeout_s: u64,
            ) -> crate::gateway::fast_socks5::Result<TcpStream> {
                let port = self.0.get_port();

                let entry = Socks5Entry {
                    src: SocketAddr::new(self.0.get_address(), port),
                    dst: addr,
                };
                *self.2.lock().unwrap() = Some(entry.clone());
                self.1.insert(entry);

                let remote_socket = timeout(
                    Duration::from_secs(timeout_s),
                    self.0.tcp_connect(addr, port),
                )
                .await
                .with_context(|| "connect to remote timeout")?;

                remote_socket.map_err(|e| super::fast_socks5::SocksError::Other(e.into()))
            }
        }

        impl Drop for SmolTcpConnector {
            fn drop(&mut self) {
                if let Some(entry) = self.2.lock().unwrap().take() {
                    self.1.remove(&entry);
                }
            }
        }

        let socket = Socks5Socket::new(
            stream,
            Arc::new(config),
            SmolTcpConnector(
                self.smoltcp_net.clone(),
                self.entries.clone(),
                std::sync::Mutex::new(None),
            ),
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

pub struct Socks5Server {
    global_ctx: Arc<GlobalCtx>,
    peer_manager: Arc<PeerManager>,
    auth: Option<SimpleUserPassword>,

    tasks: Arc<Mutex<JoinSet<()>>>,
    packet_sender: mpsc::Sender<ZCPacket>,
    packet_recv: Arc<Mutex<mpsc::Receiver<ZCPacket>>>,

    net: Arc<Mutex<Option<Socks5ServerNet>>>,
    entries: Socks5EntrySet,
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
        if ipv4.get_version() != 4 || ipv4.get_next_level_protocol() != IpNextHeaderProtocols::Tcp {
            return Some(packet);
        }

        let tcp_packet = TcpPacket::new(ipv4.payload()).unwrap();
        let entry = Socks5Entry {
            dst: SocketAddr::new(ipv4.get_source().into(), tcp_packet.get_source()),
            src: SocketAddr::new(ipv4.get_destination().into(), tcp_packet.get_destination()),
        };

        if !self.entries.contains(&entry) {
            return Some(packet);
        }

        let _ = self.packet_sender.try_send(packet).ok();
        return None;
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

            tasks: Arc::new(Mutex::new(JoinSet::new())),
            packet_recv: Arc::new(Mutex::new(packet_recv)),
            packet_sender,

            net: Arc::new(Mutex::new(None)),
            entries: Arc::new(DashSet::new()),
        })
    }

    async fn run_net_update_task(self: &Arc<Self>) {
        let net = self.net.clone();
        let global_ctx = self.global_ctx.clone();
        let peer_manager = self.peer_manager.clone();
        let packet_recv = self.packet_recv.clone();
        let entries = self.entries.clone();
        self.tasks.lock().await.spawn(async move {
            let mut prev_ipv4 = None;
            loop {
                let mut event_recv = global_ctx.subscribe();

                let cur_ipv4 = global_ctx.get_ipv4();
                if prev_ipv4 != cur_ipv4 {
                    prev_ipv4 = cur_ipv4;
                    entries.clear();

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

    pub async fn run(self: &Arc<Self>) -> Result<(), Error> {
        let Some(proxy_url) = self.global_ctx.config.get_socks5_portal() else {
            return Ok(());
        };

        let bind_addr = format!(
            "{}:{}",
            proxy_url.host_str().unwrap(),
            proxy_url.port().unwrap()
        );

        let listener = {
            let _g = self.global_ctx.net_ns.guard();
            TcpListener::bind(bind_addr.parse::<SocketAddr>().unwrap()).await?
        };

        self.peer_manager
            .add_packet_process_pipeline(Box::new(self.clone()))
            .await;

        self.run_net_update_task().await;

        let net = self.net.clone();
        self.tasks.lock().await.spawn(async move {
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

        Ok(())
    }
}
