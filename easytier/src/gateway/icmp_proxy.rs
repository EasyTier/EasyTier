use std::{
    mem::MaybeUninit,
    net::{IpAddr, Ipv4Addr, SocketAddrV4},
    sync::{Arc, Weak},
    thread,
    time::Duration,
};

use anyhow::Context;
use socket2::Socket;
use tokio::{
    sync::{Mutex, mpsc::UnboundedSender},
    task::JoinSet,
};

use tracing::Instrument;

use easytier_core::proxy::icmp_proxy_engine::{IcmpProxyAction, IcmpProxyContext, IcmpProxyEngine};

use crate::{
    common::{error::Error, global_ctx::ArcGlobalCtx},
    peers::{PeerPacketFilter, peer_manager::PeerManager},
    tunnel::packet_def::ZCPacket,
};

use super::CidrSet;

#[derive(Debug)]
pub struct IcmpProxy {
    global_ctx: ArcGlobalCtx,
    peer_manager: Weak<PeerManager>,

    cidr_set: CidrSet,
    socket: std::sync::Mutex<Option<Arc<socket2::Socket>>>,
    engine: Arc<IcmpProxyEngine>,

    tasks: Mutex<JoinSet<()>>,
    icmp_sender: Arc<std::sync::Mutex<Option<UnboundedSender<ZCPacket>>>>,
}

fn socket_recv(
    socket: &Socket,
    buf: &mut [MaybeUninit<u8>],
) -> Result<(usize, IpAddr), std::io::Error> {
    let (size, addr) = socket.recv_from(buf)?;
    let addr = match addr.as_socket() {
        None => IpAddr::V4(Ipv4Addr::UNSPECIFIED),
        Some(add) => add.ip(),
    };
    Ok((size, addr))
}

fn socket_recv_loop(
    socket: Arc<Socket>,
    engine: Arc<IcmpProxyEngine>,
    sender: UnboundedSender<ZCPacket>,
) {
    let mut buf = [0u8; 8192];
    let data: &mut [MaybeUninit<u8>] = unsafe { std::mem::transmute(&mut buf[..]) };

    loop {
        let (len, peer_ip) = match socket_recv(&socket, data) {
            Ok((len, peer_ip)) => (len, peer_ip),
            Err(e) => {
                tracing::error!("recv icmp packet failed: {:?}", e);
                if sender.is_closed() {
                    break;
                } else {
                    continue;
                }
            }
        };

        if len == 0 {
            tracing::error!("recv empty packet, len: {}", len);
            return;
        }

        let IpAddr::V4(peer_ip) = peer_ip else {
            continue;
        };

        for packet in engine.handle_socket_response(peer_ip, &mut buf[..len]) {
            if let Err(e) = sender.send(packet) {
                tracing::error!("send icmp packet to peer failed: {:?}, may exiting..", e);
            }
        }
    }
}

#[async_trait::async_trait]
impl PeerPacketFilter for IcmpProxy {
    async fn try_process_packet_from_peer(&self, packet: ZCPacket) -> Option<ZCPacket> {
        let context = IcmpProxyContext {
            virtual_ipv4: self
                .global_ctx
                .get_ipv4()
                .as_ref()
                .map(cidr::Ipv4Inet::address),
            enable_exit_node: self.global_ctx.enable_exit_node(),
            no_tun: self.global_ctx.no_tun(),
        };
        match self.engine.handle_peer_packet(&packet, context) {
            IcmpProxyAction::Pass => Some(packet),
            IcmpProxyAction::SendToSocket {
                destination,
                packet: request,
            } => {
                if let Err(e) = self.send_icmp_packet(destination, &request) {
                    tracing::error!("send icmp packet failed: {:?}", e);
                }
                None
            }
            IcmpProxyAction::SendToPeer(packets) => {
                let sender = self.icmp_sender.lock().unwrap();
                let sender = sender.as_ref().expect("ICMP proxy sender is initialized");
                for packet in packets {
                    let _ = sender.send(packet);
                }
                None
            }
        }
    }
}

impl IcmpProxy {
    pub fn new(
        global_ctx: ArcGlobalCtx,
        peer_manager: Arc<PeerManager>,
    ) -> Result<Arc<Self>, Error> {
        let cidr_set = CidrSet::new(global_ctx.clone());
        let engine = Arc::new(IcmpProxyEngine::new(
            cidr_set.table(),
            Duration::from_secs(10),
        ));
        let ret = Self {
            global_ctx,
            peer_manager: Arc::downgrade(&peer_manager),
            cidr_set,
            socket: std::sync::Mutex::new(None),
            engine,
            tasks: Mutex::new(JoinSet::new()),
            icmp_sender: Arc::new(std::sync::Mutex::new(None)),
        };

        Ok(Arc::new(ret))
    }

    fn create_raw_socket(self: &Arc<Self>) -> Result<Socket, Error> {
        let _g = self.global_ctx.net_ns.guard();
        let socket = socket2::Socket::new(
            socket2::Domain::IPV4,
            socket2::Type::RAW,
            Some(socket2::Protocol::ICMPV4),
        )?;
        socket.bind(&socket2::SockAddr::from(SocketAddrV4::new(
            std::net::Ipv4Addr::UNSPECIFIED,
            0,
        )))?;
        Ok(socket)
    }

    pub async fn start(self: &Arc<Self>) -> Result<(), Error> {
        let socket = self.create_raw_socket();
        match socket {
            Ok(socket) => {
                self.socket.lock().unwrap().replace(Arc::new(socket));
            }
            Err(e) => {
                tracing::warn!("create icmp socket failed: {:?}", e);
                if !self.global_ctx.no_tun() {
                    return Err(anyhow::anyhow!("create icmp socket failed: {:?}", e).into());
                }
            }
        }

        self.start_icmp_proxy().await?;
        self.start_nat_table_cleaner().await?;
        Ok(())
    }

    async fn start_nat_table_cleaner(self: &Arc<Self>) -> Result<(), Error> {
        let engine = self.engine.clone();
        self.tasks.lock().await.spawn(
            async move {
                loop {
                    tokio::time::sleep(std::time::Duration::from_secs(1)).await;
                    engine.remove_expired_entries(Duration::from_secs(20));
                }
            }
            .instrument(tracing::info_span!("icmp proxy nat table cleaner")),
        );
        Ok(())
    }

    async fn start_icmp_proxy(self: &Arc<Self>) -> Result<(), Error> {
        let (sender, mut receiver) = tokio::sync::mpsc::unbounded_channel();
        self.icmp_sender.lock().unwrap().replace(sender.clone());
        if let Some(socket) = self.socket.lock().unwrap().as_ref() {
            let socket = socket.clone();
            let engine = self.engine.clone();
            thread::spawn(|| {
                socket_recv_loop(socket, engine, sender);
            });
        }

        let peer_manager = self.peer_manager.clone();
        let is_latency_first = self.global_ctx.latency_first();
        self.tasks.lock().await.spawn(
            async move {
                while let Some(mut msg) = receiver.recv().await {
                    let hdr = msg.mut_peer_manager_header().unwrap();
                    hdr.set_latency_first(is_latency_first);
                    let to_peer_id = hdr.to_peer_id.into();
                    let Some(pm) = peer_manager.upgrade() else {
                        tracing::warn!("peer manager is gone, icmp proxy send loop exit");
                        return;
                    };
                    let ret = pm.send_msg_for_proxy(msg, to_peer_id).await;
                    if ret.is_err() {
                        tracing::error!("send icmp packet to peer failed: {:?}", ret);
                    }
                }
            }
            .instrument(tracing::info_span!("icmp proxy send loop")),
        );

        let engine = self.engine.clone();
        self.tasks.lock().await.spawn(async move {
            loop {
                tokio::time::sleep(Duration::from_secs(1)).await;
                engine.remove_expired_fragments();
            }
        });

        let Some(pm) = self.peer_manager.upgrade() else {
            tracing::warn!("peer manager is gone, icmp proxy init failed");
            return Err(anyhow::anyhow!("peer manager is gone").into());
        };

        pm.add_packet_process_pipeline(Box::new(self.clone())).await;
        Ok(())
    }

    fn send_icmp_packet(&self, dst_ip: Ipv4Addr, packet: &[u8]) -> Result<(), Error> {
        self.socket
            .lock()
            .unwrap()
            .as_ref()
            .with_context(|| "icmp socket not created")?
            .send_to(packet, &SocketAddrV4::new(dst_ip, 0).into())?;

        Ok(())
    }
}

impl Drop for IcmpProxy {
    fn drop(&mut self) {
        tracing::info!(
            "dropping icmp proxy, {:?}",
            self.socket.lock().unwrap().as_ref()
        );
        if let Some(s) = self.socket.lock().unwrap().as_ref() {
            tracing::info!("shutting down icmp socket");
            let _ = s.shutdown(std::net::Shutdown::Both);
        }
    }
}
