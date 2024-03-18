use std::{net::SocketAddr, sync::Arc};

use anyhow::Context;
use crossbeam::atomic::AtomicCell;
use rand::{seq::SliceRandom, Rng, SeedableRng};
use tokio::{net::UdpSocket, sync::Mutex, task::JoinSet};
use tracing::Instrument;

use crate::{
    common::{
        constants, error::Error, global_ctx::ArcGlobalCtx, rkyv_util::encode_to_bytes,
        stun::StunInfoCollectorTrait, PeerId,
    },
    peers::peer_manager::PeerManager,
    rpc::NatType,
    tunnels::{
        common::setup_sokcet2,
        udp_tunnel::{UdpPacket, UdpTunnelConnector, UdpTunnelListener},
        Tunnel, TunnelConnCounter, TunnelListener,
    },
};

use super::direct::PeerManagerForDirectConnector;

#[tarpc::service]
pub trait UdpHolePunchService {
    async fn try_punch_hole(local_mapped_addr: SocketAddr) -> Option<SocketAddr>;
}

#[derive(Debug)]
struct UdpHolePunchListener {
    socket: Arc<UdpSocket>,
    tasks: JoinSet<()>,
    running: Arc<AtomicCell<bool>>,
    mapped_addr: SocketAddr,
    conn_counter: Arc<Box<dyn TunnelConnCounter>>,

    listen_time: std::time::Instant,
    last_select_time: AtomicCell<std::time::Instant>,
    last_connected_time: Arc<AtomicCell<std::time::Instant>>,
}

impl UdpHolePunchListener {
    async fn get_avail_port() -> Result<u16, Error> {
        let socket = UdpSocket::bind("0.0.0.0:0").await?;
        Ok(socket.local_addr()?.port())
    }

    pub async fn new(peer_mgr: Arc<PeerManager>) -> Result<Self, Error> {
        let port = Self::get_avail_port().await?;
        let listen_url = format!("udp://0.0.0.0:{}", port);

        let gctx = peer_mgr.get_global_ctx();
        let stun_info_collect = gctx.get_stun_info_collector();
        let mapped_addr = stun_info_collect.get_udp_port_mapping(port).await?;

        let mut listener = UdpTunnelListener::new(listen_url.parse().unwrap());

        {
            let _g = peer_mgr.get_global_ctx().net_ns.guard();
            listener.listen().await?;
        }
        let socket = listener.get_socket().unwrap();

        let running = Arc::new(AtomicCell::new(true));
        let running_clone = running.clone();

        let last_connected_time = Arc::new(AtomicCell::new(std::time::Instant::now()));
        let last_connected_time_clone = last_connected_time.clone();

        let conn_counter = listener.get_conn_counter();
        let mut tasks = JoinSet::new();

        tasks.spawn(async move {
            while let Ok(conn) = listener.accept().await {
                last_connected_time_clone.store(std::time::Instant::now());
                tracing::warn!(?conn, "udp hole punching listener got peer connection");
                if let Err(e) = peer_mgr.add_tunnel_as_server(conn).await {
                    tracing::error!(?e, "failed to add tunnel as server in hole punch listener");
                }
            }

            running_clone.store(false);
        });

        tracing::warn!(?mapped_addr, ?socket, "udp hole punching listener started");

        Ok(Self {
            tasks,
            socket,
            running,
            mapped_addr,
            conn_counter,

            listen_time: std::time::Instant::now(),
            last_select_time: AtomicCell::new(std::time::Instant::now()),
            last_connected_time,
        })
    }

    pub async fn get_socket(&self) -> Arc<UdpSocket> {
        self.last_select_time.store(std::time::Instant::now());
        self.socket.clone()
    }
}

#[derive(Debug)]
struct UdpHolePunchConnectorData {
    global_ctx: ArcGlobalCtx,
    peer_mgr: Arc<PeerManager>,
    listeners: Arc<Mutex<Vec<UdpHolePunchListener>>>,
}

#[derive(Clone)]
struct UdpHolePunchRpcServer {
    data: Arc<UdpHolePunchConnectorData>,

    tasks: Arc<Mutex<JoinSet<()>>>,
}

#[tarpc::server]
impl UdpHolePunchService for UdpHolePunchRpcServer {
    async fn try_punch_hole(
        self,
        _: tarpc::context::Context,
        local_mapped_addr: SocketAddr,
    ) -> Option<SocketAddr> {
        let (socket, mapped_addr) = self.select_listener().await?;
        tracing::warn!(?local_mapped_addr, ?mapped_addr, "start hole punching");

        let my_udp_nat_type = self
            .data
            .global_ctx
            .get_stun_info_collector()
            .get_stun_info()
            .udp_nat_type;

        // if we are restricted, we need to send hole punching resp to client
        if my_udp_nat_type == NatType::PortRestricted as i32
            || my_udp_nat_type == NatType::Restricted as i32
        {
            // send punch msg to local_mapped_addr for 3 seconds, 3.3 packet per second
            self.tasks.lock().await.spawn(async move {
                for _ in 0..10 {
                    tracing::info!(?local_mapped_addr, "sending hole punching packet");
                    // generate a 128 bytes vec with random data
                    let mut rng = rand::rngs::StdRng::from_entropy();
                    let mut buf = vec![0u8; 128];
                    rng.fill(&mut buf[..]);

                    let udp_packet = UdpPacket::new_hole_punch_packet(buf);
                    let udp_packet_bytes = encode_to_bytes::<_, 256>(&udp_packet);
                    let _ = socket
                        .send_to(udp_packet_bytes.as_ref(), local_mapped_addr)
                        .await;
                    tokio::time::sleep(std::time::Duration::from_millis(300)).await;
                }
            });
        }

        Some(mapped_addr)
    }
}

impl UdpHolePunchRpcServer {
    pub fn new(data: Arc<UdpHolePunchConnectorData>) -> Self {
        Self {
            data,
            tasks: Arc::new(Mutex::new(JoinSet::new())),
        }
    }

    async fn select_listener(&self) -> Option<(Arc<UdpSocket>, SocketAddr)> {
        let all_listener_sockets = &self.data.listeners;

        // remove listener that not have connection in for 20 seconds
        all_listener_sockets.lock().await.retain(|listener| {
            listener.last_connected_time.load().elapsed().as_secs() < 20
                && listener.conn_counter.get() > 0
        });

        let mut use_last = false;
        if all_listener_sockets.lock().await.len() < 4 {
            tracing::warn!("creating new udp hole punching listener");
            all_listener_sockets.lock().await.push(
                UdpHolePunchListener::new(self.data.peer_mgr.clone())
                    .await
                    .ok()?,
            );
            use_last = true;
        }

        let locked = all_listener_sockets.lock().await;

        let listener = if use_last {
            locked.last()?
        } else {
            locked.choose(&mut rand::rngs::StdRng::from_entropy())?
        };

        Some((listener.get_socket().await, listener.mapped_addr))
    }
}

pub struct UdpHolePunchConnector {
    data: Arc<UdpHolePunchConnectorData>,
    tasks: JoinSet<()>,
}

// Currently support:
// Symmetric -> Full Cone
// Any Type of Full Cone -> Any Type of Full Cone

// if same level of full cone, node with smaller peer_id will be the initiator
// if different level of full cone, node with more strict level will be the initiator

impl UdpHolePunchConnector {
    pub fn new(global_ctx: ArcGlobalCtx, peer_mgr: Arc<PeerManager>) -> Self {
        Self {
            data: Arc::new(UdpHolePunchConnectorData {
                global_ctx,
                peer_mgr,
                listeners: Arc::new(Mutex::new(Vec::new())),
            }),
            tasks: JoinSet::new(),
        }
    }

    pub async fn run_as_client(&mut self) -> Result<(), Error> {
        let data = self.data.clone();
        self.tasks.spawn(async move {
            Self::main_loop(data).await;
        });

        Ok(())
    }

    pub async fn run_as_server(&mut self) -> Result<(), Error> {
        self.data.peer_mgr.get_peer_rpc_mgr().run_service(
            constants::UDP_HOLE_PUNCH_CONNECTOR_SERVICE_ID,
            UdpHolePunchRpcServer::new(self.data.clone()).serve(),
        );

        Ok(())
    }

    pub async fn run(&mut self) -> Result<(), Error> {
        self.run_as_client().await?;
        self.run_as_server().await?;

        Ok(())
    }

    async fn collect_peer_to_connect(data: Arc<UdpHolePunchConnectorData>) -> Vec<PeerId> {
        let mut peers_to_connect = Vec::new();

        // do not do anything if:
        // 1. our stun test has not finished
        // 2. our nat type is OpenInternet or NoPat, which means we can wait other peers to connect us
        let my_nat_type = data
            .global_ctx
            .get_stun_info_collector()
            .get_stun_info()
            .udp_nat_type;

        let my_nat_type = NatType::try_from(my_nat_type).unwrap();

        if my_nat_type == NatType::Unknown
            || my_nat_type == NatType::OpenInternet
            || my_nat_type == NatType::NoPat
        {
            return peers_to_connect;
        }

        // collect peer list from peer manager and do some filter:
        // 1. peers without direct conns;
        // 2. peers is full cone (any restricted type);
        for route in data.peer_mgr.list_routes().await.iter() {
            let Some(peer_stun_info) = route.stun_info.as_ref() else {
                continue;
            };
            let Ok(peer_nat_type) = NatType::try_from(peer_stun_info.udp_nat_type) else {
                continue;
            };

            let peer_id: PeerId = route.peer_id;
            let conns = data.peer_mgr.list_peer_conns(peer_id).await;
            if conns.is_some() && conns.unwrap().len() > 0 {
                continue;
            }

            // if peer is symmetric ignore it because we cannot connect to it
            // if peer is open internet or no pat, direct connector will connecto to it
            if peer_nat_type == NatType::Unknown
                || peer_nat_type == NatType::OpenInternet
                || peer_nat_type == NatType::NoPat
                || peer_nat_type == NatType::Symmetric
                || peer_nat_type == NatType::SymUdpFirewall
            {
                continue;
            }

            // if we are symmetric, we can only connect to full cone
            // TODO: can also connect to restricted full cone, with some extra work
            if (my_nat_type == NatType::Symmetric || my_nat_type == NatType::SymUdpFirewall)
                && peer_nat_type != NatType::FullCone
            {
                continue;
            }

            // if we have smae level of full cone, node with smaller peer_id will be the initiator
            if my_nat_type == peer_nat_type {
                if data.peer_mgr.my_peer_id() > peer_id {
                    continue;
                }
            } else {
                // if we have different level of full cone
                // we will be the initiator if we have more strict level
                if my_nat_type < peer_nat_type {
                    continue;
                }
            }

            tracing::info!(
                ?peer_id,
                ?peer_nat_type,
                ?my_nat_type,
                ?data.global_ctx.id,
                "found peer to do hole punching"
            );

            peers_to_connect.push(peer_id);
        }

        peers_to_connect
    }

    #[tracing::instrument]
    async fn do_hole_punching(
        data: Arc<UdpHolePunchConnectorData>,
        dst_peer_id: PeerId,
    ) -> Result<Box<dyn Tunnel>, anyhow::Error> {
        tracing::info!(?dst_peer_id, "start hole punching");
        // client: choose a local udp port, and get the pubic mapped port from stun server
        let socket = {
            let _g = data.global_ctx.net_ns.guard();
            UdpSocket::bind("0.0.0.0:0").await.with_context(|| "")?
        };
        let local_socket_addr = socket.local_addr()?;
        let local_port = socket.local_addr()?.port();
        drop(socket); // drop the socket to release the port

        let local_mapped_addr = data
            .global_ctx
            .get_stun_info_collector()
            .get_udp_port_mapping(local_port)
            .await
            .with_context(|| "failed to get udp port mapping")?;

        // client -> server: tell server the mapped port, server will return the mapped address of listening port.
        let Some(remote_mapped_addr) = data
            .peer_mgr
            .get_peer_rpc_mgr()
            .do_client_rpc_scoped(
                constants::UDP_HOLE_PUNCH_CONNECTOR_SERVICE_ID,
                dst_peer_id,
                |c| async {
                    let client =
                        UdpHolePunchServiceClient::new(tarpc::client::Config::default(), c).spawn();
                    let remote_mapped_addr = client
                        .try_punch_hole(tarpc::context::current(), local_mapped_addr)
                        .await;
                    tracing::info!(?remote_mapped_addr, ?dst_peer_id, "got remote mapped addr");
                    remote_mapped_addr
                },
            )
            .await?
        else {
            return Err(anyhow::anyhow!("failed to get remote mapped addr"));
        };

        // server: will send some punching resps, total 10 packets.
        // client: use the socket to create UdpTunnel with UdpTunnelConnector
        // NOTICE: UdpTunnelConnector will ignore the punching resp packet sent by remote.

        let connector = UdpTunnelConnector::new(
            format!(
                "udp://{}:{}",
                remote_mapped_addr.ip(),
                remote_mapped_addr.port()
            )
            .to_string()
            .parse()
            .unwrap(),
        );

        let _g = data.global_ctx.net_ns.guard();
        let socket2_socket = socket2::Socket::new(
            socket2::Domain::for_address(local_socket_addr),
            socket2::Type::DGRAM,
            Some(socket2::Protocol::UDP),
        )?;
        setup_sokcet2(&socket2_socket, &local_socket_addr)?;
        let socket = UdpSocket::from_std(socket2_socket.into())?;

        Ok(connector
            .try_connect_with_socket(socket)
            .await
            .with_context(|| "UdpTunnelConnector failed to connect remote")?)
    }

    async fn main_loop(data: Arc<UdpHolePunchConnectorData>) {
        loop {
            let peers_to_connect = Self::collect_peer_to_connect(data.clone()).await;
            tracing::trace!(?peers_to_connect, "peers to connect");
            if peers_to_connect.len() == 0 {
                tokio::time::sleep(std::time::Duration::from_secs(5)).await;
                continue;
            }

            let mut tasks: JoinSet<Result<(), anyhow::Error>> = JoinSet::new();
            for peer_id in peers_to_connect {
                let data = data.clone();
                tasks.spawn(
                    async move {
                        let tunnel = Self::do_hole_punching(data.clone(), peer_id)
                            .await
                            .with_context(|| "failed to do hole punching")?;

                        let _ =
                            data.peer_mgr
                                .add_client_tunnel(tunnel)
                                .await
                                .with_context(|| {
                                    "failed to add tunnel as client in hole punch connector"
                                })?;

                        Ok(())
                    }
                    .instrument(tracing::info_span!("doing hole punching client", ?peer_id)),
                );
            }

            while let Some(res) = tasks.join_next().await {
                if let Err(e) = res {
                    tracing::error!(?e, "failed to join hole punching job");
                    continue;
                }

                match res.unwrap() {
                    Err(e) => {
                        tracing::error!(?e, "failed to do hole punching job");
                    }
                    Ok(_) => {
                        tracing::info!("hole punching job succeed");
                    }
                }
            }

            tokio::time::sleep(std::time::Duration::from_secs(10)).await;
        }
    }
}

#[cfg(test)]
pub mod tests {
    use std::sync::Arc;

    use crate::rpc::{NatType, StunInfo};

    use crate::{
        common::{error::Error, stun::StunInfoCollectorTrait},
        connector::udp_hole_punch::UdpHolePunchConnector,
        peers::{
            peer_manager::PeerManager,
            tests::{
                connect_peer_manager, create_mock_peer_manager, wait_route_appear,
                wait_route_appear_with_cost,
            },
        },
    };

    struct MockStunInfoCollector {
        udp_nat_type: NatType,
    }

    #[async_trait::async_trait]
    impl StunInfoCollectorTrait for MockStunInfoCollector {
        fn get_stun_info(&self) -> StunInfo {
            StunInfo {
                udp_nat_type: self.udp_nat_type as i32,
                tcp_nat_type: NatType::Unknown as i32,
                last_update_time: std::time::Instant::now().elapsed().as_secs() as i64,
            }
        }

        async fn get_udp_port_mapping(&self, port: u16) -> Result<std::net::SocketAddr, Error> {
            Ok(format!("127.0.0.1:{}", port).parse().unwrap())
        }
    }

    pub fn replace_stun_info_collector(peer_mgr: Arc<PeerManager>, udp_nat_type: NatType) {
        let collector = Box::new(MockStunInfoCollector { udp_nat_type });
        peer_mgr
            .get_global_ctx()
            .replace_stun_info_collector(collector);
    }

    pub async fn create_mock_peer_manager_with_mock_stun(
        udp_nat_type: NatType,
    ) -> Arc<PeerManager> {
        let p_a = create_mock_peer_manager().await;
        replace_stun_info_collector(p_a.clone(), udp_nat_type);
        p_a
    }

    #[tokio::test]
    async fn hole_punching() {
        let p_a = create_mock_peer_manager_with_mock_stun(NatType::PortRestricted).await;
        let p_b = create_mock_peer_manager_with_mock_stun(NatType::Symmetric).await;
        let p_c = create_mock_peer_manager_with_mock_stun(NatType::PortRestricted).await;
        connect_peer_manager(p_a.clone(), p_b.clone()).await;
        connect_peer_manager(p_b.clone(), p_c.clone()).await;

        wait_route_appear(p_a.clone(), p_c.my_peer_id())
            .await
            .unwrap();

        println!("{:?}", p_a.list_routes().await);

        let mut hole_punching_a = UdpHolePunchConnector::new(p_a.get_global_ctx(), p_a.clone());
        let mut hole_punching_c = UdpHolePunchConnector::new(p_c.get_global_ctx(), p_c.clone());

        hole_punching_a.run().await.unwrap();
        hole_punching_c.run().await.unwrap();

        wait_route_appear_with_cost(p_a.clone(), p_c.my_peer_id(), Some(1))
            .await
            .unwrap();
        println!("{:?}", p_a.list_routes().await);
    }
}
