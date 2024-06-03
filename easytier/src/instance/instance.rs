use std::collections::HashSet;
use std::net::Ipv4Addr;
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Weak};

use anyhow::Context;
use cidr::Ipv4Inet;
use futures::{SinkExt, StreamExt};

use pnet::packet::ipv4::Ipv4Packet;

use tokio::{sync::Mutex, task::JoinSet};
use tonic::transport::server::TcpIncoming;
use tonic::transport::Server;

use crate::common::config::ConfigLoader;
use crate::common::error::Error;
use crate::common::global_ctx::{ArcGlobalCtx, GlobalCtx, GlobalCtxEvent};
use crate::common::PeerId;
use crate::connector::direct::DirectConnectorManager;
use crate::connector::manual::{ConnectorManagerRpcService, ManualConnectorManager};
use crate::connector::udp_hole_punch::UdpHolePunchConnector;
use crate::gateway::icmp_proxy::IcmpProxy;
use crate::gateway::tcp_proxy::TcpProxy;
use crate::gateway::udp_proxy::UdpProxy;
use crate::peer_center::instance::PeerCenterInstance;
use crate::peers::peer_conn::PeerConnId;
use crate::peers::peer_manager::{PeerManager, RouteAlgoType};
use crate::peers::rpc_service::PeerManagerRpcService;
use crate::peers::PacketRecvChanReceiver;
use crate::rpc::vpn_portal_rpc_server::VpnPortalRpc;
use crate::rpc::{GetVpnPortalInfoRequest, GetVpnPortalInfoResponse, VpnPortalInfo};
use crate::tunnel::packet_def::ZCPacket;

use crate::tunnel::{ZCPacketSink, ZCPacketStream};
use crate::vpn_portal::{self, VpnPortal};

use super::listeners::ListenerManager;
use super::virtual_nic;

use crate::common::ifcfg::IfConfiguerTrait;

#[derive(Clone)]
struct IpProxy {
    tcp_proxy: Arc<TcpProxy>,
    icmp_proxy: Arc<IcmpProxy>,
    udp_proxy: Arc<UdpProxy>,
    global_ctx: ArcGlobalCtx,
    started: Arc<AtomicBool>,
}

impl IpProxy {
    fn new(global_ctx: ArcGlobalCtx, peer_manager: Arc<PeerManager>) -> Result<Self, Error> {
        let tcp_proxy = TcpProxy::new(global_ctx.clone(), peer_manager.clone());
        let icmp_proxy = IcmpProxy::new(global_ctx.clone(), peer_manager.clone())
            .with_context(|| "create icmp proxy failed")?;
        let udp_proxy = UdpProxy::new(global_ctx.clone(), peer_manager.clone())
            .with_context(|| "create udp proxy failed")?;
        Ok(IpProxy {
            tcp_proxy,
            icmp_proxy,
            udp_proxy,
            global_ctx,
            started: Arc::new(AtomicBool::new(false)),
        })
    }

    async fn start(&self) -> Result<(), Error> {
        if (self.global_ctx.get_proxy_cidrs().is_empty() || self.started.load(Ordering::Relaxed))
            && !self.global_ctx.config.get_flags().enable_exit_node
        {
            return Ok(());
        }

        self.started.store(true, Ordering::Relaxed);
        self.tcp_proxy.start().await?;
        self.icmp_proxy.start().await?;
        self.udp_proxy.start().await?;
        Ok(())
    }
}

struct NicCtx {
    global_ctx: ArcGlobalCtx,
    peer_mgr: Weak<PeerManager>,
    peer_packet_receiver: Arc<Mutex<PacketRecvChanReceiver>>,

    nic: Arc<Mutex<virtual_nic::VirtualNic>>,
    tasks: JoinSet<()>,
}

impl NicCtx {
    fn new(
        global_ctx: ArcGlobalCtx,
        peer_manager: &Arc<PeerManager>,
        peer_packet_receiver: Arc<Mutex<PacketRecvChanReceiver>>,
    ) -> Self {
        NicCtx {
            global_ctx: global_ctx.clone(),
            peer_mgr: Arc::downgrade(&peer_manager),
            peer_packet_receiver,
            nic: Arc::new(Mutex::new(virtual_nic::VirtualNic::new(global_ctx))),
            tasks: JoinSet::new(),
        }
    }

    async fn assign_ipv4_to_tun_device(&self, ipv4_addr: Ipv4Addr) -> Result<(), Error> {
        let nic = self.nic.lock().await;
        nic.link_up().await?;
        nic.remove_ip(None).await?;
        nic.add_ip(ipv4_addr, 24).await?;
        if cfg!(target_os = "macos") {
            nic.add_route(ipv4_addr, 24).await?;
        }
        Ok(())
    }

    async fn do_forward_nic_to_peers_ipv4(ret: ZCPacket, mgr: &PeerManager) {
        if let Some(ipv4) = Ipv4Packet::new(ret.payload()) {
            if ipv4.get_version() != 4 {
                tracing::info!("[USER_PACKET] not ipv4 packet: {:?}", ipv4);
                return;
            }
            let dst_ipv4 = ipv4.get_destination();
            tracing::trace!(
                ?ret,
                "[USER_PACKET] recv new packet from tun device and forward to peers."
            );

            // TODO: use zero-copy
            let send_ret = mgr.send_msg_ipv4(ret, dst_ipv4).await;
            if send_ret.is_err() {
                tracing::trace!(?send_ret, "[USER_PACKET] send_msg_ipv4 failed")
            }
        } else {
            tracing::warn!(?ret, "[USER_PACKET] not ipv4 packet");
        }
    }

    fn do_forward_nic_to_peers(
        &mut self,
        mut stream: Pin<Box<dyn ZCPacketStream>>,
    ) -> Result<(), Error> {
        // read from nic and write to corresponding tunnel
        let Some(mgr) = self.peer_mgr.upgrade() else {
            return Err(anyhow::anyhow!("peer manager not available").into());
        };
        self.tasks.spawn(async move {
            while let Some(ret) = stream.next().await {
                if ret.is_err() {
                    log::error!("read from nic failed: {:?}", ret);
                    break;
                }
                Self::do_forward_nic_to_peers_ipv4(ret.unwrap(), mgr.as_ref()).await;
            }
        });

        Ok(())
    }

    fn do_forward_peers_to_nic(&mut self, mut sink: Pin<Box<dyn ZCPacketSink>>) {
        let channel = self.peer_packet_receiver.clone();
        self.tasks.spawn(async move {
            // unlock until coroutine finished
            let mut channel = channel.lock().await;
            while let Some(packet) = channel.recv().await {
                tracing::trace!(
                    "[USER_PACKET] forward packet from peers to nic. packet: {:?}",
                    packet
                );
                let ret = sink.send(packet).await;
                if ret.is_err() {
                    tracing::error!(?ret, "do_forward_tunnel_to_nic sink error");
                }
            }
        });
    }

    async fn run_proxy_cidrs_route_updater(&mut self) -> Result<(), Error> {
        let Some(peer_mgr) = self.peer_mgr.upgrade() else {
            return Err(anyhow::anyhow!("peer manager not available").into());
        };
        let global_ctx = self.global_ctx.clone();
        let net_ns = self.global_ctx.net_ns.clone();
        let nic = self.nic.lock().await;
        let ifcfg = nic.get_ifcfg();
        let ifname = nic.ifname().to_owned();

        self.tasks.spawn(async move {
            let mut cur_proxy_cidrs = vec![];
            loop {
                let mut proxy_cidrs = vec![];
                let routes = peer_mgr.list_routes().await;
                for r in routes {
                    for cidr in r.proxy_cidrs {
                        let Ok(cidr) = cidr.parse::<cidr::Ipv4Cidr>() else {
                            continue;
                        };
                        proxy_cidrs.push(cidr);
                    }
                }
                // add vpn portal cidr to proxy_cidrs
                if let Some(vpn_cfg) = global_ctx.config.get_vpn_portal_config() {
                    proxy_cidrs.push(vpn_cfg.client_cidr);
                }

                // if route is in cur_proxy_cidrs but not in proxy_cidrs, delete it.
                for cidr in cur_proxy_cidrs.iter() {
                    if proxy_cidrs.contains(cidr) {
                        continue;
                    }

                    let _g = net_ns.guard();
                    let ret = ifcfg
                        .remove_ipv4_route(
                            ifname.as_str(),
                            cidr.first_address(),
                            cidr.network_length(),
                        )
                        .await;

                    if ret.is_err() {
                        tracing::trace!(
                            cidr = ?cidr,
                            err = ?ret,
                            "remove route failed.",
                        );
                    }
                }

                for cidr in proxy_cidrs.iter() {
                    if cur_proxy_cidrs.contains(cidr) {
                        continue;
                    }
                    let _g = net_ns.guard();
                    let ret = ifcfg
                        .add_ipv4_route(
                            ifname.as_str(),
                            cidr.first_address(),
                            cidr.network_length(),
                        )
                        .await;

                    if ret.is_err() {
                        tracing::trace!(
                            cidr = ?cidr,
                            err = ?ret,
                            "add route failed.",
                        );
                    }
                }

                cur_proxy_cidrs = proxy_cidrs;
                tokio::time::sleep(std::time::Duration::from_secs(1)).await;
            }
        });

        Ok(())
    }

    async fn run(&mut self, ipv4_addr: Ipv4Addr) -> Result<(), Error> {
        let tunnel = {
            let mut nic = self.nic.lock().await;
            let ret = nic.create_dev().await?;
            self.global_ctx
                .issue_event(GlobalCtxEvent::TunDeviceReady(nic.ifname().to_string()));
            ret
        };

        let (stream, sink) = tunnel.split();

        self.do_forward_nic_to_peers(stream)?;
        self.do_forward_peers_to_nic(sink);

        self.assign_ipv4_to_tun_device(ipv4_addr).await?;
        self.run_proxy_cidrs_route_updater().await?;
        Ok(())
    }
}

type ArcNicCtx = Arc<Mutex<Option<NicCtx>>>;

pub struct Instance {
    inst_name: String,

    id: uuid::Uuid,

    nic_ctx: ArcNicCtx,

    tasks: JoinSet<()>,

    peer_packet_receiver: Arc<Mutex<PacketRecvChanReceiver>>,
    peer_manager: Arc<PeerManager>,
    listener_manager: Arc<Mutex<ListenerManager<PeerManager>>>,
    conn_manager: Arc<ManualConnectorManager>,
    direct_conn_manager: Arc<DirectConnectorManager>,
    udp_hole_puncher: Arc<Mutex<UdpHolePunchConnector>>,

    ip_proxy: Option<IpProxy>,

    peer_center: Arc<PeerCenterInstance>,

    vpn_portal: Arc<Mutex<Box<dyn VpnPortal>>>,

    global_ctx: ArcGlobalCtx,
}

impl Instance {
    pub fn new(config: impl ConfigLoader + Send + Sync + 'static) -> Self {
        let global_ctx = Arc::new(GlobalCtx::new(config));

        log::info!(
            "[INIT] instance creating. config: {}",
            global_ctx.config.dump()
        );

        let (peer_packet_sender, peer_packet_receiver) = tokio::sync::mpsc::channel(100);

        let id = global_ctx.get_id();

        let peer_manager = Arc::new(PeerManager::new(
            RouteAlgoType::Ospf,
            global_ctx.clone(),
            peer_packet_sender.clone(),
        ));

        let listener_manager = Arc::new(Mutex::new(ListenerManager::new(
            global_ctx.clone(),
            peer_manager.clone(),
        )));

        let conn_manager = Arc::new(ManualConnectorManager::new(
            global_ctx.clone(),
            peer_manager.clone(),
        ));

        let mut direct_conn_manager =
            DirectConnectorManager::new(global_ctx.clone(), peer_manager.clone());
        direct_conn_manager.run();

        let udp_hole_puncher = UdpHolePunchConnector::new(global_ctx.clone(), peer_manager.clone());

        let peer_center = Arc::new(PeerCenterInstance::new(peer_manager.clone()));

        #[cfg(feature = "wireguard")]
        let vpn_portal_inst = vpn_portal::wireguard::WireGuard::default();
        #[cfg(not(feature = "wireguard"))]
        let vpn_portal_inst = vpn_portal::NullVpnPortal;

        Instance {
            inst_name: global_ctx.inst_name.clone(),
            id,

            peer_packet_receiver: Arc::new(Mutex::new(peer_packet_receiver)),
            nic_ctx: Arc::new(Mutex::new(None)),

            tasks: JoinSet::new(),
            peer_manager,
            listener_manager,
            conn_manager,
            direct_conn_manager: Arc::new(direct_conn_manager),
            udp_hole_puncher: Arc::new(Mutex::new(udp_hole_puncher)),

            ip_proxy: None,

            peer_center,

            vpn_portal: Arc::new(Mutex::new(Box::new(vpn_portal_inst))),

            global_ctx,
        }
    }

    pub fn get_conn_manager(&self) -> Arc<ManualConnectorManager> {
        self.conn_manager.clone()
    }

    async fn add_initial_peers(&mut self) -> Result<(), Error> {
        for peer in self.global_ctx.config.get_peers().iter() {
            self.get_conn_manager()
                .add_connector_by_url(peer.uri.as_str())
                .await?;
        }
        Ok(())
    }

    async fn clear_nic_ctx(arc_nic_ctx: ArcNicCtx) {
        let _ = arc_nic_ctx.lock().await.take();
    }

    async fn use_new_nic_ctx(arc_nic_ctx: ArcNicCtx, nic_ctx: NicCtx) {
        let mut g = arc_nic_ctx.lock().await;
        *g = Some(nic_ctx);
    }

    // Warning, if there is an IP conflict in the network when using DHCP, the IP will be automatically changed.
    fn check_dhcp_ip_conflict(&self) {
        use rand::Rng;
        let peer_manager_c = self.peer_manager.clone();
        let global_ctx_c = self.get_global_ctx();
        let nic_ctx = self.nic_ctx.clone();
        let peer_packet_receiver = self.peer_packet_receiver.clone();
        tokio::spawn(async move {
            let default_ipv4_addr = Ipv4Addr::new(10, 0, 0, 0);
            let mut dhcp_ip: Option<Ipv4Inet> = None;
            let mut tries = 6;
            loop {
                let mut ipv4_addr: Option<Ipv4Inet> = None;
                let mut unique_ipv4 = HashSet::new();

                for i in 0..tries {
                    if dhcp_ip.is_none() {
                        tokio::time::sleep(std::time::Duration::from_millis(500)).await;
                    }

                    for route in peer_manager_c.list_routes().await {
                        if !route.ipv4_addr.is_empty() {
                            if let Ok(ip) = Ipv4Inet::new(
                                if let Ok(ipv4) = route.ipv4_addr.parse::<Ipv4Addr>() {
                                    ipv4
                                } else {
                                    default_ipv4_addr
                                },
                                24,
                            ) {
                                unique_ipv4.insert(ip);
                            }
                        }
                    }

                    if i == tries - 1 && unique_ipv4.is_empty() {
                        unique_ipv4.insert(Ipv4Inet::new(default_ipv4_addr, 24).unwrap());
                    }

                    if let Some(ip) = dhcp_ip {
                        if !unique_ipv4.contains(&ip) {
                            ipv4_addr = dhcp_ip;
                            break;
                        }
                    }

                    for net in unique_ipv4.iter().map(|inet| inet.network()).take(1) {
                        if let Some(ip) = net.iter().find(|ip| {
                            ip.address() != net.first_address()
                                && ip.address() != net.last_address()
                                && !unique_ipv4.contains(ip)
                        }) {
                            ipv4_addr = Some(ip);
                        }
                    }
                }

                if dhcp_ip != ipv4_addr {
                    let last_ip = dhcp_ip.map(|p| p.address());
                    tracing::debug!("last_ip: {:?}", last_ip);

                    Self::clear_nic_ctx(nic_ctx.clone()).await;

                    if let Some(ip) = ipv4_addr {
                        let mut new_nic_ctx = NicCtx::new(
                            global_ctx_c.clone(),
                            &peer_manager_c,
                            peer_packet_receiver.clone(),
                        );
                        dhcp_ip = Some(ip);
                        tries = 1;
                        if let Err(e) = new_nic_ctx.run(ip.address()).await {
                            tracing::error!("add ip failed: {:?}", e);
                            global_ctx_c.set_ipv4(None);
                            let sleep: u64 = rand::thread_rng().gen_range(200..500);
                            tokio::time::sleep(std::time::Duration::from_millis(sleep)).await;
                            continue;
                        }
                        global_ctx_c.set_ipv4(Some(ip.address()));
                        global_ctx_c.issue_event(GlobalCtxEvent::DhcpIpv4Changed(
                            last_ip,
                            Some(ip.address()),
                        ));
                        Self::use_new_nic_ctx(nic_ctx.clone(), new_nic_ctx).await;
                    } else {
                        global_ctx_c.set_ipv4(None);
                        global_ctx_c.issue_event(GlobalCtxEvent::DhcpIpv4Conflicted(last_ip));
                        dhcp_ip = None;
                        tries = 6;
                    }
                }

                let sleep: u64 = rand::thread_rng().gen_range(5..10);

                tokio::time::sleep(std::time::Duration::from_secs(sleep)).await;
            }
        });
    }

    pub async fn run(&mut self) -> Result<(), Error> {
        self.listener_manager
            .lock()
            .await
            .prepare_listeners()
            .await?;
        self.listener_manager.lock().await.run().await?;
        self.peer_manager.run().await?;

        if self.global_ctx.config.get_dhcp() {
            self.check_dhcp_ip_conflict();
        } else if let Some(ipv4_addr) = self.global_ctx.get_ipv4() {
            let mut new_nic_ctx = NicCtx::new(
                self.global_ctx.clone(),
                &self.peer_manager,
                self.peer_packet_receiver.clone(),
            );
            new_nic_ctx.run(ipv4_addr).await?;
            Self::use_new_nic_ctx(self.nic_ctx.clone(), new_nic_ctx).await;
        }

        self.run_rpc_server()?;

        // run after tun device created, so listener can bind to tun device, which may be required by win 10
        self.ip_proxy = Some(IpProxy::new(
            self.get_global_ctx(),
            self.get_peer_manager(),
        )?);
        self.run_ip_proxy().await?;

        self.udp_hole_puncher.lock().await.run().await?;

        self.peer_center.init().await;
        let route_calc = self.peer_center.get_cost_calculator();
        self.peer_manager
            .get_route()
            .set_route_cost_fn(route_calc)
            .await;

        self.add_initial_peers().await?;

        if self.global_ctx.get_vpn_portal_cidr().is_some() {
            self.run_vpn_portal().await?;
        }

        Ok(())
    }

    pub async fn run_ip_proxy(&mut self) -> Result<(), Error> {
        if self.ip_proxy.is_none() {
            return Err(anyhow::anyhow!("ip proxy not enabled.").into());
        }
        self.ip_proxy.as_ref().unwrap().start().await?;
        Ok(())
    }

    pub async fn run_vpn_portal(&mut self) -> Result<(), Error> {
        if self.global_ctx.get_vpn_portal_cidr().is_none() {
            return Err(anyhow::anyhow!("vpn portal cidr not set.").into());
        }
        self.vpn_portal
            .lock()
            .await
            .start(self.get_global_ctx(), self.get_peer_manager())
            .await?;
        Ok(())
    }

    pub fn get_peer_manager(&self) -> Arc<PeerManager> {
        self.peer_manager.clone()
    }

    pub async fn close_peer_conn(
        &mut self,
        peer_id: PeerId,
        conn_id: &PeerConnId,
    ) -> Result<(), Error> {
        self.peer_manager
            .get_peer_map()
            .close_peer_conn(peer_id, conn_id)
            .await?;
        Ok(())
    }

    pub async fn wait(&mut self) {
        while let Some(ret) = self.tasks.join_next().await {
            log::info!("task finished: {:?}", ret);
            ret.unwrap();
        }
    }

    pub fn id(&self) -> uuid::Uuid {
        self.id
    }

    pub fn peer_id(&self) -> PeerId {
        self.peer_manager.my_peer_id()
    }

    fn get_vpn_portal_rpc_service(&self) -> impl VpnPortalRpc {
        struct VpnPortalRpcService {
            peer_mgr: Weak<PeerManager>,
            vpn_portal: Weak<Mutex<Box<dyn VpnPortal>>>,
        }

        #[tonic::async_trait]
        impl VpnPortalRpc for VpnPortalRpcService {
            async fn get_vpn_portal_info(
                &self,
                _request: tonic::Request<GetVpnPortalInfoRequest>,
            ) -> Result<tonic::Response<GetVpnPortalInfoResponse>, tonic::Status> {
                let Some(vpn_portal) = self.vpn_portal.upgrade() else {
                    return Err(tonic::Status::unavailable("vpn portal not available"));
                };

                let Some(peer_mgr) = self.peer_mgr.upgrade() else {
                    return Err(tonic::Status::unavailable("peer manager not available"));
                };

                let vpn_portal = vpn_portal.lock().await;
                let ret = GetVpnPortalInfoResponse {
                    vpn_portal_info: Some(VpnPortalInfo {
                        vpn_type: vpn_portal.name(),
                        client_config: vpn_portal.dump_client_config(peer_mgr).await,
                        connected_clients: vpn_portal.list_clients().await,
                    }),
                };

                Ok(tonic::Response::new(ret))
            }
        }

        VpnPortalRpcService {
            peer_mgr: Arc::downgrade(&self.peer_manager),
            vpn_portal: Arc::downgrade(&self.vpn_portal),
        }
    }

    fn run_rpc_server(&mut self) -> Result<(), Error> {
        let Some(addr) = self.global_ctx.config.get_rpc_portal() else {
            tracing::info!("rpc server not enabled, because rpc_portal is not set.");
            return Ok(());
        };
        let peer_mgr = self.peer_manager.clone();
        let conn_manager = self.conn_manager.clone();
        let net_ns = self.global_ctx.net_ns.clone();
        let peer_center = self.peer_center.clone();
        let vpn_portal_rpc = self.get_vpn_portal_rpc_service();

        let incoming = TcpIncoming::new(addr, true, None)
            .map_err(|e| anyhow::anyhow!("create rpc server failed. addr: {}, err: {}", addr, e))?;
        self.tasks.spawn(async move {
            let _g = net_ns.guard();
            Server::builder()
                .add_service(
                    crate::rpc::peer_manage_rpc_server::PeerManageRpcServer::new(
                        PeerManagerRpcService::new(peer_mgr),
                    ),
                )
                .add_service(
                    crate::rpc::connector_manage_rpc_server::ConnectorManageRpcServer::new(
                        ConnectorManagerRpcService(conn_manager.clone()),
                    ),
                )
                .add_service(
                    crate::rpc::peer_center_rpc_server::PeerCenterRpcServer::new(
                        peer_center.get_rpc_service(),
                    ),
                )
                .add_service(crate::rpc::vpn_portal_rpc_server::VpnPortalRpcServer::new(
                    vpn_portal_rpc,
                ))
                .serve_with_incoming(incoming)
                .await
                .with_context(|| format!("rpc server failed. addr: {}", addr))
                .unwrap();
        });
        Ok(())
    }

    pub fn get_global_ctx(&self) -> ArcGlobalCtx {
        self.global_ctx.clone()
    }

    pub fn get_vpn_portal_inst(&self) -> Arc<Mutex<Box<dyn VpnPortal>>> {
        self.vpn_portal.clone()
    }
}
