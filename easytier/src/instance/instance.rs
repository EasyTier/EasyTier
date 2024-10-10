use std::any::Any;
use std::collections::HashSet;
use std::net::Ipv4Addr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Weak};

use anyhow::Context;
use cidr::Ipv4Inet;

use tokio::{sync::Mutex, task::JoinSet};

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
use crate::proto::cli::VpnPortalRpc;
use crate::proto::cli::{GetVpnPortalInfoRequest, GetVpnPortalInfoResponse, VpnPortalInfo};
use crate::proto::peer_rpc::PeerCenterRpcServer;
use crate::proto::rpc_impl::standalone::StandAloneServer;
use crate::proto::rpc_types;
use crate::proto::rpc_types::controller::BaseController;
use crate::tunnel::tcp::TcpTunnelListener;
use crate::vpn_portal::{self, VpnPortal};

use super::listeners::ListenerManager;

#[cfg(feature = "socks5")]
use crate::gateway::socks5::Socks5Server;

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
            && !self.global_ctx.enable_exit_node()
            && !self.global_ctx.no_tun()
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

#[cfg(feature = "tun")]
type NicCtx = super::virtual_nic::NicCtx;
#[cfg(not(feature = "tun"))]
struct NicCtx;
#[cfg(not(feature = "tun"))]
impl NicCtx {
    pub fn new(
        _global_ctx: ArcGlobalCtx,
        _peer_manager: &Arc<PeerManager>,
        _peer_packet_receiver: Arc<Mutex<PacketRecvChanReceiver>>,
    ) -> Self {
        Self
    }

    pub async fn run(&mut self, _ipv4_addr: Ipv4Addr) -> Result<(), Error> {
        Ok(())
    }
}

type ArcNicCtx = Arc<Mutex<Option<Box<dyn Any + 'static + Send>>>>;

pub struct Instance {
    inst_name: String,

    id: uuid::Uuid,

    nic_ctx: ArcNicCtx,

    peer_packet_receiver: Arc<Mutex<PacketRecvChanReceiver>>,
    peer_manager: Arc<PeerManager>,
    listener_manager: Arc<Mutex<ListenerManager<PeerManager>>>,
    conn_manager: Arc<ManualConnectorManager>,
    direct_conn_manager: Arc<DirectConnectorManager>,
    udp_hole_puncher: Arc<Mutex<UdpHolePunchConnector>>,

    ip_proxy: Option<IpProxy>,

    peer_center: Arc<PeerCenterInstance>,

    vpn_portal: Arc<Mutex<Box<dyn VpnPortal>>>,

    #[cfg(feature = "socks5")]
    socks5_server: Arc<Socks5Server>,

    rpc_server: Option<StandAloneServer<TcpTunnelListener>>,

    global_ctx: ArcGlobalCtx,
}

impl Instance {
    pub fn new(config: impl ConfigLoader + Send + Sync + 'static) -> Self {
        let global_ctx = Arc::new(GlobalCtx::new(config));

        tracing::info!(
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

        let udp_hole_puncher = UdpHolePunchConnector::new(peer_manager.clone());

        let peer_center = Arc::new(PeerCenterInstance::new(peer_manager.clone()));

        #[cfg(feature = "wireguard")]
        let vpn_portal_inst = vpn_portal::wireguard::WireGuard::default();
        #[cfg(not(feature = "wireguard"))]
        let vpn_portal_inst = vpn_portal::NullVpnPortal;

        #[cfg(feature = "socks5")]
        let socks5_server = Socks5Server::new(global_ctx.clone(), peer_manager.clone(), None);

        let rpc_server = global_ctx.config.get_rpc_portal().and_then(|s| {
            Some(StandAloneServer::new(TcpTunnelListener::new(
                format!("tcp://{}", s).parse().unwrap(),
            )))
        });

        Instance {
            inst_name: global_ctx.inst_name.clone(),
            id,

            peer_packet_receiver: Arc::new(Mutex::new(peer_packet_receiver)),
            nic_ctx: Arc::new(Mutex::new(None)),

            peer_manager,
            listener_manager,
            conn_manager,
            direct_conn_manager: Arc::new(direct_conn_manager),
            udp_hole_puncher: Arc::new(Mutex::new(udp_hole_puncher)),

            ip_proxy: None,

            peer_center,

            vpn_portal: Arc::new(Mutex::new(Box::new(vpn_portal_inst))),

            #[cfg(feature = "socks5")]
            socks5_server,

            rpc_server,

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

    // use a mock nic ctx to consume packets.
    async fn clear_nic_ctx(
        arc_nic_ctx: ArcNicCtx,
        packet_recv: Arc<Mutex<PacketRecvChanReceiver>>,
    ) {
        let _ = arc_nic_ctx.lock().await.take();

        let mut tasks = JoinSet::new();
        tasks.spawn(async move {
            let mut packet_recv = packet_recv.lock().await;
            while let Some(packet) = packet_recv.recv().await {
                tracing::trace!("packet consumed by mock nic ctx: {:?}", packet);
            }
        });
        arc_nic_ctx.lock().await.replace(Box::new(tasks));

        tracing::debug!("nic ctx cleared.");
    }

    async fn use_new_nic_ctx(arc_nic_ctx: ArcNicCtx, nic_ctx: NicCtx) {
        let mut g = arc_nic_ctx.lock().await;
        *g = Some(Box::new(nic_ctx));
        tracing::debug!("nic ctx updated.");
    }

    // Warning, if there is an IP conflict in the network when using DHCP, the IP will be automatically changed.
    fn check_dhcp_ip_conflict(&self) {
        use rand::Rng;
        let peer_manager_c = self.peer_manager.clone();
        let global_ctx_c = self.get_global_ctx();
        let nic_ctx = self.nic_ctx.clone();
        let _peer_packet_receiver = self.peer_packet_receiver.clone();
        tokio::spawn(async move {
            let default_ipv4_addr = Ipv4Inet::new(Ipv4Addr::new(10, 126, 126, 0), 24).unwrap();
            let mut current_dhcp_ip: Option<Ipv4Inet> = None;
            let mut next_sleep_time = 0;
            loop {
                tokio::time::sleep(std::time::Duration::from_secs(next_sleep_time)).await;

                // do not allocate ip if no peer connected
                let routes = peer_manager_c.list_routes().await;
                if routes.is_empty() {
                    next_sleep_time = 1;
                    continue;
                } else {
                    next_sleep_time = rand::thread_rng().gen_range(5..10);
                }

                let mut used_ipv4 = HashSet::new();
                for route in routes {
                    let Some(peer_ipv4_addr) = route.ipv4_addr else {
                        continue;
                    };

                    used_ipv4.insert(peer_ipv4_addr.into());
                }

                let dhcp_inet = used_ipv4.iter().next().unwrap_or(&default_ipv4_addr);
                // if old ip is already in this subnet and not conflicted, use it
                if let Some(ip) = current_dhcp_ip {
                    if ip.network() == dhcp_inet.network() && !used_ipv4.contains(&ip) {
                        continue;
                    }
                }

                // find an available ip in the subnet
                let candidate_ipv4_addr = dhcp_inet.network().iter().find(|ip| {
                    ip.address() != dhcp_inet.first_address()
                        && ip.address() != dhcp_inet.last_address()
                        && !used_ipv4.contains(ip)
                });

                if current_dhcp_ip == candidate_ipv4_addr {
                    continue;
                }

                let last_ip = current_dhcp_ip.clone();
                tracing::debug!(
                    ?current_dhcp_ip,
                    ?candidate_ipv4_addr,
                    "dhcp start changing ip"
                );

                Self::clear_nic_ctx(nic_ctx.clone(), _peer_packet_receiver.clone()).await;

                if let Some(ip) = candidate_ipv4_addr {
                    if global_ctx_c.no_tun() {
                        current_dhcp_ip = Some(ip);
                        global_ctx_c.set_ipv4(Some(ip));
                        global_ctx_c
                            .issue_event(GlobalCtxEvent::DhcpIpv4Changed(last_ip, Some(ip)));
                        continue;
                    }

                    #[cfg(not(target_os = "android"))]
                    {
                        let mut new_nic_ctx = NicCtx::new(
                            global_ctx_c.clone(),
                            &peer_manager_c,
                            _peer_packet_receiver.clone(),
                        );
                        if let Err(e) = new_nic_ctx.run(ip).await {
                            tracing::error!(
                                ?current_dhcp_ip,
                                ?candidate_ipv4_addr,
                                ?e,
                                "add ip failed"
                            );
                            global_ctx_c.set_ipv4(None);
                            continue;
                        }
                        Self::use_new_nic_ctx(nic_ctx.clone(), new_nic_ctx).await;
                    }

                    current_dhcp_ip = Some(ip);
                    global_ctx_c.set_ipv4(Some(ip));
                    global_ctx_c.issue_event(GlobalCtxEvent::DhcpIpv4Changed(last_ip, Some(ip)));
                } else {
                    current_dhcp_ip = None;
                    global_ctx_c.set_ipv4(None);
                    global_ctx_c.issue_event(GlobalCtxEvent::DhcpIpv4Conflicted(last_ip));
                }
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

        Self::clear_nic_ctx(self.nic_ctx.clone(), self.peer_packet_receiver.clone()).await;

        if !self.global_ctx.config.get_flags().no_tun {
            #[cfg(not(target_os = "android"))]
            if let Some(ipv4_addr) = self.global_ctx.get_ipv4() {
                let mut new_nic_ctx = NicCtx::new(
                    self.global_ctx.clone(),
                    &self.peer_manager,
                    self.peer_packet_receiver.clone(),
                );
                new_nic_ctx.run(ipv4_addr).await?;
                Self::use_new_nic_ctx(self.nic_ctx.clone(), new_nic_ctx).await;
            }
        }

        if self.global_ctx.config.get_dhcp() {
            self.check_dhcp_ip_conflict();
        }

        self.run_rpc_server().await?;

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

        #[cfg(feature = "socks5")]
        self.socks5_server.run().await?;

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

    pub async fn wait(&self) {
        self.peer_manager.wait().await;
    }

    pub fn id(&self) -> uuid::Uuid {
        self.id
    }

    pub fn peer_id(&self) -> PeerId {
        self.peer_manager.my_peer_id()
    }

    fn get_vpn_portal_rpc_service(&self) -> impl VpnPortalRpc<Controller = BaseController> + Clone {
        #[derive(Clone)]
        struct VpnPortalRpcService {
            peer_mgr: Weak<PeerManager>,
            vpn_portal: Weak<Mutex<Box<dyn VpnPortal>>>,
        }

        #[async_trait::async_trait]
        impl VpnPortalRpc for VpnPortalRpcService {
            type Controller = BaseController;

            async fn get_vpn_portal_info(
                &self,
                _: BaseController,
                _request: GetVpnPortalInfoRequest,
            ) -> Result<GetVpnPortalInfoResponse, rpc_types::error::Error> {
                let Some(vpn_portal) = self.vpn_portal.upgrade() else {
                    return Err(anyhow::anyhow!("vpn portal not available").into());
                };

                let Some(peer_mgr) = self.peer_mgr.upgrade() else {
                    return Err(anyhow::anyhow!("peer manager not available").into());
                };

                let vpn_portal = vpn_portal.lock().await;
                let ret = GetVpnPortalInfoResponse {
                    vpn_portal_info: Some(VpnPortalInfo {
                        vpn_type: vpn_portal.name(),
                        client_config: vpn_portal.dump_client_config(peer_mgr).await,
                        connected_clients: vpn_portal.list_clients().await,
                    }),
                };

                Ok(ret)
            }
        }

        VpnPortalRpcService {
            peer_mgr: Arc::downgrade(&self.peer_manager),
            vpn_portal: Arc::downgrade(&self.vpn_portal),
        }
    }

    async fn run_rpc_server(&mut self) -> Result<(), Error> {
        let Some(_) = self.global_ctx.config.get_rpc_portal() else {
            tracing::info!("rpc server not enabled, because rpc_portal is not set.");
            return Ok(());
        };

        use crate::proto::cli::*;

        let peer_mgr = self.peer_manager.clone();
        let conn_manager = self.conn_manager.clone();
        let peer_center = self.peer_center.clone();
        let vpn_portal_rpc = self.get_vpn_portal_rpc_service();

        let s = self.rpc_server.as_mut().unwrap();
        s.registry().register(
            PeerManageRpcServer::new(PeerManagerRpcService::new(peer_mgr)),
            "",
        );
        s.registry().register(
            ConnectorManageRpcServer::new(ConnectorManagerRpcService(conn_manager)),
            "",
        );

        s.registry()
            .register(PeerCenterRpcServer::new(peer_center.get_rpc_service()), "");
        s.registry()
            .register(VpnPortalRpcServer::new(vpn_portal_rpc), "");

        let _g = self.global_ctx.net_ns.guard();
        Ok(s.serve().await.with_context(|| "rpc server start failed")?)
    }

    pub fn get_global_ctx(&self) -> ArcGlobalCtx {
        self.global_ctx.clone()
    }

    pub fn get_vpn_portal_inst(&self) -> Arc<Mutex<Box<dyn VpnPortal>>> {
        self.vpn_portal.clone()
    }

    pub fn get_nic_ctx(&self) -> ArcNicCtx {
        self.nic_ctx.clone()
    }

    pub fn get_peer_packet_receiver(&self) -> Arc<Mutex<PacketRecvChanReceiver>> {
        self.peer_packet_receiver.clone()
    }

    #[cfg(target_os = "android")]
    pub async fn setup_nic_ctx_for_android(
        nic_ctx: ArcNicCtx,
        global_ctx: ArcGlobalCtx,
        peer_manager: Arc<PeerManager>,
        peer_packet_receiver: Arc<Mutex<PacketRecvChanReceiver>>,
        fd: i32,
    ) -> Result<(), anyhow::Error> {
        println!("setup_nic_ctx_for_android, fd: {}", fd);
        Self::clear_nic_ctx(nic_ctx.clone(), peer_packet_receiver.clone()).await;
        if fd <= 0 {
            return Ok(());
        }
        let mut new_nic_ctx = NicCtx::new(
            global_ctx.clone(),
            &peer_manager,
            peer_packet_receiver.clone(),
        );
        new_nic_ctx
            .run_for_android(fd)
            .await
            .with_context(|| "add ip failed")?;
        Self::use_new_nic_ctx(nic_ctx.clone(), new_nic_ctx).await;
        Ok(())
    }
}
