use std::any::Any;
use std::collections::HashSet;
use std::net::{IpAddr, Ipv4Addr};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Weak};

use anyhow::Context;
use cidr::{IpCidr, Ipv4Inet};

use tokio::{sync::Mutex, task::JoinSet};
use tokio_util::sync::CancellationToken;

use crate::common::acl_processor::AclRuleBuilder;
use crate::common::config::ConfigLoader;
use crate::common::error::Error;
use crate::common::global_ctx::{ArcGlobalCtx, GlobalCtx, GlobalCtxEvent};
use crate::common::scoped_task::ScopedTask;
use crate::common::PeerId;
use crate::connector::direct::DirectConnectorManager;
use crate::connector::manual::{ConnectorManagerRpcService, ManualConnectorManager};
use crate::connector::udp_hole_punch::UdpHolePunchConnector;
use crate::gateway::icmp_proxy::IcmpProxy;
use crate::gateway::kcp_proxy::{KcpProxyDst, KcpProxyDstRpcService, KcpProxySrc};
use crate::gateway::quic_proxy::{QUICProxyDst, QUICProxyDstRpcService, QUICProxySrc};
use crate::gateway::tcp_proxy::{NatDstTcpConnector, TcpProxy, TcpProxyRpcService};
use crate::gateway::udp_proxy::UdpProxy;
use crate::peer_center::instance::PeerCenterInstance;
use crate::peers::peer_conn::PeerConnId;
use crate::peers::peer_manager::{PeerManager, RouteAlgoType};
use crate::peers::rpc_service::PeerManagerRpcService;
use crate::peers::{create_packet_recv_chan, recv_packet_from_chan, PacketRecvChanReceiver};
use crate::proto::cli::VpnPortalRpc;
use crate::proto::cli::{
    AddPortForwardRequest, AddPortForwardResponse, GetPrometheusStatsRequest,
    GetPrometheusStatsResponse, GetStatsRequest, GetStatsResponse, ListMappedListenerRequest,
    ListMappedListenerResponse, ListPortForwardRequest, ListPortForwardResponse,
    ManageMappedListenerRequest, ManageMappedListenerResponse, MappedListener,
    MappedListenerManageAction, MappedListenerManageRpc, MetricSnapshot, PortForwardManageRpc,
    RemovePortForwardRequest, RemovePortForwardResponse, StatsRpc,
};
use crate::proto::cli::{GetVpnPortalInfoRequest, GetVpnPortalInfoResponse, VpnPortalInfo};
use crate::proto::common::{PortForwardConfigPb, TunnelInfo};
use crate::proto::peer_rpc::PeerCenterRpcServer;
use crate::proto::rpc_impl::standalone::{RpcServerHook, StandAloneServer};
use crate::proto::rpc_types;
use crate::proto::rpc_types::controller::BaseController;
use crate::tunnel::tcp::TcpTunnelListener;
use crate::vpn_portal::{self, VpnPortal};

use super::dns_server::runner::DnsRunner;
use super::dns_server::MAGIC_DNS_FAKE_IP;
use super::listeners::ListenerManager;

#[cfg(feature = "socks5")]
use crate::gateway::socks5::Socks5Server;

#[derive(Clone)]
struct IpProxy {
    tcp_proxy: Arc<TcpProxy<NatDstTcpConnector>>,
    icmp_proxy: Arc<IcmpProxy>,
    udp_proxy: Arc<UdpProxy>,
    global_ctx: ArcGlobalCtx,
    started: Arc<AtomicBool>,
}

impl IpProxy {
    fn new(global_ctx: ArcGlobalCtx, peer_manager: Arc<PeerManager>) -> Result<Self, Error> {
        let tcp_proxy = TcpProxy::new(peer_manager.clone(), NatDstTcpConnector {});
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
        if (self.global_ctx.config.get_proxy_cidrs().is_empty()
            || self.started.load(Ordering::Relaxed))
            && !self.global_ctx.enable_exit_node()
            && !self.global_ctx.no_tun()
        {
            return Ok(());
        }

        // Actually, if this node is enabled as an exit node,
        // we still can use the system stack to forward packets.
        if self.global_ctx.proxy_forward_by_system() && !self.global_ctx.no_tun() {
            return Ok(());
        }

        self.started.store(true, Ordering::Relaxed);
        self.tcp_proxy.start(true).await?;
        if let Err(e) = self.icmp_proxy.start().await {
            tracing::error!("start icmp proxy failed: {:?}", e);
            if cfg!(not(any(target_os = "android", target_env = "ohos"))) {
                // android and ohos not support icmp proxy
                return Err(e);
            }
        }
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

struct MagicDnsContainer {
    dns_runner_task: ScopedTask<()>,
    dns_runner_cancel_token: CancellationToken,
}

// nic container will be cleared when dhcp ip changed
pub(crate) struct NicCtxContainer {
    nic_ctx: Option<Box<dyn Any + 'static + Send>>,
    magic_dns: Option<MagicDnsContainer>,
}

impl NicCtxContainer {
    fn new(nic_ctx: NicCtx, dns_runner: Option<DnsRunner>) -> Self {
        if let Some(mut dns_runner) = dns_runner {
            let token = CancellationToken::new();
            let token_clone = token.clone();
            let task = tokio::spawn(async move {
                let _ = dns_runner.run(token_clone).await;
            });
            Self {
                nic_ctx: Some(Box::new(nic_ctx)),
                magic_dns: Some(MagicDnsContainer {
                    dns_runner_task: task.into(),
                    dns_runner_cancel_token: token,
                }),
            }
        } else {
            Self {
                nic_ctx: Some(Box::new(nic_ctx)),
                magic_dns: None,
            }
        }
    }

    fn new_with_any<T: 'static + Send>(ctx: T) -> Self {
        Self {
            nic_ctx: Some(Box::new(ctx)),
            magic_dns: None,
        }
    }
}

type ArcNicCtx = Arc<Mutex<Option<NicCtxContainer>>>;

pub struct InstanceRpcServerHook {
    rpc_portal_whitelist: Vec<IpCidr>,
}

impl InstanceRpcServerHook {
    pub fn new(rpc_portal_whitelist: Option<Vec<IpCidr>>) -> Self {
        let rpc_portal_whitelist = rpc_portal_whitelist
            .unwrap_or_else(|| vec!["127.0.0.0/8".parse().unwrap(), "::1/128".parse().unwrap()]);
        InstanceRpcServerHook {
            rpc_portal_whitelist,
        }
    }
}

#[async_trait::async_trait]
impl RpcServerHook for InstanceRpcServerHook {
    async fn on_new_client(
        &self,
        tunnel_info: Option<TunnelInfo>,
    ) -> Result<Option<TunnelInfo>, anyhow::Error> {
        let tunnel_info = tunnel_info.ok_or_else(|| anyhow::anyhow!("tunnel info is None"))?;

        let remote_url = tunnel_info
            .remote_addr
            .clone()
            .ok_or_else(|| anyhow::anyhow!("remote_addr is None"))?;

        let url_str = &remote_url.url;
        let url = url::Url::parse(url_str)
            .map_err(|e| anyhow::anyhow!("Failed to parse remote URL '{}': {}", url_str, e))?;

        let host = url
            .host_str()
            .ok_or_else(|| anyhow::anyhow!("No host found in remote URL '{}'", url_str))?;

        let ip_addr: IpAddr = host
            .parse()
            .map_err(|e| anyhow::anyhow!("Failed to parse IP address '{}': {}", host, e))?;

        for cidr in &self.rpc_portal_whitelist {
            if cidr.contains(&ip_addr) {
                return Ok(Some(tunnel_info));
            }
        }
        return Err(anyhow::anyhow!(
            "Rpc portal client IP {} not in whitelist: {:?}, ignoring client.",
            ip_addr,
            self.rpc_portal_whitelist
        ));
    }
}

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

    kcp_proxy_src: Option<KcpProxySrc>,
    kcp_proxy_dst: Option<KcpProxyDst>,

    quic_proxy_src: Option<QUICProxySrc>,
    quic_proxy_dst: Option<QUICProxyDst>,

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

        let (peer_packet_sender, peer_packet_receiver) = create_packet_recv_chan();

        let id = global_ctx.get_id();

        let peer_manager = Arc::new(PeerManager::new(
            RouteAlgoType::Ospf,
            global_ctx.clone(),
            peer_packet_sender.clone(),
        ));

        peer_manager.set_allow_loopback_tunnel(false);

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
            kcp_proxy_src: None,
            kcp_proxy_dst: None,

            quic_proxy_src: None,
            quic_proxy_dst: None,

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
        if let Some(old_ctx) = arc_nic_ctx.lock().await.take() {
            if let Some(dns_runner) = old_ctx.magic_dns {
                dns_runner.dns_runner_cancel_token.cancel();
                tracing::debug!("cancelling dns runner task");
                let ret = dns_runner.dns_runner_task.await;
                tracing::debug!("dns runner task cancelled, ret: {:?}", ret);
            }
        };

        let mut tasks = JoinSet::new();
        tasks.spawn(async move {
            let mut packet_recv = packet_recv.lock().await;
            while let Ok(packet) = recv_packet_from_chan(&mut packet_recv).await {
                tracing::trace!("packet consumed by mock nic ctx: {:?}", packet);
            }
        });
        arc_nic_ctx
            .lock()
            .await
            .replace(NicCtxContainer::new_with_any(tasks));

        tracing::debug!("nic ctx cleared.");
    }

    fn create_magic_dns_runner(
        peer_mgr: Arc<PeerManager>,
        tun_dev: Option<String>,
        tun_ip: Ipv4Inet,
    ) -> Option<DnsRunner> {
        let ctx = peer_mgr.get_global_ctx();
        if !ctx.config.get_flags().accept_dns {
            return None;
        }

        let runner = DnsRunner::new(
            peer_mgr,
            tun_dev,
            tun_ip,
            MAGIC_DNS_FAKE_IP.parse().unwrap(),
        );
        Some(runner)
    }

    async fn use_new_nic_ctx(
        arc_nic_ctx: ArcNicCtx,
        nic_ctx: NicCtx,
        magic_dns: Option<DnsRunner>,
    ) {
        let mut g = arc_nic_ctx.lock().await;
        *g = Some(NicCtxContainer::new(nic_ctx, magic_dns));
        tracing::debug!("nic ctx updated.");
    }

    // Warning, if there is an IP conflict in the network when using DHCP, the IP will be automatically changed.
    fn check_dhcp_ip_conflict(&self) {
        use rand::Rng;
        let peer_manager_c = Arc::downgrade(&self.peer_manager.clone());
        let global_ctx_c = self.get_global_ctx();
        let nic_ctx = self.nic_ctx.clone();
        let _peer_packet_receiver = self.peer_packet_receiver.clone();
        tokio::spawn(async move {
            let default_ipv4_addr = Ipv4Inet::new(Ipv4Addr::new(10, 126, 126, 0), 24).unwrap();
            let mut current_dhcp_ip: Option<Ipv4Inet> = None;
            let mut next_sleep_time = 0;
            loop {
                tokio::time::sleep(std::time::Duration::from_secs(next_sleep_time)).await;

                let Some(peer_manager_c) = peer_manager_c.upgrade() else {
                    tracing::warn!("peer manager is dropped, stop dhcp check.");
                    return;
                };

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

                    #[cfg(not(any(target_os = "android", target_env = "ohos")))]
                    {
                        let mut new_nic_ctx = NicCtx::new(
                            global_ctx_c.clone(),
                            &peer_manager_c,
                            _peer_packet_receiver.clone(),
                        );
                        if let Err(e) = new_nic_ctx.run(Some(ip), global_ctx_c.get_ipv6()).await {
                            tracing::error!(
                                ?current_dhcp_ip,
                                ?candidate_ipv4_addr,
                                ?e,
                                "add ip failed"
                            );
                            global_ctx_c.set_ipv4(None);
                            continue;
                        }
                        let ifname = new_nic_ctx.ifname().await;
                        Self::use_new_nic_ctx(
                            nic_ctx.clone(),
                            new_nic_ctx,
                            Self::create_magic_dns_runner(
                                peer_manager_c.clone(),
                                ifname,
                                ip.clone(),
                            ),
                        )
                        .await;
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

    async fn run_quic_dst(&mut self) -> Result<(), Error> {
        if !self.global_ctx.get_flags().enable_quic_proxy {
            return Ok(());
        }

        let quic_dst = QUICProxyDst::new(self.global_ctx.clone())?;
        quic_dst.start().await?;
        self.global_ctx
            .set_quic_proxy_port(Some(quic_dst.local_addr()?.port()));
        self.quic_proxy_dst = Some(quic_dst);
        Ok(())
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
            #[cfg(not(any(target_os = "android", target_env = "ohos")))]
            {
                let ipv4_addr = self.global_ctx.get_ipv4();
                let ipv6_addr = self.global_ctx.get_ipv6();

                // Only run if we have at least one IP address (IPv4 or IPv6)
                if ipv4_addr.is_some() || ipv6_addr.is_some() {
                    let mut new_nic_ctx = NicCtx::new(
                        self.global_ctx.clone(),
                        &self.peer_manager,
                        self.peer_packet_receiver.clone(),
                    );

                    new_nic_ctx.run(ipv4_addr, ipv6_addr).await?;
                    let ifname = new_nic_ctx.ifname().await;

                    // Create Magic DNS runner only if we have IPv4
                    let dns_runner = if let Some(ipv4) = ipv4_addr {
                        Self::create_magic_dns_runner(self.peer_manager.clone(), ifname, ipv4)
                    } else {
                        None
                    };
                    Self::use_new_nic_ctx(self.nic_ctx.clone(), new_nic_ctx, dns_runner).await;
                }
            }
        }

        if self.global_ctx.config.get_dhcp() {
            self.check_dhcp_ip_conflict();
        }

        if self.global_ctx.get_flags().enable_kcp_proxy {
            let src_proxy = KcpProxySrc::new(self.get_peer_manager()).await;
            src_proxy.start().await;
            self.kcp_proxy_src = Some(src_proxy);
        }

        if !self.global_ctx.get_flags().disable_kcp_input {
            let mut dst_proxy = KcpProxyDst::new(self.get_peer_manager()).await;
            dst_proxy.start().await;
            self.kcp_proxy_dst = Some(dst_proxy);
        }

        if self.global_ctx.get_flags().enable_quic_proxy {
            let quic_src = QUICProxySrc::new(self.get_peer_manager()).await;
            quic_src.start().await;
            self.quic_proxy_src = Some(quic_src);
        }

        if !self.global_ctx.get_flags().disable_quic_input {
            if let Err(e) = self.run_quic_dst().await {
                eprintln!(
                    "quic input start failed: {:?} (some platforms may not support)",
                    e
                );
            }
        }

        self.global_ctx
            .get_acl_filter()
            .reload_rules(AclRuleBuilder::build(&self.global_ctx)?.as_ref());

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
        self.socks5_server
            .run(
                self.kcp_proxy_src
                    .as_ref()
                    .map(|x| Arc::downgrade(&x.get_kcp_endpoint())),
            )
            .await?;

        self.run_rpc_server().await?;

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

    fn get_mapped_listener_manager_rpc_service(
        &self,
    ) -> impl MappedListenerManageRpc<Controller = BaseController> + Clone {
        #[derive(Clone)]
        pub struct MappedListenerManagerRpcService(Arc<GlobalCtx>);

        #[async_trait::async_trait]
        impl MappedListenerManageRpc for MappedListenerManagerRpcService {
            type Controller = BaseController;

            async fn list_mapped_listener(
                &self,
                _: BaseController,
                _request: ListMappedListenerRequest,
            ) -> Result<ListMappedListenerResponse, rpc_types::error::Error> {
                let mut ret = ListMappedListenerResponse::default();
                let urls = self.0.config.get_mapped_listeners();
                let mapped_listeners: Vec<MappedListener> = urls
                    .into_iter()
                    .map(|u| MappedListener {
                        url: Some(u.into()),
                    })
                    .collect();
                ret.mappedlisteners = mapped_listeners;
                Ok(ret)
            }

            async fn manage_mapped_listener(
                &self,
                _: BaseController,
                req: ManageMappedListenerRequest,
            ) -> Result<ManageMappedListenerResponse, rpc_types::error::Error> {
                let url: url::Url = req.url.ok_or(anyhow::anyhow!("url is empty"))?.into();

                let urls = self.0.config.get_mapped_listeners();
                let mut set_urls: HashSet<url::Url> = urls.into_iter().collect();
                if req.action == MappedListenerManageAction::MappedListenerRemove as i32 {
                    set_urls.remove(&url);
                } else if req.action == MappedListenerManageAction::MappedListenerAdd as i32 {
                    set_urls.insert(url);
                }
                let urls: Vec<url::Url> = set_urls.into_iter().collect();
                self.0.config.set_mapped_listeners(Some(urls));
                Ok(ManageMappedListenerResponse::default())
            }
        }

        MappedListenerManagerRpcService(self.global_ctx.clone())
    }

    fn get_port_forward_manager_rpc_service(
        &self,
    ) -> impl PortForwardManageRpc<Controller = BaseController> + Clone {
        #[derive(Clone)]
        pub struct PortForwardManagerRpcService {
            global_ctx: ArcGlobalCtx,
            socks5_server: Weak<Socks5Server>,
        }

        #[async_trait::async_trait]
        impl PortForwardManageRpc for PortForwardManagerRpcService {
            type Controller = BaseController;

            async fn add_port_forward(
                &self,
                _: BaseController,
                request: AddPortForwardRequest,
            ) -> Result<AddPortForwardResponse, rpc_types::error::Error> {
                let Some(socks5_server) = self.socks5_server.upgrade() else {
                    return Err(anyhow::anyhow!("socks5 server not available").into());
                };
                if let Some(cfg) = request.cfg {
                    tracing::info!("Port forward rule added: {:?}", cfg);
                    let mut current_forwards = self.global_ctx.config.get_port_forwards();
                    current_forwards.push(cfg.into());
                    self.global_ctx
                        .config
                        .set_port_forwards(current_forwards.clone());
                    socks5_server
                        .reload_port_forwards(&current_forwards)
                        .await
                        .with_context(|| "Failed to reload port forwards")?;
                }
                Ok(AddPortForwardResponse {})
            }

            async fn remove_port_forward(
                &self,
                _: BaseController,
                request: RemovePortForwardRequest,
            ) -> Result<RemovePortForwardResponse, rpc_types::error::Error> {
                let Some(socks5_server) = self.socks5_server.upgrade() else {
                    return Err(anyhow::anyhow!("socks5 server not available").into());
                };
                let Some(cfg) = request.cfg else {
                    return Err(anyhow::anyhow!("port forward config is empty").into());
                };
                let cfg = cfg.into();
                let mut current_forwards = self.global_ctx.config.get_port_forwards();
                current_forwards.retain(|e| *e != cfg);
                self.global_ctx
                    .config
                    .set_port_forwards(current_forwards.clone());
                socks5_server
                    .reload_port_forwards(&current_forwards)
                    .await
                    .with_context(|| "Failed to reload port forwards")?;

                tracing::info!("Port forward rule removed: {:?}", cfg);
                Ok(RemovePortForwardResponse {})
            }

            async fn list_port_forward(
                &self,
                _: BaseController,
                _request: ListPortForwardRequest,
            ) -> Result<ListPortForwardResponse, rpc_types::error::Error> {
                let forwards = self.global_ctx.config.get_port_forwards();
                let cfgs: Vec<PortForwardConfigPb> = forwards.into_iter().map(Into::into).collect();
                Ok(ListPortForwardResponse { cfgs })
            }
        }

        PortForwardManagerRpcService {
            global_ctx: self.global_ctx.clone(),
            socks5_server: Arc::downgrade(&self.socks5_server),
        }
    }

    fn get_stats_rpc_service(&self) -> impl StatsRpc<Controller = BaseController> + Clone {
        #[derive(Clone)]
        pub struct StatsRpcService {
            global_ctx: ArcGlobalCtx,
        }

        #[async_trait::async_trait]
        impl StatsRpc for StatsRpcService {
            type Controller = BaseController;

            async fn get_stats(
                &self,
                _: BaseController,
                _request: GetStatsRequest,
            ) -> Result<GetStatsResponse, rpc_types::error::Error> {
                let stats_manager = self.global_ctx.stats_manager();
                let snapshots = stats_manager.get_all_metrics();
                
                let metrics = snapshots
                    .into_iter()
                    .map(|snapshot| {
                        let mut labels = std::collections::BTreeMap::new();
                        for label in snapshot.labels.labels() {
                            labels.insert(label.key.clone(), label.value.clone());
                        }
                        
                        MetricSnapshot {
                            name: snapshot.name_str(),
                            value: snapshot.value,
                            labels,
                        }
                    })
                    .collect();
                
                Ok(GetStatsResponse { metrics })
            }

            async fn get_prometheus_stats(
                &self,
                _: BaseController,
                _request: GetPrometheusStatsRequest,
            ) -> Result<GetPrometheusStatsResponse, rpc_types::error::Error> {
                let stats_manager = self.global_ctx.stats_manager();
                let prometheus_text = stats_manager.export_prometheus();
                
                Ok(GetPrometheusStatsResponse { prometheus_text })
            }
        }

        StatsRpcService {
            global_ctx: self.global_ctx.clone(),
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
        let mapped_listener_manager_rpc = self.get_mapped_listener_manager_rpc_service();
        let port_forward_manager_rpc = self.get_port_forward_manager_rpc_service();
        let stats_rpc_service = self.get_stats_rpc_service();

        let s = self.rpc_server.as_mut().unwrap();
        let peer_mgr_rpc_service = PeerManagerRpcService::new(peer_mgr.clone());
        s.registry()
            .register(PeerManageRpcServer::new(peer_mgr_rpc_service.clone()), "");
        s.registry()
            .register(AclManageRpcServer::new(peer_mgr_rpc_service), "");
        s.registry().register(
            ConnectorManageRpcServer::new(ConnectorManagerRpcService(conn_manager)),
            "",
        );

        s.registry()
            .register(PeerCenterRpcServer::new(peer_center.get_rpc_service()), "");
        s.registry()
            .register(VpnPortalRpcServer::new(vpn_portal_rpc), "");
        s.registry().register(
            MappedListenerManageRpcServer::new(mapped_listener_manager_rpc),
            "",
        );
        s.registry().register(
            PortForwardManageRpcServer::new(port_forward_manager_rpc),
            "",
        );
        s.registry().register(
            crate::proto::cli::StatsRpcServer::new(stats_rpc_service),
            "",
        );

        if let Some(ip_proxy) = self.ip_proxy.as_ref() {
            s.registry().register(
                TcpProxyRpcServer::new(TcpProxyRpcService::new(ip_proxy.tcp_proxy.clone())),
                "tcp",
            );
        }
        if let Some(kcp_proxy) = self.kcp_proxy_src.as_ref() {
            s.registry().register(
                TcpProxyRpcServer::new(TcpProxyRpcService::new(kcp_proxy.get_tcp_proxy())),
                "kcp_src",
            );
        }

        if let Some(kcp_proxy) = self.kcp_proxy_dst.as_ref() {
            s.registry().register(
                TcpProxyRpcServer::new(KcpProxyDstRpcService::new(kcp_proxy)),
                "kcp_dst",
            );
        }

        if let Some(quic_proxy) = self.quic_proxy_src.as_ref() {
            s.registry().register(
                TcpProxyRpcServer::new(TcpProxyRpcService::new(quic_proxy.get_tcp_proxy())),
                "quic_src",
            );
        }

        if let Some(quic_proxy) = self.quic_proxy_dst.as_ref() {
            s.registry().register(
                TcpProxyRpcServer::new(QUICProxyDstRpcService::new(quic_proxy)),
                "quic_dst",
            );
        }

        s.set_hook(Arc::new(InstanceRpcServerHook::new(
            self.global_ctx.config.get_rpc_portal_whitelist(),
        )));

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

    #[cfg(any(target_os = "android", target_env = "ohos"))]
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

        let magic_dns_runner = if let Some(ipv4) = global_ctx.get_ipv4() {
            Self::create_magic_dns_runner(peer_manager.clone(), None, ipv4)
        } else {
            None
        };
        Self::use_new_nic_ctx(nic_ctx.clone(), new_nic_ctx, magic_dns_runner).await;
        Ok(())
    }

    pub async fn clear_resources(&mut self) {
        self.peer_manager.clear_resources().await;
        let _ = self.nic_ctx.lock().await.take();
        if let Some(rpc_server) = self.rpc_server.take() {
            rpc_server.registry().unregister_all();
        };
    }
}

impl Drop for Instance {
    fn drop(&mut self) {
        let my_peer_id = self.peer_manager.my_peer_id();
        let pm = Arc::downgrade(&self.peer_manager);
        let nic_ctx = self.nic_ctx.clone();
        if let Some(rpc_server) = self.rpc_server.take() {
            rpc_server.registry().unregister_all();
        };
        tokio::spawn(async move {
            nic_ctx.lock().await.take();
            if let Some(pm) = pm.upgrade() {
                pm.clear_resources().await;
            };

            let now = std::time::Instant::now();
            while now.elapsed().as_secs() < 10 {
                tokio::time::sleep(std::time::Duration::from_millis(50)).await;
                if pm.strong_count() == 0 {
                    tracing::info!(
                        "Instance for peer {} dropped, all resources cleared.",
                        my_peer_id
                    );
                    return;
                }
            }

            debug_assert!(
                false,
                "Instance for peer {} dropped, but resources not cleared in 1 seconds.",
                my_peer_id
            );
        });
    }
}

#[cfg(test)]
mod tests {
    use crate::{
        instance::instance::InstanceRpcServerHook, proto::rpc_impl::standalone::RpcServerHook,
    };

    #[tokio::test]
    async fn test_rpc_portal_whitelist() {
        use cidr::IpCidr;

        struct TestCase {
            remote_url: String,
            whitelist: Option<Vec<IpCidr>>,
            expected_result: bool,
        }

        let test_cases: Vec<TestCase> = vec![
            // Test default whitelist (127.0.0.0/8, ::1/128)
            TestCase {
                remote_url: "tcp://127.0.0.1:15888".to_string(),
                whitelist: None,
                expected_result: true,
            },
            TestCase {
                remote_url: "tcp://127.1.2.3:15888".to_string(),
                whitelist: None,
                expected_result: true,
            },
            TestCase {
                remote_url: "tcp://192.168.1.1:15888".to_string(),
                whitelist: None,
                expected_result: false,
            },
            // Test custom whitelist
            TestCase {
                remote_url: "tcp://192.168.1.10:15888".to_string(),
                whitelist: Some(vec![
                    "192.168.1.0/24".parse().unwrap(),
                    "10.0.0.0/8".parse().unwrap(),
                ]),
                expected_result: true,
            },
            TestCase {
                remote_url: "tcp://10.1.2.3:15888".to_string(),
                whitelist: Some(vec![
                    "192.168.1.0/24".parse().unwrap(),
                    "10.0.0.0/8".parse().unwrap(),
                ]),
                expected_result: true,
            },
            TestCase {
                remote_url: "tcp://172.16.0.1:15888".to_string(),
                whitelist: Some(vec![
                    "192.168.1.0/24".parse().unwrap(),
                    "10.0.0.0/8".parse().unwrap(),
                ]),
                expected_result: false,
            },
            // Test empty whitelist (should reject all connections)
            TestCase {
                remote_url: "tcp://127.0.0.1:15888".to_string(),
                whitelist: Some(vec![]),
                expected_result: false,
            },
            // Test broad whitelist (0.0.0.0/0 and ::/0 accept all IP addresses)
            TestCase {
                remote_url: "tcp://8.8.8.8:15888".to_string(),
                whitelist: Some(vec!["0.0.0.0/0".parse().unwrap()]),
                expected_result: true,
            },
            // Test edge case: specific IP whitelist
            TestCase {
                remote_url: "tcp://192.168.1.5:15888".to_string(),
                whitelist: Some(vec!["192.168.1.5/32".parse().unwrap()]),
                expected_result: true,
            },
            TestCase {
                remote_url: "tcp://192.168.1.6:15888".to_string(),
                whitelist: Some(vec!["192.168.1.5/32".parse().unwrap()]),
                expected_result: false,
            },
            // Test invalid URL (this case will fail during URL parsing)
            TestCase {
                remote_url: "invalid-url".to_string(),
                whitelist: None,
                expected_result: false,
            },
            // Test URL without IP address (this case will fail during IP parsing)
            TestCase {
                remote_url: "tcp://localhost:15888".to_string(),
                whitelist: None,
                expected_result: false,
            },
        ];

        for case in test_cases {
            let hook = InstanceRpcServerHook::new(case.whitelist.clone());
            let tunnel_info = Some(crate::proto::common::TunnelInfo {
                remote_addr: Some(crate::proto::common::Url {
                    url: case.remote_url.clone(),
                }),
                ..Default::default()
            });

            let result = hook.on_new_client(tunnel_info).await;
            if case.expected_result {
                assert!(
                    result.is_ok(),
                    "Expected success for remote_url:{},whitelist:{:?},but got: {:?}",
                    case.remote_url,
                    case.whitelist,
                    result
                );
            } else {
                assert!(
                    result.is_err(),
                    "Expected failure for remote_url:{},whitelist:{:?},but got: {:?}",
                    case.remote_url,
                    case.whitelist,
                    result
                );
            }
        }
    }
}
