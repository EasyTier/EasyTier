use std::any::Any;
use std::collections::HashSet;
use std::net::{IpAddr, Ipv4Addr};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Weak};
use std::time::Duration;

use anyhow::Context;
use cidr::{IpCidr, Ipv4Inet};

use futures::FutureExt;
use tokio::sync::{oneshot, Notify};
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
use crate::proto::api::config::{
    ConfigPatchAction, ConfigRpc, PatchConfigRequest, PatchConfigResponse, PortForwardPatch,
};
use crate::proto::api::instance::{
    GetPrometheusStatsRequest, GetPrometheusStatsResponse, GetStatsRequest, GetStatsResponse,
    GetVpnPortalInfoRequest, GetVpnPortalInfoResponse, ListMappedListenerRequest,
    ListMappedListenerResponse, ListPortForwardRequest, ListPortForwardResponse, MappedListener,
    MappedListenerManageRpc, MetricSnapshot, PortForwardManageRpc, StatsRpc, VpnPortalInfo,
    VpnPortalRpc,
};
use crate::proto::common::{PortForwardConfigPb, TunnelInfo};
use crate::proto::rpc_impl::standalone::RpcServerHook;
use crate::proto::rpc_types;
use crate::proto::rpc_types::controller::BaseController;
use crate::rpc_service::InstanceRpcService;
use crate::utils::weak_upgrade;
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

#[derive(Clone)]
pub struct InstanceConfigPatcher {
    global_ctx: Weak<GlobalCtx>,
    socks5_server: Weak<Socks5Server>,
    peer_manager: Weak<PeerManager>,
    conn_manager: Weak<ManualConnectorManager>,
}

impl InstanceConfigPatcher {
    pub async fn apply_patch(
        &self,
        patch: crate::proto::api::config::InstanceConfigPatch,
    ) -> Result<(), anyhow::Error> {
        let patch_for_event = patch.clone();

        self.patch_port_forwards(patch.port_forwards).await?;
        self.patch_acl(patch.acl).await?;
        self.patch_proxy_networks(patch.proxy_networks).await?;
        self.patch_routes(patch.routes).await?;
        self.patch_exit_nodes(patch.exit_nodes).await?;
        self.patch_mapped_listeners(patch.mapped_listeners).await?;
        self.patch_connector(patch.connectors).await?;

        let global_ctx = weak_upgrade(&self.global_ctx)?;
        if let Some(hostname) = patch.hostname {
            global_ctx.set_hostname(hostname.clone());
            global_ctx.config.set_hostname(Some(hostname));
        }
        if let Some(ipv4) = patch.ipv4 {
            if !global_ctx.config.get_dhcp() {
                global_ctx.set_ipv4(Some(ipv4.into()));
                global_ctx.config.set_ipv4(Some(ipv4.into()));
            }
        }
        if let Some(ipv6) = patch.ipv6 {
            global_ctx.set_ipv6(Some(ipv6.into()));
            global_ctx.config.set_ipv6(Some(ipv6.into()));
        }

        global_ctx.issue_event(GlobalCtxEvent::ConfigPatched(patch_for_event));

        Ok(())
    }

    fn trace_patchables<T: std::fmt::Debug>(
        patches: &Vec<crate::proto::api::config::Patchable<T>>,
    ) {
        for patch in patches {
            match patch.action {
                Some(ConfigPatchAction::Add) | Some(ConfigPatchAction::Remove) => {
                    if let Some(value) = &patch.value {
                        tracing::info!("{:?} {:?}", patch.action, value);
                    } else {
                        tracing::warn!(
                            "Ignored {:?} patch with no value for type '{}'. Please ensure the patch value is provided.",
                            patch.action,
                            std::any::type_name::<T>()
                        );
                    }
                }
                Some(ConfigPatchAction::Clear) => {
                    tracing::info!("Clear all for type '{}'", std::any::type_name::<T>());
                }
                None => {
                    tracing::warn!(
                        "Invalid patch action for type '{}'",
                        std::any::type_name::<T>()
                    );
                }
            }
        }
    }

    async fn patch_port_forwards(
        &self,
        port_forwards: Vec<PortForwardPatch>,
    ) -> Result<(), anyhow::Error> {
        if port_forwards.is_empty() {
            return Ok(());
        }
        let Some(socks5_server) = self.socks5_server.upgrade() else {
            return Err(anyhow::anyhow!("socks5 server not available"));
        };
        let global_ctx = weak_upgrade(&self.global_ctx)?;

        let mut current_forwards = global_ctx.config.get_port_forwards();
        let patches = port_forwards.into_iter().map(Into::into).collect();
        InstanceConfigPatcher::trace_patchables(&patches);
        crate::proto::api::config::patch_vec(&mut current_forwards, patches);

        global_ctx
            .config
            .set_port_forwards(current_forwards.clone());
        socks5_server
            .reload_port_forwards(&current_forwards)
            .await
            .with_context(|| "Failed to reload port forwards")?;

        Ok(())
    }

    async fn patch_acl(
        &self,
        acl_patch: Option<crate::proto::api::config::AclPatch>,
    ) -> Result<(), anyhow::Error> {
        let Some(acl_patch) = acl_patch else {
            return Ok(());
        };
        let global_ctx = weak_upgrade(&self.global_ctx)?;
        if let Some(acl) = acl_patch.acl {
            global_ctx.config.set_acl(Some(acl));
        }
        if !acl_patch.tcp_whitelist.is_empty() {
            let mut current_whitelist = global_ctx.config.get_tcp_whitelist();
            let patches = acl_patch
                .tcp_whitelist
                .into_iter()
                .map(Into::into)
                .collect();
            InstanceConfigPatcher::trace_patchables(&patches);
            crate::proto::api::config::patch_vec(&mut current_whitelist, patches);
            global_ctx.config.set_tcp_whitelist(current_whitelist);
        }
        if !acl_patch.udp_whitelist.is_empty() {
            let mut current_whitelist = global_ctx.config.get_udp_whitelist();
            let patches = acl_patch
                .udp_whitelist
                .into_iter()
                .map(Into::into)
                .collect();
            InstanceConfigPatcher::trace_patchables(&patches);
            crate::proto::api::config::patch_vec(&mut current_whitelist, patches);
            global_ctx.config.set_udp_whitelist(current_whitelist);
        }
        global_ctx
            .get_acl_filter()
            .reload_rules(AclRuleBuilder::build(&global_ctx)?.as_ref());
        Ok(())
    }

    async fn patch_proxy_networks(
        &self,
        proxy_networks: Vec<crate::proto::api::config::ProxyNetworkPatch>,
    ) -> Result<(), anyhow::Error> {
        if proxy_networks.is_empty() {
            return Ok(());
        }
        let global_ctx = weak_upgrade(&self.global_ctx)?;
        for proxy_network_patch in proxy_networks {
            let Some(cidr) = proxy_network_patch.cidr.map(|c| c.into()) else {
                tracing::warn!("Proxy network cidr is None, skipping.");
                continue;
            };
            let mapped_cidr: Option<cidr::Ipv4Cidr> =
                proxy_network_patch.mapped_cidr.map(|s| s.into());
            match ConfigPatchAction::try_from(proxy_network_patch.action) {
                Ok(ConfigPatchAction::Add) => {
                    tracing::info!("Proxy network added: {}", cidr);
                    global_ctx.config.add_proxy_cidr(cidr, mapped_cidr)?;
                }
                Ok(ConfigPatchAction::Remove) => {
                    tracing::info!("Proxy network removed: {}", cidr);
                    global_ctx.config.remove_proxy_cidr(cidr);
                }
                Ok(ConfigPatchAction::Clear) => {
                    tracing::info!("Proxy networks cleared.");
                    global_ctx.config.clear_proxy_cidrs();
                }
                Err(_) => {
                    tracing::warn!(
                        "Invalid proxy network action: {}",
                        proxy_network_patch.action
                    );
                }
            }
        }
        Ok(())
    }

    async fn patch_routes(
        &self,
        routes: Vec<crate::proto::api::config::RoutePatch>,
    ) -> Result<(), anyhow::Error> {
        if routes.is_empty() {
            return Ok(());
        }
        let global_ctx = weak_upgrade(&self.global_ctx)?;
        let mut current_routes = global_ctx.config.get_routes().unwrap_or_default();
        let patches = routes.into_iter().map(Into::into).collect();
        InstanceConfigPatcher::trace_patchables(&patches);
        crate::proto::api::config::patch_vec(&mut current_routes, patches);
        if current_routes.is_empty() {
            global_ctx.config.set_routes(None);
        } else {
            global_ctx.config.set_routes(Some(current_routes));
        }
        Ok(())
    }

    async fn patch_exit_nodes(
        &self,
        exit_nodes: Vec<crate::proto::api::config::ExitNodePatch>,
    ) -> Result<(), anyhow::Error> {
        if exit_nodes.is_empty() {
            return Ok(());
        }
        let global_ctx = weak_upgrade(&self.global_ctx)?;
        let peer_manager = weak_upgrade(&self.peer_manager)?;
        let mut current_exit_nodes = global_ctx.config.get_exit_nodes();
        let patches = exit_nodes.into_iter().map(Into::into).collect();
        InstanceConfigPatcher::trace_patchables(&patches);
        crate::proto::api::config::patch_vec(&mut current_exit_nodes, patches);
        global_ctx.config.set_exit_nodes(current_exit_nodes);
        peer_manager.update_exit_nodes().await;

        Ok(())
    }

    async fn patch_mapped_listeners(
        &self,
        mapped_listeners: Vec<crate::proto::api::config::UrlPatch>,
    ) -> Result<(), anyhow::Error> {
        if mapped_listeners.is_empty() {
            return Ok(());
        }
        let global_ctx = weak_upgrade(&self.global_ctx)?;
        let mut current_mapped_listeners = global_ctx.config.get_mapped_listeners();
        let patches = mapped_listeners.into_iter().map(Into::into).collect();
        InstanceConfigPatcher::trace_patchables(&patches);
        crate::proto::api::config::patch_vec(&mut current_mapped_listeners, patches);
        if current_mapped_listeners.is_empty() {
            global_ctx.config.set_mapped_listeners(None);
        } else {
            global_ctx
                .config
                .set_mapped_listeners(Some(current_mapped_listeners));
        }
        Ok(())
    }

    async fn patch_connector(
        &self,
        connectors: Vec<crate::proto::api::config::UrlPatch>,
    ) -> Result<(), anyhow::Error> {
        if connectors.is_empty() {
            return Ok(());
        }
        let conn_manager = weak_upgrade(&self.conn_manager)?;
        for connector in connectors {
            let Some(url) = connector.url.map(Into::<url::Url>::into) else {
                tracing::warn!("Connector url is None, skipping.");
                return Ok(());
            };
            match ConfigPatchAction::try_from(connector.action) {
                Ok(ConfigPatchAction::Add) => {
                    tracing::info!("Connector added: {}", url);
                    conn_manager.add_connector_by_url(url.as_str()).await?;
                }
                Ok(ConfigPatchAction::Remove) => {
                    tracing::info!("Connector removed: {}", url);
                    conn_manager.remove_connector(url).await?;
                }
                Ok(ConfigPatchAction::Clear) => {
                    tracing::info!("Connectors cleared.");
                    conn_manager.clear_connectors().await;
                }
                Err(_) => {
                    tracing::warn!("Invalid connector action: {}", connector.action);
                }
            }
        }
        Ok(())
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

    global_ctx: ArcGlobalCtx,
}

impl Instance {
    pub fn new(config: impl ConfigLoader + 'static) -> Self {
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
            let nic_closed_notifier = Arc::new(Notify::new());
            loop {
                tokio::time::sleep(std::time::Duration::from_secs(next_sleep_time)).await;

                let Some(peer_manager_c) = peer_manager_c.upgrade() else {
                    tracing::warn!("peer manager is dropped, stop dhcp check.");
                    return;
                };

                if nic_closed_notifier.notified().now_or_never().is_some() {
                    tracing::debug!("nic ctx is closed, try recreate it");
                    current_dhcp_ip = None;
                }

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

                let last_ip = current_dhcp_ip;
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
                            nic_closed_notifier.clone(),
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
                            Self::create_magic_dns_runner(peer_manager_c.clone(), ifname, ip),
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

    fn check_for_static_ip(&self, first_round_output: oneshot::Sender<Result<(), Error>>) {
        let ipv4_addr = self.global_ctx.get_ipv4();
        let ipv6_addr = self.global_ctx.get_ipv6();

        // Only run if we have at least one IP address (IPv4 or IPv6)
        if ipv4_addr.is_none() && ipv6_addr.is_none() {
            let _ = first_round_output.send(Ok(()));
            return;
        }

        let nic_ctx = self.nic_ctx.clone();
        let peer_mgr = Arc::downgrade(&self.peer_manager);
        let peer_packet_receiver = self.peer_packet_receiver.clone();

        tokio::spawn(async move {
            let mut output_tx = Some(first_round_output);
            loop {
                let Some(peer_manager) = peer_mgr.upgrade() else {
                    tracing::warn!("peer manager is dropped, stop static ip check.");
                    if let Some(output_tx) = output_tx.take() {
                        let _ = output_tx.send(Err(Error::Unknown));
                        return;
                    }
                    return;
                };

                let close_notifier = Arc::new(Notify::new());
                let mut new_nic_ctx = NicCtx::new(
                    peer_manager.get_global_ctx(),
                    &peer_manager,
                    peer_packet_receiver.clone(),
                    close_notifier.clone(),
                );

                if let Err(e) = new_nic_ctx.run(ipv4_addr, ipv6_addr).await {
                    if let Some(output_tx) = output_tx.take() {
                        let _ = output_tx.send(Err(e));
                        return;
                    }
                    tracing::error!("failed to create new nic ctx, err: {:?}", e);
                    tokio::time::sleep(Duration::from_secs(1)).await;
                    continue;
                }
                let ifname = new_nic_ctx.ifname().await;

                // Create Magic DNS runner only if we have IPv4
                let dns_runner = if let Some(ipv4) = ipv4_addr {
                    Self::create_magic_dns_runner(peer_manager, ifname, ipv4)
                } else {
                    None
                };
                Self::use_new_nic_ctx(nic_ctx.clone(), new_nic_ctx, dns_runner).await;

                if let Some(output_tx) = output_tx.take() {
                    let _ = output_tx.send(Ok(()));
                }

                // NOTICE: make sure we do not hold the peer manager here,
                while close_notifier.notified().now_or_never().is_none() {
                    tokio::time::sleep(Duration::from_secs(1)).await;
                    if peer_mgr.strong_count() == 0 {
                        tracing::warn!("peer manager is dropped, stop static ip check.");
                        return;
                    }
                }
            }
        });
    }

    async fn run_quic_dst(&mut self) -> Result<(), Error> {
        if self.global_ctx.get_flags().disable_quic_input {
            return Ok(());
        }

        let route = Arc::new(self.peer_manager.get_route());
        let quic_dst = QUICProxyDst::new(self.global_ctx.clone(), route)?;
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
                let (output_tx, output_rx) = oneshot::channel();
                self.check_for_static_ip(output_tx);
                output_rx.await.unwrap()?;
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
        pub struct MappedListenerManagerRpcService(Weak<GlobalCtx>);

        #[async_trait::async_trait]
        impl MappedListenerManageRpc for MappedListenerManagerRpcService {
            type Controller = BaseController;

            async fn list_mapped_listener(
                &self,
                _: BaseController,
                _request: ListMappedListenerRequest,
            ) -> Result<ListMappedListenerResponse, rpc_types::error::Error> {
                let mut ret = ListMappedListenerResponse::default();
                let urls = weak_upgrade(&self.0)?.config.get_mapped_listeners();
                let mapped_listeners: Vec<MappedListener> = urls
                    .into_iter()
                    .map(|u| MappedListener {
                        url: Some(u.into()),
                    })
                    .collect();
                ret.mappedlisteners = mapped_listeners;
                Ok(ret)
            }
        }

        MappedListenerManagerRpcService(Arc::downgrade(&self.global_ctx))
    }

    fn get_port_forward_manager_rpc_service(
        &self,
    ) -> impl PortForwardManageRpc<Controller = BaseController> + Clone {
        #[derive(Clone)]
        pub struct PortForwardManagerRpcService {
            global_ctx: Weak<GlobalCtx>,
            socks5_server: Weak<Socks5Server>,
        }

        #[async_trait::async_trait]
        impl PortForwardManageRpc for PortForwardManagerRpcService {
            type Controller = BaseController;

            async fn list_port_forward(
                &self,
                _: BaseController,
                _request: ListPortForwardRequest,
            ) -> Result<ListPortForwardResponse, rpc_types::error::Error> {
                let forwards = weak_upgrade(&self.global_ctx)?.config.get_port_forwards();
                let cfgs: Vec<PortForwardConfigPb> = forwards.into_iter().map(Into::into).collect();
                Ok(ListPortForwardResponse { cfgs })
            }
        }

        PortForwardManagerRpcService {
            global_ctx: Arc::downgrade(&self.global_ctx),
            socks5_server: Arc::downgrade(&self.socks5_server),
        }
    }

    fn get_stats_rpc_service(&self) -> impl StatsRpc<Controller = BaseController> + Clone {
        #[derive(Clone)]
        pub struct StatsRpcService {
            global_ctx: Weak<GlobalCtx>,
        }

        #[async_trait::async_trait]
        impl StatsRpc for StatsRpcService {
            type Controller = BaseController;

            async fn get_stats(
                &self,
                _: BaseController,
                _request: GetStatsRequest,
            ) -> Result<GetStatsResponse, rpc_types::error::Error> {
                let snapshots = weak_upgrade(&self.global_ctx)?
                    .stats_manager()
                    .get_all_metrics();

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
                let prometheus_text = weak_upgrade(&self.global_ctx)?
                    .stats_manager()
                    .export_prometheus();

                Ok(GetPrometheusStatsResponse { prometheus_text })
            }
        }

        StatsRpcService {
            global_ctx: Arc::downgrade(&self.global_ctx),
        }
    }

    pub fn get_config_patcher(&self) -> InstanceConfigPatcher {
        InstanceConfigPatcher {
            global_ctx: Arc::downgrade(&self.global_ctx),
            socks5_server: Arc::downgrade(&self.socks5_server),
            peer_manager: Arc::downgrade(&self.peer_manager),
            conn_manager: Arc::downgrade(&self.conn_manager),
        }
    }

    fn get_config_service(&self) -> impl ConfigRpc<Controller = BaseController> + Clone {
        #[derive(Clone)]
        pub struct ConfigRpcService {
            patcher: InstanceConfigPatcher,
        }

        #[async_trait::async_trait]
        impl ConfigRpc for ConfigRpcService {
            type Controller = BaseController;

            async fn patch_config(
                &self,
                _: Self::Controller,
                request: PatchConfigRequest,
            ) -> crate::proto::rpc_types::error::Result<PatchConfigResponse> {
                let Some(patch) = request.patch else {
                    return Ok(PatchConfigResponse::default());
                };

                self.patcher.apply_patch(patch).await?;
                Ok(PatchConfigResponse::default())
            }
        }

        ConfigRpcService {
            patcher: self.get_config_patcher(),
        }
    }

    pub fn get_api_rpc_service(&self) -> impl InstanceRpcService {
        use crate::proto::api::instance::*;

        #[derive(Clone)]
        struct ApiRpcServiceImpl<A, B, C, D, E, F, G, H> {
            peer_mgr_rpc_service: A,
            connector_mgr_rpc_service: B,
            mapped_listener_mgr_rpc_service: C,
            vpn_portal_rpc_service: D,
            tcp_proxy_rpc_services: dashmap::DashMap<
                String,
                Arc<dyn TcpProxyRpc<Controller = BaseController> + Send + Sync>,
            >,
            acl_manage_rpc_service: E,
            port_forward_manage_rpc_service: F,
            stats_rpc_service: G,
            config_rpc_service: H,
        }

        #[async_trait::async_trait]
        impl<
                A: PeerManageRpc<Controller = BaseController> + Send + Sync,
                B: ConnectorManageRpc<Controller = BaseController> + Send + Sync,
                C: MappedListenerManageRpc<Controller = BaseController> + Send + Sync,
                D: VpnPortalRpc<Controller = BaseController> + Send + Sync,
                E: AclManageRpc<Controller = BaseController> + Send + Sync,
                F: PortForwardManageRpc<Controller = BaseController> + Send + Sync,
                G: StatsRpc<Controller = BaseController> + Send + Sync,
                H: ConfigRpc<Controller = BaseController> + Send + Sync,
            > InstanceRpcService for ApiRpcServiceImpl<A, B, C, D, E, F, G, H>
        {
            fn get_peer_manage_service(&self) -> &dyn PeerManageRpc<Controller = BaseController> {
                &self.peer_mgr_rpc_service
            }

            fn get_connector_manage_service(
                &self,
            ) -> &dyn ConnectorManageRpc<Controller = BaseController> {
                &self.connector_mgr_rpc_service
            }

            fn get_mapped_listener_manage_service(
                &self,
            ) -> &dyn MappedListenerManageRpc<Controller = BaseController> {
                &self.mapped_listener_mgr_rpc_service
            }

            fn get_vpn_portal_service(&self) -> &dyn VpnPortalRpc<Controller = BaseController> {
                &self.vpn_portal_rpc_service
            }

            fn get_proxy_service(
                &self,
                client_type: &str,
            ) -> Option<Arc<dyn TcpProxyRpc<Controller = BaseController> + Send + Sync>>
            {
                self.tcp_proxy_rpc_services
                    .get(client_type)
                    .map(|e| e.clone())
            }

            fn get_acl_manage_service(&self) -> &dyn AclManageRpc<Controller = BaseController> {
                &self.acl_manage_rpc_service
            }

            fn get_port_forward_manage_service(
                &self,
            ) -> &dyn PortForwardManageRpc<Controller = BaseController> {
                &self.port_forward_manage_rpc_service
            }

            fn get_stats_service(&self) -> &dyn StatsRpc<Controller = BaseController> {
                &self.stats_rpc_service
            }

            fn get_config_service(&self) -> &dyn ConfigRpc<Controller = BaseController> {
                &self.config_rpc_service
            }
        }

        ApiRpcServiceImpl {
            peer_mgr_rpc_service: PeerManagerRpcService::new(self.peer_manager.clone()),
            connector_mgr_rpc_service: ConnectorManagerRpcService(Arc::downgrade(
                &self.conn_manager,
            )),
            mapped_listener_mgr_rpc_service: self.get_mapped_listener_manager_rpc_service(),
            vpn_portal_rpc_service: self.get_vpn_portal_rpc_service(),
            tcp_proxy_rpc_services: {
                let tcp_proxy_rpc_services: dashmap::DashMap<
                    String,
                    Arc<dyn TcpProxyRpc<Controller = BaseController> + Send + Sync>,
                > = dashmap::DashMap::new();

                if let Some(ip_proxy) = self.ip_proxy.as_ref() {
                    tcp_proxy_rpc_services.insert(
                        "tcp".to_string(),
                        Arc::new(TcpProxyRpcService::new(ip_proxy.tcp_proxy.clone())),
                    );
                }
                if let Some(kcp_proxy) = self.kcp_proxy_src.as_ref() {
                    tcp_proxy_rpc_services.insert(
                        "kcp_src".to_string(),
                        Arc::new(TcpProxyRpcService::new(kcp_proxy.get_tcp_proxy())),
                    );
                }

                if let Some(kcp_proxy) = self.kcp_proxy_dst.as_ref() {
                    tcp_proxy_rpc_services.insert(
                        "kcp_dst".to_string(),
                        Arc::new(KcpProxyDstRpcService::new(kcp_proxy)),
                    );
                }

                if let Some(quic_proxy) = self.quic_proxy_src.as_ref() {
                    tcp_proxy_rpc_services.insert(
                        "quic_src".to_string(),
                        Arc::new(TcpProxyRpcService::new(quic_proxy.get_tcp_proxy())),
                    );
                }

                if let Some(quic_proxy) = self.quic_proxy_dst.as_ref() {
                    tcp_proxy_rpc_services.insert(
                        "quic_dst".to_string(),
                        Arc::new(QUICProxyDstRpcService::new(quic_proxy)),
                    );
                }

                tcp_proxy_rpc_services
            },
            acl_manage_rpc_service: PeerManagerRpcService::new(self.peer_manager.clone()),
            port_forward_manage_rpc_service: self.get_port_forward_manager_rpc_service(),
            stats_rpc_service: self.get_stats_rpc_service(),
            config_rpc_service: self.get_config_service(),
        }
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
        let close_notifier = Arc::new(Notify::new());
        let mut new_nic_ctx = NicCtx::new(
            global_ctx.clone(),
            &peer_manager,
            peer_packet_receiver.clone(),
            close_notifier.clone(),
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
    }
}

impl Drop for Instance {
    fn drop(&mut self) {
        let my_peer_id = self.peer_manager.my_peer_id();
        let pm = Arc::downgrade(&self.peer_manager);
        let nic_ctx = self.nic_ctx.clone();
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
