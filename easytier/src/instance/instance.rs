#[cfg(feature = "tun")]
use std::any::Any;
use std::net::IpAddr;
use std::sync::{
    Arc, Weak,
    atomic::{AtomicBool, Ordering},
};
#[cfg(feature = "tun")]
use std::time::Duration;

use anyhow::Context;
use cidr::{IpCidr, Ipv4Inet};
use easytier_core::dhcp::DhcpIpv4Host;
#[cfg(any(feature = "kcp", feature = "quic"))]
use easytier_core::proxy::wrapped_transport::WrappedTransportEngine;
use easytier_core::proxy::wrapped_transport::{
    WrappedTransportEngineBuild, WrappedTransportEngineFactory,
};
use easytier_core::tunnel::ring::RingTunnelRegistry;
#[cfg(feature = "tun")]
use futures::FutureExt;
#[cfg(feature = "tun")]
use tokio::sync::Notify;
use tokio::sync::{Mutex, mpsc};
#[cfg(feature = "tun")]
use tokio::{sync::oneshot, task::JoinSet};
use tokio_util::sync::CancellationToken;
#[cfg(feature = "magic-dns")]
use tokio_util::task::AbortOnDropHandle;

use crate::common::PeerId;
use crate::common::acl_processor::runtime_acl_config;
use crate::common::config::ConfigLoader;
use crate::common::error::Error;
use crate::common::global_ctx::{ArcGlobalCtx, GlobalCtx, GlobalCtxEvent};
use crate::connector::core_instance::{
    RuntimeCoreInstance,
    build_portable_runtime_core_instance_with_transport_factory_and_ring_registry,
    runtime_instance_config,
};
use crate::connector::manual::{ConnectorManagerRpcService, ManualConnectorManager};
#[cfg(feature = "kcp")]
use crate::gateway::kcp_proxy::KcpProxyService;
#[cfg(feature = "quic")]
use crate::gateway::quic_proxy::QuicProxyService;
use crate::gateway::tcp_proxy::CoreTcpProxyRpcService;
use crate::launcher::NetworkConfigExt;
use crate::peer_center::instance::PeerCenterInstanceService;
use crate::peers::peer_conn::PeerConnId;
use crate::peers::rpc_service::PeerManagerRpcService;
use crate::proto::api::config::{
    ConfigPatchAction, ConfigRpc, GetConfigRequest, GetConfigResponse, PatchConfigRequest,
    PatchConfigResponse, PortForwardPatch,
};
use crate::proto::api::instance::{
    GetPrometheusStatsRequest, GetPrometheusStatsResponse, GetStatsRequest, GetStatsResponse,
    GetVpnPortalInfoRequest, GetVpnPortalInfoResponse, ListMappedListenerRequest,
    ListMappedListenerResponse, ListPortForwardRequest, ListPortForwardResponse, MappedListener,
    MappedListenerManageRpc, MetricSnapshot, PortForwardManageRpc, StatsRpc, VpnPortalInfo,
    VpnPortalRpc,
};
use crate::proto::api::manage::NetworkConfig;
use crate::proto::common::{PortForwardConfigPb, TunnelInfo};
use crate::proto::peer_rpc::PeerCenterRpc;
use crate::proto::rpc_impl::standalone::RpcServerHook;
use crate::proto::rpc_types;
use crate::proto::rpc_types::controller::BaseController;
use crate::rpc_service::InstanceRpcService;
use crate::utils::weak_upgrade;

#[cfg(feature = "magic-dns")]
use super::dns_server::{MAGIC_DNS_FAKE_IP, runner::DnsRunner};
use super::public_ipv6_provider::validate_public_ipv6_config_values;

pub(crate) type HostPacketReceiver = mpsc::Receiver<Vec<u8>>;

struct RuntimeTransportProxyFactory;

impl RuntimeTransportProxyFactory {
    fn new() -> Self {
        Self
    }
}

struct RuntimeTransportProxyAttachment {
    #[cfg(feature = "kcp")]
    kcp: Weak<KcpProxyService>,
    #[cfg(feature = "quic")]
    quic: Weak<QuicProxyService>,
}

impl RuntimeTransportProxyAttachment {
    #[cfg(feature = "kcp")]
    fn kcp(&self) -> Arc<KcpProxyService> {
        self.kcp
            .upgrade()
            .expect("core must retain the KCP proxy lifecycle")
    }

    #[cfg(feature = "quic")]
    fn quic(&self) -> Arc<QuicProxyService> {
        self.quic
            .upgrade()
            .expect("core must retain the QUIC proxy lifecycle")
    }
}

impl WrappedTransportEngineFactory for RuntimeTransportProxyFactory {
    type Attachment = RuntimeTransportProxyAttachment;

    fn build(self) -> anyhow::Result<WrappedTransportEngineBuild<Self::Attachment>> {
        #[cfg(any(feature = "kcp", feature = "quic"))]
        let (kcp_engine, quic_engine, attachment) = {
            #[cfg(feature = "kcp")]
            let kcp = Arc::new(KcpProxyService::new());
            #[cfg(feature = "quic")]
            let quic = Arc::new(QuicProxyService::new());
            (
                #[cfg(feature = "kcp")]
                Some(kcp.clone() as Arc<dyn WrappedTransportEngine>),
                #[cfg(not(feature = "kcp"))]
                None,
                #[cfg(feature = "quic")]
                Some(quic.clone() as Arc<dyn WrappedTransportEngine>),
                #[cfg(not(feature = "quic"))]
                None,
                RuntimeTransportProxyAttachment {
                    #[cfg(feature = "kcp")]
                    kcp: Arc::downgrade(&kcp),
                    #[cfg(feature = "quic")]
                    quic: Arc::downgrade(&quic),
                },
            )
        };
        #[cfg(not(any(feature = "kcp", feature = "quic")))]
        let (kcp_engine, quic_engine, attachment) = {
            let _ = self;
            (None, None, RuntimeTransportProxyAttachment {})
        };

        Ok(WrappedTransportEngineBuild {
            kcp: kcp_engine,
            quic: quic_engine,
            attachment,
        })
    }
}

#[cfg(feature = "tun")]
type NicCtx = super::virtual_nic::NicCtx;

#[cfg(feature = "magic-dns")]
struct MagicDnsContainer {
    dns_runner_task: AbortOnDropHandle<()>,
    dns_runner_cancel_token: CancellationToken,
}

// nic container will be cleared when dhcp ip changed
#[cfg(feature = "tun")]
pub struct NicCtxContainer {
    nic_ctx: Option<Box<dyn Any + 'static + Send>>,
    #[cfg(feature = "magic-dns")]
    magic_dns: Option<MagicDnsContainer>,
}

#[cfg(feature = "tun")]
impl NicCtxContainer {
    #[cfg(not(feature = "magic-dns"))]
    fn new(nic_ctx: NicCtx) -> Self {
        Self {
            nic_ctx: Some(Box::new(nic_ctx)),
        }
    }

    #[cfg(feature = "magic-dns")]
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
                    dns_runner_task: AbortOnDropHandle::new(task),
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
            #[cfg(feature = "magic-dns")]
            magic_dns: None,
        }
    }
}

#[cfg(feature = "tun")]
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

#[derive(Default)]
struct ConfigOperation {
    closing: AtomicBool,
    operation: Mutex<()>,
    cancel: CancellationToken,
}

#[derive(Clone)]
pub struct InstanceConfigPatcher {
    global_ctx: Weak<GlobalCtx>,
    core_instance: Weak<RuntimeCoreInstance>,
    operation: Arc<ConfigOperation>,
}

impl InstanceConfigPatcher {
    fn parse_ipv6_public_addr_prefix_patch(
        prefix: Option<&str>,
    ) -> Result<Option<Option<cidr::Ipv6Cidr>>, anyhow::Error> {
        let Some(prefix) = prefix else {
            return Ok(None);
        };

        let prefix = prefix.trim();
        if prefix.is_empty() {
            return Ok(Some(None));
        }

        let parsed = prefix
            .parse()
            .with_context(|| format!("failed to parse ipv6 public address prefix: {prefix}"))?;
        Ok(Some(Some(parsed)))
    }

    fn effective_ipv6_for_public_ipv6_validation(
        global_ctx: &ArcGlobalCtx,
        patch: &crate::proto::api::config::InstanceConfigPatch,
        _auto_enabled: bool,
    ) -> Option<cidr::Ipv6Inet> {
        if let Some(ipv6) = patch.ipv6 {
            return Some(ipv6.into());
        }

        global_ctx.get_ipv6()
    }

    fn validate_public_ipv6_patch(
        global_ctx: &ArcGlobalCtx,
        patch: &crate::proto::api::config::InstanceConfigPatch,
    ) -> Result<Option<Option<cidr::Ipv6Cidr>>, anyhow::Error> {
        let parsed_prefix =
            Self::parse_ipv6_public_addr_prefix_patch(patch.ipv6_public_addr_prefix.as_deref())?;

        let auto_enabled = patch
            .ipv6_public_addr_auto
            .unwrap_or(global_ctx.config.get_ipv6_public_addr_auto());
        let provider_enabled = patch
            .ipv6_public_addr_provider
            .unwrap_or(global_ctx.config.get_ipv6_public_addr_provider());
        let prefix =
            parsed_prefix.unwrap_or_else(|| global_ctx.config.get_ipv6_public_addr_prefix());
        let ipv6 = Self::effective_ipv6_for_public_ipv6_validation(global_ctx, patch, auto_enabled);

        validate_public_ipv6_config_values(ipv6, provider_enabled, auto_enabled, prefix)?;
        Ok(parsed_prefix)
    }

    pub async fn apply_patch(
        &self,
        patch: crate::proto::api::config::InstanceConfigPatch,
    ) -> Result<(), anyhow::Error> {
        if self.operation.closing.load(Ordering::Acquire) {
            anyhow::bail!("instance is closing; config patch rejected");
        }
        let _operation = self.operation.operation.lock().await;
        if self.operation.closing.load(Ordering::Acquire) {
            anyhow::bail!("instance is closing; config patch rejected");
        }
        let patch_for_event = patch.clone();
        let global_ctx = weak_upgrade(&self.global_ctx)?;
        let core_instance = weak_upgrade(&self.core_instance)?;
        let parsed_ipv6_public_addr_prefix = Self::validate_public_ipv6_patch(&global_ctx, &patch)?;

        // Preserve the legacy ordered partial-commit contract: earlier valid
        // sub-patches stay applied if a later sub-patch fails. The shared lock
        // prevents interleaving, and the final snapshot always mirrors every
        // host change that did commit before the error.
        let patch_result: Result<bool, anyhow::Error> = async {
            self.patch_port_forwards(patch.port_forwards).await?;
            self.patch_acl(patch.acl).await?;
            self.patch_proxy_networks(patch.proxy_networks).await?;
            self.patch_routes(patch.routes).await?;
            self.patch_exit_nodes(patch.exit_nodes).await?;
            self.patch_mapped_listeners(patch.mapped_listeners).await?;
            self.patch_connector(patch.connectors).await?;

            let mut provider_config_changed = false;
            if let Some(hostname) = patch.hostname {
                global_ctx.set_hostname(hostname.clone());
                global_ctx.config.set_hostname(Some(hostname));
            }
            if let Some(ipv4) = patch.ipv4
                && !global_ctx.config.get_dhcp()
            {
                global_ctx.set_ipv4(Some(ipv4.into()));
                global_ctx.config.set_ipv4(Some(ipv4.into()));
            }
            if let Some(ipv6) = patch.ipv6 {
                global_ctx.set_ipv6(Some(ipv6.into()));
                global_ctx.config.set_ipv6(Some(ipv6.into()));
            }
            if let Some(disable_relay_data) = patch.disable_relay_data {
                let mut flags = global_ctx.get_flags();
                flags.disable_relay_data = disable_relay_data;
                global_ctx.set_flags(flags);
            }
            if let Some(enabled) = patch.ipv6_public_addr_provider {
                global_ctx.config.set_ipv6_public_addr_provider(enabled);
                provider_config_changed = true;
            }
            if let Some(enabled) = patch.ipv6_public_addr_auto {
                global_ctx.config.set_ipv6_public_addr_auto(enabled);
            }
            if let Some(prefix) = parsed_ipv6_public_addr_prefix {
                global_ctx.config.set_ipv6_public_addr_prefix(prefix);
                provider_config_changed = true;
            }
            Ok(provider_config_changed)
        }
        .await;

        core_instance
            .update_runtime_config(runtime_instance_config(&global_ctx))
            .await?;
        let provider_config_changed = patch_result?;
        global_ctx.issue_event(GlobalCtxEvent::ConfigPatched(patch_for_event));

        if provider_config_changed {
            core_instance.reconcile_public_ipv6_provider().await;
            core_instance.start_public_ipv6_provider().await;
        }

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
        let global_ctx = weak_upgrade(&self.global_ctx)?;

        let mut current_forwards = global_ctx.config.get_port_forwards();
        let patches = port_forwards
            .into_iter()
            .map(|patch| crate::proto::api::config::Patchable {
                action: ConfigPatchAction::try_from(patch.action).ok(),
                value: patch.cfg.map(Into::into),
            })
            .collect();
        InstanceConfigPatcher::trace_patchables(&patches);
        crate::proto::api::config::patch_vec(&mut current_forwards, patches);

        global_ctx.config.set_port_forwards(current_forwards);

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
        let mut config = runtime_acl_config(&global_ctx);
        if let Some(acl) = acl_patch.acl {
            config.acl = Some(acl);
        }
        if !acl_patch.tcp_whitelist.is_empty() {
            let patches = acl_patch
                .tcp_whitelist
                .into_iter()
                .map(Into::into)
                .collect();
            InstanceConfigPatcher::trace_patchables(&patches);
            crate::proto::api::config::patch_vec(&mut config.tcp_whitelist, patches);
        }
        if !acl_patch.udp_whitelist.is_empty() {
            let patches = acl_patch
                .udp_whitelist
                .into_iter()
                .map(Into::into)
                .collect();
            InstanceConfigPatcher::trace_patchables(&patches);
            crate::proto::api::config::patch_vec(&mut config.udp_whitelist, patches);
        }
        config.build()?;
        let previous_acl = global_ctx.config.get_acl();
        let previous_tcp_whitelist = global_ctx.config.get_tcp_whitelist();
        let previous_udp_whitelist = global_ctx.config.get_udp_whitelist();
        let core_config = config.clone();
        global_ctx.config.set_acl(config.acl);
        global_ctx.config.set_tcp_whitelist(config.tcp_whitelist);
        global_ctx.config.set_udp_whitelist(config.udp_whitelist);
        if let Err(error) = weak_upgrade(&self.core_instance)?
            .reload_acl_config(&core_config)
            .await
        {
            global_ctx.config.set_acl(previous_acl);
            global_ctx.config.set_tcp_whitelist(previous_tcp_whitelist);
            global_ctx.config.set_udp_whitelist(previous_udp_whitelist);
            return Err(error);
        }
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
            match ConfigPatchAction::try_from(proxy_network_patch.action) {
                Ok(ConfigPatchAction::Add) => {
                    let Some(cidr) = proxy_network_patch.cidr.map(|c| c.into()) else {
                        tracing::warn!("Proxy network cidr is None, skipping add.");
                        continue;
                    };
                    let mapped_cidr: Option<cidr::Ipv4Cidr> =
                        proxy_network_patch.mapped_cidr.map(|s| s.into());
                    tracing::info!("Proxy network added: {}", cidr);
                    global_ctx.config.add_proxy_cidr(cidr, mapped_cidr)?;
                }
                Ok(ConfigPatchAction::Remove) => {
                    let Some(cidr) = proxy_network_patch.cidr.map(|c| c.into()) else {
                        tracing::warn!("Proxy network cidr is None, skipping remove.");
                        continue;
                    };
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
        let core_instance = weak_upgrade(&self.core_instance)?;
        let mut current_exit_nodes = global_ctx.config.get_exit_nodes();
        let patches = exit_nodes.into_iter().map(Into::into).collect();
        InstanceConfigPatcher::trace_patchables(&patches);
        crate::proto::api::config::patch_vec(&mut current_exit_nodes, patches);
        global_ctx.config.set_exit_nodes(current_exit_nodes.clone());
        core_instance.update_exit_nodes(current_exit_nodes).await;

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
        let core_instance = weak_upgrade(&self.core_instance)?;
        for connector in connectors {
            let Some(url) = connector.url.map(Into::<url::Url>::into) else {
                tracing::warn!("Connector url is None, skipping.");
                return Ok(());
            };
            match ConfigPatchAction::try_from(connector.action) {
                Ok(ConfigPatchAction::Add) => {
                    tracing::info!("Connector added: {}", url);
                    core_instance.add_connector(url)?;
                }
                Ok(ConfigPatchAction::Remove) => {
                    tracing::info!("Connector removed: {}", url);
                    if !core_instance.remove_connector(&url) {
                        return Err(Error::NotFound.into());
                    }
                }
                Ok(ConfigPatchAction::Clear) => {
                    tracing::info!("Connectors cleared.");
                    core_instance.clear_connectors();
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

    #[cfg(feature = "tun")]
    nic_ctx: ArcNicCtx,

    peer_packet_receiver: Arc<Mutex<HostPacketReceiver>>,
    core_instance: Arc<RuntimeCoreInstance>,
    config_operation: Arc<ConfigOperation>,

    transport_proxy: RuntimeTransportProxyAttachment,

    global_ctx: ArcGlobalCtx,
}

struct RuntimeDhcpIpv4Host {
    global_ctx: ArcGlobalCtx,
    config_operation: Arc<ConfigOperation>,
    #[cfg(feature = "tun")]
    nic_ctx: ArcNicCtx,
    #[cfg(feature = "tun")]
    peer_packet_receiver: Arc<Mutex<HostPacketReceiver>>,
    #[cfg(feature = "tun")]
    nic_closed_notifier: Arc<Notify>,
    core_instance: Weak<RuntimeCoreInstance>,
}

impl RuntimeDhcpIpv4Host {
    fn new(instance: &Instance) -> Arc<Self> {
        Arc::new(Self {
            global_ctx: instance.global_ctx.clone(),
            config_operation: instance.config_operation.clone(),
            #[cfg(feature = "tun")]
            nic_ctx: instance.nic_ctx.clone(),
            #[cfg(feature = "tun")]
            peer_packet_receiver: instance.peer_packet_receiver.clone(),
            #[cfg(feature = "tun")]
            nic_closed_notifier: Arc::new(Notify::new()),
            core_instance: Arc::downgrade(&instance.core_instance),
        })
    }

    fn ensure_config_open(&self) -> anyhow::Result<()> {
        if self.config_operation.closing.load(Ordering::Acquire)
            || self.config_operation.cancel.is_cancelled()
        {
            anyhow::bail!("instance is closing; DHCP update cancelled");
        }
        Ok(())
    }

    async fn refresh_peer_runtime_config(&self) {
        if let Some(core_instance) = self.core_instance.upgrade() {
            core_instance
                .update_peer_runtime_snapshot(runtime_instance_config(&self.global_ctx).peer)
                .await;
        }
    }
}

#[async_trait::async_trait]
impl DhcpIpv4Host for RuntimeDhcpIpv4Host {
    fn take_interface_closed(&self) -> bool {
        #[cfg(feature = "tun")]
        {
            return self.nic_closed_notifier.notified().now_or_never().is_some();
        }
        #[cfg(not(feature = "tun"))]
        false
    }

    async fn apply_dhcp_ipv4(
        &self,
        previous: Option<Ipv4Inet>,
        next: Option<Ipv4Inet>,
    ) -> anyhow::Result<()> {
        let _config_operation = self.config_operation.operation.lock().await;
        self.ensure_config_open()?;
        #[cfg(feature = "tun")]
        tokio::select! {
            biased;
            _ = self.config_operation.cancel.cancelled() => {
                anyhow::bail!("instance is closing; DHCP update cancelled");
            }
            _ = Instance::clear_nic_ctx(
                self.nic_ctx.clone(),
                self.peer_packet_receiver.clone(),
            ) => {}
        }
        self.ensure_config_open()?;

        let Some(ip) = next else {
            self.ensure_config_open()?;
            self.global_ctx.set_ipv4(None);
            self.refresh_peer_runtime_config().await;
            self.global_ctx
                .issue_event(GlobalCtxEvent::DhcpIpv4Conflicted(previous));
            return Ok(());
        };

        if self.global_ctx.no_tun() {
            self.ensure_config_open()?;
            self.global_ctx.set_ipv4(Some(ip));
            self.refresh_peer_runtime_config().await;
            self.global_ctx
                .issue_event(GlobalCtxEvent::DhcpIpv4Changed(previous, Some(ip)));
            return Ok(());
        }

        #[cfg(all(not(mobile), feature = "tun"))]
        {
            let core_instance = self
                .core_instance
                .upgrade()
                .context("core instance is gone during DHCP IPv4 apply")?;
            let mut new_nic_ctx = NicCtx::new(
                self.global_ctx.clone(),
                &core_instance,
                self.peer_packet_receiver.clone(),
                self.nic_closed_notifier.clone(),
            );
            let run_result = tokio::select! {
                biased;
                _ = self.config_operation.cancel.cancelled() => {
                    anyhow::bail!("instance is closing; DHCP update cancelled");
                }
                result = new_nic_ctx.run(Some(ip), self.global_ctx.get_ipv6()) => result,
            };
            if let Err(err) = run_result {
                self.ensure_config_open()?;
                self.global_ctx.set_ipv4(None);
                core_instance
                    .update_peer_runtime_snapshot(runtime_instance_config(&self.global_ctx).peer)
                    .await;
                return Err(err.into());
            }
            #[cfg(feature = "magic-dns")]
            let ifname = tokio::select! {
                biased;
                _ = self.config_operation.cancel.cancelled() => {
                    anyhow::bail!("instance is closing; DHCP update cancelled");
                }
                ifname = new_nic_ctx.ifname() => ifname,
            };
            tokio::select! {
                biased;
                _ = self.config_operation.cancel.cancelled() => {
                    anyhow::bail!("instance is closing; DHCP update cancelled");
                }
                _ = Instance::use_new_nic_ctx(
                    self.nic_ctx.clone(),
                    new_nic_ctx,
                    #[cfg(feature = "magic-dns")]
                    Instance::create_magic_dns_runner(
                        self.global_ctx.clone(),
                        core_instance,
                        ifname,
                        ip,
                    ),
                ) => {}
            }
        }

        self.ensure_config_open()?;
        self.global_ctx.set_ipv4(Some(ip));
        self.refresh_peer_runtime_config().await;
        self.global_ctx
            .issue_event(GlobalCtxEvent::DhcpIpv4Changed(previous, Some(ip)));
        Ok(())
    }
}

impl Instance {
    pub fn new(config: impl ConfigLoader + 'static) -> Self {
        Self::new_with_ring_registry(config, Arc::new(RingTunnelRegistry::default()))
    }

    pub fn new_with_ring_registry(
        config: impl ConfigLoader + 'static,
        ring_registry: Arc<RingTunnelRegistry>,
    ) -> Self {
        let global_ctx = Arc::new(GlobalCtx::new(config));

        tracing::info!(
            "[INIT] instance creating. config: {}",
            global_ctx.config.dump()
        );

        let (peer_packet_sender, peer_packet_receiver) = mpsc::channel(128);

        let id = global_ctx.get_id();

        let (core_instance, transport_proxy) =
            build_portable_runtime_core_instance_with_transport_factory_and_ring_registry(
                global_ctx.clone(),
                Arc::new(peer_packet_sender),
                RuntimeTransportProxyFactory::new(),
                ring_registry.clone(),
            )
            .expect("runtime core instance composition should be valid");
        let core_instance = Arc::new(core_instance);
        let config_operation = Arc::new(ConfigOperation::default());

        Instance {
            inst_name: global_ctx.inst_name.clone(),
            id,

            peer_packet_receiver: Arc::new(Mutex::new(peer_packet_receiver)),
            #[cfg(feature = "tun")]
            nic_ctx: Arc::new(Mutex::new(None)),

            core_instance,
            config_operation,

            transport_proxy,

            global_ctx,
        }
    }

    pub fn get_conn_manager(&self) -> Arc<ManualConnectorManager> {
        Arc::new(ManualConnectorManager::new_with_core_instance(
            self.core_instance.clone(),
        ))
    }

    #[cfg(feature = "tun")]
    async fn stop_nic_ctx(arc_nic_ctx: &ArcNicCtx) {
        let mut old_ctx = arc_nic_ctx.lock().await.take();
        #[cfg(feature = "magic-dns")]
        if let Some(dns_runner) = old_ctx.as_mut().and_then(|ctx| ctx.magic_dns.take()) {
            dns_runner.dns_runner_cancel_token.cancel();
            tracing::debug!("cancelling dns runner task");
            let ret = dns_runner.dns_runner_task.await;
            tracing::debug!("dns runner task cancelled, ret: {:?}", ret);
        }
        drop(old_ctx);
    }

    // use a mock nic ctx to consume packets.
    #[cfg(feature = "tun")]
    async fn clear_nic_ctx(arc_nic_ctx: ArcNicCtx, packet_recv: Arc<Mutex<HostPacketReceiver>>) {
        Self::stop_nic_ctx(&arc_nic_ctx).await;

        let mut tasks = JoinSet::new();
        tasks.spawn(async move {
            let mut packet_recv = packet_recv.lock().await;
            while let Some(packet) = packet_recv.recv().await {
                tracing::trace!("packet consumed by mock nic ctx: {:?}", packet);
            }
        });
        arc_nic_ctx
            .lock()
            .await
            .replace(NicCtxContainer::new_with_any(tasks));

        tracing::debug!("nic ctx cleared.");
    }

    #[cfg(feature = "magic-dns")]
    fn create_magic_dns_runner(
        global_ctx: ArcGlobalCtx,
        core_instance: Arc<RuntimeCoreInstance>,
        tun_dev: Option<String>,
        tun_ip: Ipv4Inet,
    ) -> Option<DnsRunner> {
        if !global_ctx.config.get_flags().accept_dns {
            return None;
        }

        let runner = DnsRunner::new(
            core_instance,
            global_ctx,
            tun_dev,
            tun_ip,
            MAGIC_DNS_FAKE_IP.parse().unwrap(),
        );
        Some(runner)
    }

    #[cfg(feature = "tun")]
    async fn use_new_nic_ctx(
        arc_nic_ctx: ArcNicCtx,
        nic_ctx: NicCtx,
        #[cfg(feature = "magic-dns")] magic_dns: Option<DnsRunner>,
    ) {
        Self::stop_nic_ctx(&arc_nic_ctx).await;
        let mut g = arc_nic_ctx.lock().await;
        *g = Some(NicCtxContainer::new(
            nic_ctx,
            #[cfg(feature = "magic-dns")]
            magic_dns,
        ));
        tracing::debug!("nic ctx updated.");
    }

    #[cfg(all(not(mobile), feature = "tun"))]
    fn check_for_static_ip(&self, first_round_output: oneshot::Sender<Result<(), Error>>) {
        let ipv4_addr = self.global_ctx.get_ipv4();
        let ipv6_addr = self.global_ctx.get_ipv6();

        // Only run if we have at least one IP address (IPv4 or IPv6)
        if ipv4_addr.is_none() && ipv6_addr.is_none() {
            let _ = first_round_output.send(Ok(()));
            return;
        }

        let nic_ctx = self.nic_ctx.clone();
        let core_instance = Arc::downgrade(&self.core_instance);
        let global_ctx = self.global_ctx.clone();
        let peer_packet_receiver = self.peer_packet_receiver.clone();

        tokio::spawn(async move {
            let mut output_tx = Some(first_round_output);
            loop {
                let close_notifier = Arc::new(Notify::new());
                {
                    let Some(core_instance) = core_instance.upgrade() else {
                        tracing::warn!("core instance is dropped, stop static IP check.");
                        if let Some(output_tx) = output_tx.take() {
                            let _ = output_tx.send(Err(Error::Unknown));
                        }
                        return;
                    };

                    let mut new_nic_ctx = NicCtx::new(
                        global_ctx.clone(),
                        &core_instance,
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

                    // Create Magic DNS runner only if we have IPv4
                    #[cfg(feature = "magic-dns")]
                    {
                        let ifname = new_nic_ctx.ifname().await;
                        let dns_runner = if let Some(ipv4) = ipv4_addr {
                            Self::create_magic_dns_runner(
                                global_ctx.clone(),
                                core_instance.clone(),
                                ifname,
                                ipv4,
                            )
                        } else {
                            None
                        };
                        Self::use_new_nic_ctx(nic_ctx.clone(), new_nic_ctx, dns_runner).await;
                    }
                    #[cfg(not(feature = "magic-dns"))]
                    Self::use_new_nic_ctx(nic_ctx.clone(), new_nic_ctx).await;
                }

                if let Some(output_tx) = output_tx.take() {
                    let _ = output_tx.send(Ok(()));
                }

                // NOTICE: make sure we do not hold the core instance here.
                while close_notifier.notified().now_or_never().is_none() {
                    tokio::time::sleep(Duration::from_secs(1)).await;
                    if core_instance.strong_count() == 0 {
                        tracing::warn!("core instance is dropped, stop static IP check.");
                        return;
                    }
                }
            }
        });
    }

    pub async fn run(&mut self) -> Result<(), Error> {
        let config_operation = self.config_operation.clone();
        if config_operation.closing.load(Ordering::Acquire) {
            return Err(anyhow::anyhow!("instance is closing; start rejected").into());
        }
        let _config_operation = config_operation.operation.lock().await;
        if config_operation.closing.load(Ordering::Acquire) {
            return Err(anyhow::anyhow!("instance is closing; start rejected").into());
        }
        self.core_instance
            .update_runtime_config(runtime_instance_config(&self.global_ctx))
            .await?;
        self.core_instance.start().await?;

        #[cfg(feature = "tun")]
        {
            Self::clear_nic_ctx(self.nic_ctx.clone(), self.peer_packet_receiver.clone()).await;

            #[cfg(not(mobile))]
            if !self.global_ctx.config.get_flags().no_tun {
                let (output_tx, output_rx) = oneshot::channel();
                self.check_for_static_ip(output_tx);
                output_rx.await.unwrap()?;
            }
        }

        // run after tun device created, so listener can bind to tun device, which may be required by win 10
        self.core_instance
            .start_network_services(Some(RuntimeDhcpIpv4Host::new(self)))
            .await?;

        #[cfg(feature = "socks5")]
        self.core_instance.start_gateway().await?;

        Ok(())
    }

    pub async fn run_vpn_portal(&mut self) -> Result<(), Error> {
        if self.global_ctx.get_vpn_portal_cidr().is_none() {
            return Err(anyhow::anyhow!("vpn portal cidr not set.").into());
        }
        self.core_instance.start_vpn_portal().await?;
        Ok(())
    }

    pub async fn close_peer_conn(
        &mut self,
        peer_id: PeerId,
        conn_id: &PeerConnId,
    ) -> Result<(), Error> {
        self.core_instance
            .close_peer_conn(peer_id, conn_id)
            .await
            .map_err(Error::from)?;
        Ok(())
    }

    pub async fn wait(&self) {
        self.core_instance.wait().await;
    }

    pub fn id(&self) -> uuid::Uuid {
        self.id
    }

    pub fn peer_id(&self) -> PeerId {
        self.core_instance.peer_id()
    }

    fn get_vpn_portal_rpc_service(
        &self,
    ) -> impl VpnPortalRpc<Controller = BaseController> + Clone + use<> {
        #[derive(Clone)]
        struct VpnPortalRpcService {
            core_instance: Weak<RuntimeCoreInstance>,
        }

        #[async_trait::async_trait]
        impl VpnPortalRpc for VpnPortalRpcService {
            type Controller = BaseController;

            async fn get_vpn_portal_info(
                &self,
                _: BaseController,
                _request: GetVpnPortalInfoRequest,
            ) -> Result<GetVpnPortalInfoResponse, rpc_types::error::Error> {
                let Some(core_instance) = self.core_instance.upgrade() else {
                    return Err(anyhow::anyhow!("vpn portal not available").into());
                };
                let info = core_instance.vpn_portal_info().await;
                let ret = GetVpnPortalInfoResponse {
                    vpn_portal_info: Some(VpnPortalInfo {
                        vpn_type: info.vpn_type,
                        client_config: info.client_config,
                        connected_clients: info.connected_clients,
                    }),
                };

                Ok(ret)
            }
        }

        VpnPortalRpcService {
            core_instance: Arc::downgrade(&self.core_instance),
        }
    }

    fn get_mapped_listener_manager_rpc_service(
        &self,
    ) -> impl MappedListenerManageRpc<Controller = BaseController> + Clone + use<> {
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
    ) -> impl PortForwardManageRpc<Controller = BaseController> + Clone + use<> {
        #[derive(Clone)]
        pub struct PortForwardManagerRpcService {
            global_ctx: Weak<GlobalCtx>,
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
        }
    }

    fn get_stats_rpc_service(&self) -> impl StatsRpc<Controller = BaseController> + Clone + use<> {
        #[derive(Clone)]
        pub struct StatsRpcService {
            core_instance: Weak<RuntimeCoreInstance>,
        }

        #[async_trait::async_trait]
        impl StatsRpc for StatsRpcService {
            type Controller = BaseController;

            async fn get_stats(
                &self,
                _: BaseController,
                _request: GetStatsRequest,
            ) -> Result<GetStatsResponse, rpc_types::error::Error> {
                let snapshots = weak_upgrade(&self.core_instance)?.metric_snapshots();

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
                let prometheus_text = weak_upgrade(&self.core_instance)?.prometheus_metrics();

                Ok(GetPrometheusStatsResponse { prometheus_text })
            }
        }

        StatsRpcService {
            core_instance: Arc::downgrade(&self.core_instance),
        }
    }

    pub fn get_config_patcher(&self) -> InstanceConfigPatcher {
        InstanceConfigPatcher {
            global_ctx: Arc::downgrade(&self.global_ctx),
            core_instance: Arc::downgrade(&self.core_instance),
            operation: self.config_operation.clone(),
        }
    }

    fn get_config_service(&self) -> impl ConfigRpc<Controller = BaseController> + Clone + use<> {
        #[derive(Clone)]
        pub struct ConfigRpcService {
            patcher: InstanceConfigPatcher,
            global_ctx: Weak<GlobalCtx>,
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

            async fn get_config(
                &self,
                _: Self::Controller,
                _request: GetConfigRequest,
            ) -> crate::proto::rpc_types::error::Result<GetConfigResponse> {
                let global_ctx = weak_upgrade(&self.global_ctx)?;
                let config = NetworkConfig::new_from_config(&global_ctx.config)?;
                Ok(GetConfigResponse {
                    config: Some(config),
                })
            }
        }

        ConfigRpcService {
            patcher: self.get_config_patcher(),
            global_ctx: Arc::downgrade(&self.global_ctx),
        }
    }

    pub fn get_api_rpc_service(&self) -> impl InstanceRpcService + use<> {
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
            peer_center_rpc_service: Arc<PeerCenterInstanceService>,
            credential_manage_rpc_service: PeerManagerRpcService,
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

            fn get_peer_center_service(
                &self,
            ) -> Arc<dyn PeerCenterRpc<Controller = BaseController> + Send + Sync> {
                self.peer_center_rpc_service.clone()
            }

            fn get_credential_manage_service(
                &self,
            ) -> &dyn CredentialManageRpc<Controller = BaseController> {
                &self.credential_manage_rpc_service
            }
        }

        ApiRpcServiceImpl {
            peer_mgr_rpc_service: PeerManagerRpcService::new(&self.global_ctx, &self.core_instance),
            connector_mgr_rpc_service: ConnectorManagerRpcService::new(&self.core_instance),
            mapped_listener_mgr_rpc_service: self.get_mapped_listener_manager_rpc_service(),
            vpn_portal_rpc_service: self.get_vpn_portal_rpc_service(),
            tcp_proxy_rpc_services: {
                let tcp_proxy_rpc_services: dashmap::DashMap<
                    String,
                    Arc<dyn TcpProxyRpc<Controller = BaseController> + Send + Sync>,
                > = dashmap::DashMap::new();

                tcp_proxy_rpc_services.insert(
                    "tcp".to_string(),
                    Arc::new(CoreTcpProxyRpcService::new(&self.core_instance)),
                );
                #[cfg(feature = "kcp")]
                if self.core_instance.wrapped_transport_is_started(
                    easytier_core::proxy::wrapped_transport::WrappedTransportKind::Kcp,
                    easytier_core::proxy::wrapped_transport::WrappedTransportRole::Source,
                ) {
                    tcp_proxy_rpc_services.insert(
                        "kcp_src".to_string(),
                        Arc::new(CoreTcpProxyRpcService::new_wrapped(
                            &self.core_instance,
                            easytier_core::proxy::wrapped_transport::WrappedTransportKind::Kcp,
                            easytier_core::proxy::wrapped_transport::WrappedTransportRole::Source,
                        )),
                    );
                }

                #[cfg(feature = "kcp")]
                if self.core_instance.wrapped_transport_is_started(
                    easytier_core::proxy::wrapped_transport::WrappedTransportKind::Kcp,
                    easytier_core::proxy::wrapped_transport::WrappedTransportRole::Destination,
                ) {
                    tcp_proxy_rpc_services.insert(
                        "kcp_dst".to_string(),
                        Arc::new(CoreTcpProxyRpcService::new_wrapped(
                            &self.core_instance,
                            easytier_core::proxy::wrapped_transport::WrappedTransportKind::Kcp,
                            easytier_core::proxy::wrapped_transport::WrappedTransportRole::Destination,
                        )),
                    );
                }

                #[cfg(feature = "quic")]
                if self.core_instance.wrapped_transport_is_started(
                    easytier_core::proxy::wrapped_transport::WrappedTransportKind::Quic,
                    easytier_core::proxy::wrapped_transport::WrappedTransportRole::Source,
                ) {
                    tcp_proxy_rpc_services.insert(
                        "quic_src".to_string(),
                        Arc::new(CoreTcpProxyRpcService::new_wrapped(
                            &self.core_instance,
                            easytier_core::proxy::wrapped_transport::WrappedTransportKind::Quic,
                            easytier_core::proxy::wrapped_transport::WrappedTransportRole::Source,
                        )),
                    );
                }

                #[cfg(feature = "quic")]
                if self.core_instance.wrapped_transport_is_started(
                    easytier_core::proxy::wrapped_transport::WrappedTransportKind::Quic,
                    easytier_core::proxy::wrapped_transport::WrappedTransportRole::Destination,
                ) {
                    tcp_proxy_rpc_services.insert(
                        "quic_dst".to_string(),
                        Arc::new(CoreTcpProxyRpcService::new_wrapped(
                            &self.core_instance,
                            easytier_core::proxy::wrapped_transport::WrappedTransportKind::Quic,
                            easytier_core::proxy::wrapped_transport::WrappedTransportRole::Destination,
                        )),
                    );
                }

                tcp_proxy_rpc_services
            },
            acl_manage_rpc_service: PeerManagerRpcService::new(
                &self.global_ctx,
                &self.core_instance,
            ),
            port_forward_manage_rpc_service: self.get_port_forward_manager_rpc_service(),
            stats_rpc_service: self.get_stats_rpc_service(),
            config_rpc_service: self.get_config_service(),
            peer_center_rpc_service: Arc::new(self.core_instance.peer_center_rpc_service()),
            credential_manage_rpc_service: PeerManagerRpcService::new(
                &self.global_ctx,
                &self.core_instance,
            ),
        }
    }

    pub fn get_global_ctx(&self) -> ArcGlobalCtx {
        self.global_ctx.clone()
    }

    #[cfg(feature = "tun")]
    pub fn get_nic_ctx(&self) -> ArcNicCtx {
        self.nic_ctx.clone()
    }

    pub fn get_peer_packet_receiver(&self) -> Arc<Mutex<HostPacketReceiver>> {
        self.peer_packet_receiver.clone()
    }

    pub(crate) fn get_core_instance(&self) -> Arc<RuntimeCoreInstance> {
        self.core_instance.clone()
    }

    #[cfg(mobile)]
    pub(crate) async fn setup_nic_ctx_for_mobile(
        nic_ctx: ArcNicCtx,
        global_ctx: ArcGlobalCtx,
        core_instance: Arc<RuntimeCoreInstance>,
        peer_packet_receiver: Arc<Mutex<HostPacketReceiver>>,
        fd: i32,
    ) -> Result<(), anyhow::Error> {
        tracing::info!("setup_nic_ctx_for_mobile, fd: {}", fd);
        Self::clear_nic_ctx(nic_ctx.clone(), peer_packet_receiver.clone()).await;
        if fd <= 0 {
            return Ok(());
        }
        let close_notifier = Arc::new(Notify::new());
        let mut new_nic_ctx = NicCtx::new(
            global_ctx.clone(),
            &core_instance,
            peer_packet_receiver.clone(),
            close_notifier.clone(),
        );
        new_nic_ctx
            .run_for_mobile(fd)
            .await
            .with_context(|| "add ip failed")?;

        let magic_dns_runner = if let Some(ipv4) = global_ctx.get_ipv4() {
            Self::create_magic_dns_runner(global_ctx.clone(), core_instance.clone(), None, ipv4)
        } else {
            None
        };
        Self::use_new_nic_ctx(nic_ctx.clone(), new_nic_ctx, magic_dns_runner).await;
        Ok(())
    }

    pub async fn clear_resources(&mut self) {
        self.config_operation.closing.store(true, Ordering::Release);
        self.config_operation.cancel.cancel();
        let _config_operation = self.config_operation.operation.lock().await;
        #[cfg(feature = "tun")]
        Self::stop_nic_ctx(&self.nic_ctx).await;
        self.core_instance.stop().await;
    }
}

impl Drop for Instance {
    fn drop(&mut self) {
        let core_instance = self.core_instance.clone();
        let config_operation = self.config_operation.clone();
        config_operation.closing.store(true, Ordering::Release);
        config_operation.cancel.cancel();
        #[cfg(feature = "tun")]
        let nic_ctx = self.nic_ctx.clone();
        tokio::spawn(async move {
            let _config_operation = config_operation.operation.lock().await;
            #[cfg(feature = "tun")]
            Self::stop_nic_ctx(&nic_ctx).await;
            core_instance.stop().await;
            drop(core_instance);
        });
    }
}

#[cfg(test)]
mod tests {
    use std::net::SocketAddr;
    #[cfg(all(feature = "tun", feature = "magic-dns"))]
    use std::sync::Arc;

    #[cfg(all(feature = "tun", feature = "magic-dns"))]
    use tokio::sync::Mutex;
    #[cfg(all(feature = "tun", feature = "magic-dns"))]
    use tokio_util::{sync::CancellationToken, task::AbortOnDropHandle};

    #[cfg(all(feature = "tun", feature = "magic-dns"))]
    use crate::instance::instance::{MagicDnsContainer, NicCtxContainer};
    use crate::{
        common::config::ConfigLoader,
        common::global_ctx::tests::get_mock_global_ctx,
        instance::instance::{InstanceConfigPatcher, InstanceRpcServerHook},
        proto::{
            api::config::{
                AclPatch, ConfigPatchAction, InstanceConfigPatch, PortForwardPatch,
                ProxyNetworkPatch, StringPatch, UrlPatch,
            },
            common::{PortForwardConfigPb, SocketType},
            rpc_impl::standalone::RpcServerHook,
        },
    };
    use crate::{common::config::TomlConfigLoader, instance::instance::Instance};
    #[cfg(any(feature = "kcp", feature = "quic"))]
    use easytier_core::proxy::wrapped_transport::{
        WrappedTransportDirections, WrappedTransportEngine as _, WrappedTransportEngineStart,
    };

    fn tcp_whitelist_patch(port: &str) -> InstanceConfigPatch {
        InstanceConfigPatch {
            acl: Some(AclPatch {
                acl: None,
                tcp_whitelist: vec![StringPatch {
                    action: ConfigPatchAction::Add.into(),
                    value: port.to_owned(),
                }],
                udp_whitelist: Vec::new(),
            }),
            ..Default::default()
        }
    }

    #[cfg(all(feature = "tun", feature = "magic-dns"))]
    #[tokio::test]
    async fn stopping_nic_waits_for_dns_runner_cleanup() {
        let cancel = CancellationToken::new();
        let task_cancel = cancel.clone();
        let (cleaned_tx, cleaned_rx) = tokio::sync::oneshot::channel();
        let task = tokio::spawn(async move {
            task_cancel.cancelled().await;
            let _ = cleaned_tx.send(());
        });
        let nic_ctx = Arc::new(Mutex::new(Some(NicCtxContainer {
            nic_ctx: None,
            magic_dns: Some(MagicDnsContainer {
                dns_runner_task: AbortOnDropHandle::new(task),
                dns_runner_cancel_token: cancel,
            }),
        })));

        Instance::stop_nic_ctx(&nic_ctx).await;

        cleaned_rx.await.unwrap();
        assert!(nic_ctx.lock().await.is_none());
    }

    #[tokio::test]
    async fn config_patches_serialize_host_and_core_acl_state() {
        let mut instance = Instance::new(TomlConfigLoader::default());
        let patcher_a = instance.get_config_patcher();
        let patcher_b = instance.get_config_patcher();
        let (result_a, result_b) = tokio::join!(
            patcher_a.apply_patch(tcp_whitelist_patch("80")),
            patcher_b.apply_patch(tcp_whitelist_patch("443")),
        );
        result_a.unwrap();
        result_b.unwrap();

        let mut host_ports = instance.global_ctx.config.get_tcp_whitelist();
        host_ports.sort();
        let mut core_ports = instance.core_instance.acl_whitelist_snapshot().tcp_ports;
        core_ports.sort();
        assert_eq!(host_ports, ["443", "80"]);
        assert_eq!(core_ports, host_ports);
        instance.clear_resources().await;
    }

    #[tokio::test]
    async fn invalid_acl_patch_leaves_host_and_core_unchanged() {
        let mut instance = Instance::new(TomlConfigLoader::default());
        let error = instance
            .get_config_patcher()
            .apply_patch(tcp_whitelist_patch("invalid"))
            .await
            .unwrap_err();
        assert!(error.to_string().contains("Invalid port number"));
        assert!(instance.global_ctx.config.get_tcp_whitelist().is_empty());
        assert!(
            instance
                .core_instance
                .acl_whitelist_snapshot()
                .tcp_ports
                .is_empty()
        );
        instance.clear_resources().await;
    }

    #[tokio::test]
    async fn config_patch_preserves_ordered_partial_commit_semantics() {
        let mut instance = Instance::new(TomlConfigLoader::default());
        let mut patch = tcp_whitelist_patch("invalid");
        patch.port_forwards.push(PortForwardPatch {
            action: ConfigPatchAction::Add.into(),
            cfg: Some(PortForwardConfigPb {
                bind_addr: Some("127.0.0.1:0".parse::<SocketAddr>().unwrap().into()),
                dst_addr: Some("127.0.0.1:1".parse::<SocketAddr>().unwrap().into()),
                socket_type: SocketType::Tcp as i32,
            }),
        });

        let error = instance
            .get_config_patcher()
            .apply_patch(patch)
            .await
            .unwrap_err();
        assert!(error.to_string().contains("Invalid port number"));
        assert_eq!(instance.global_ctx.config.get_port_forwards().len(), 1);
        assert!(instance.global_ctx.config.get_tcp_whitelist().is_empty());
        assert!(
            instance
                .core_instance
                .acl_whitelist_snapshot()
                .tcp_ports
                .is_empty()
        );
        instance.clear_resources().await;
    }

    #[tokio::test]
    async fn config_patch_rejects_live_changes_after_clear() {
        let mut instance = Instance::new(TomlConfigLoader::default());
        let patcher = instance.get_config_patcher();
        instance.clear_resources().await;

        let error = patcher
            .apply_patch(tcp_whitelist_patch("80"))
            .await
            .unwrap_err();
        assert!(error.to_string().contains("instance is closing"));
        assert!(instance.global_ctx.config.get_tcp_whitelist().is_empty());
    }

    #[tokio::test]
    async fn partial_patch_failure_syncs_committed_proxy_policy_to_core() {
        let mut instance = Instance::new(TomlConfigLoader::default());
        let patch = InstanceConfigPatch {
            proxy_networks: vec![ProxyNetworkPatch {
                action: ConfigPatchAction::Add.into(),
                cidr: Some("192.0.2.0/24".parse().unwrap()),
                mapped_cidr: None,
            }],
            connectors: vec![UrlPatch {
                action: ConfigPatchAction::Add.into(),
                url: Some(
                    "unsupported://peer.example:11010"
                        .parse::<url::Url>()
                        .unwrap()
                        .into(),
                ),
            }],
            ..Default::default()
        };

        let error = instance
            .get_config_patcher()
            .apply_patch(patch)
            .await
            .unwrap_err();
        assert!(
            error
                .to_string()
                .contains("unsupported core manual connector URL")
        );
        assert_eq!(instance.global_ctx.config.get_proxy_cidrs().len(), 1);
        assert_eq!(
            instance
                .core_instance
                .node_snapshot()
                .await
                .proxy_networks
                .len(),
            1
        );
        instance.clear_resources().await;
    }

    #[tokio::test]
    async fn drop_synchronously_rejects_retained_config_patcher() {
        let instance = Instance::new(TomlConfigLoader::default());
        let patcher = instance.get_config_patcher();
        drop(instance);

        let error = patcher
            .apply_patch(tcp_whitelist_patch("80"))
            .await
            .unwrap_err();
        assert!(error.to_string().contains("instance is closing"));
    }

    #[cfg(feature = "kcp")]
    #[tokio::test]
    async fn kcp_engine_uses_explicit_source_direction() {
        let instance = Instance::new(TomlConfigLoader::default());
        let kcp = instance.transport_proxy.kcp();
        let (datagrams, _datagram_rx) = tokio::sync::mpsc::channel(16);
        kcp.prepare(WrappedTransportEngineStart {
            directions: WrappedTransportDirections {
                source: true,
                destination: false,
            },
            my_peer_id: instance.core_instance.peer_id(),
            datagrams,
            destination_ingress: None,
        })
        .await
        .unwrap();
        kcp.activate().await.unwrap();

        assert!(kcp.source_is_prepared().await);
        kcp.stop().await;
        assert!(!kcp.source_is_prepared().await);
    }

    #[cfg(feature = "quic")]
    #[tokio::test]
    async fn quic_engine_uses_explicit_source_direction() {
        let instance = Instance::new(TomlConfigLoader::default());
        let quic = instance.transport_proxy.quic();
        let (datagrams, _datagram_rx) = tokio::sync::mpsc::channel(16);
        quic.prepare(WrappedTransportEngineStart {
            directions: WrappedTransportDirections {
                source: true,
                destination: false,
            },
            my_peer_id: instance.core_instance.peer_id(),
            datagrams,
            destination_ingress: None,
        })
        .await
        .unwrap();
        quic.activate().await.unwrap();
        assert!(quic.source_is_prepared().await);
        quic.stop().await;
        assert!(!quic.source_is_prepared().await);
    }

    #[tokio::test]
    async fn core_credential_commands_share_native_storage() {
        let instance = Instance::new(TomlConfigLoader::default());
        let generated = instance
            .core_instance
            .generate_credential(easytier_core::instance::CredentialCreateOptions {
                groups: vec!["guest".to_owned()],
                allow_relay: false,
                allowed_proxy_cidrs: Vec::new(),
                ttl: std::time::Duration::from_secs(3600),
                credential_id: Some("shared-credential".to_owned()),
                reusable: true,
            })
            .unwrap();

        assert_eq!(generated.credential_id, "shared-credential");
        assert_eq!(instance.core_instance.credential_snapshots().len(), 1);
        assert!(
            instance
                .core_instance
                .revoke_credential("shared-credential")
                .unwrap()
        );
        assert!(instance.core_instance.credential_snapshots().is_empty());
    }

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

    #[tokio::test]
    async fn validate_public_ipv6_patch_rejects_non_global_prefix() {
        let global_ctx = get_mock_global_ctx();
        let patch = InstanceConfigPatch {
            ipv6_public_addr_provider: Some(true),
            ipv6_public_addr_prefix: Some("fd00::/64".to_string()),
            ..Default::default()
        };

        let err =
            InstanceConfigPatcher::validate_public_ipv6_patch(&global_ctx, &patch).unwrap_err();

        assert!(
            err.to_string()
                .contains("not a valid global unicast IPv6 prefix")
        );
    }

    #[tokio::test]
    async fn validate_public_ipv6_patch_allows_enabling_auto_with_manual_ipv6() {
        let global_ctx = get_mock_global_ctx();
        global_ctx.set_ipv6(Some("fd00::1/64".parse().unwrap()));

        let patch = InstanceConfigPatch {
            ipv6_public_addr_auto: Some(true),
            ..Default::default()
        };

        assert!(InstanceConfigPatcher::validate_public_ipv6_patch(&global_ctx, &patch).is_ok());
    }

    #[tokio::test]
    async fn validate_public_ipv6_patch_ignores_runtime_auto_ipv6_cache() {
        let global_ctx = get_mock_global_ctx();
        global_ctx.config.set_ipv6_public_addr_auto(true);
        global_ctx.set_ipv6(Some("2001:db8::10/64".parse().unwrap()));

        let patch = InstanceConfigPatch {
            ipv6_public_addr_provider: Some(true),
            ipv6_public_addr_prefix: Some("2001:db8:100::/64".to_string()),
            ..Default::default()
        };

        assert!(InstanceConfigPatcher::validate_public_ipv6_patch(&global_ctx, &patch).is_ok());
    }
}
