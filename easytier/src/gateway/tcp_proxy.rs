use cidr::Ipv4Inet;
use easytier_core::instance::ProxyService;
use easytier_core::proxy::runtime::{
    ProxyRuntimeInfo, ProxyRuntimeSnapshot, TcpProxyConnectContext, TcpProxyDestinationConnector,
    TcpProxyRuntime,
};
use easytier_core::proxy::tcp_proxy_engine::{
    TcpNatEntrySnapshot, TcpNatEntryState as CoreTcpNatEntryState, TcpProxyMode, TcpProxyNicContext,
};
use easytier_core::proxy::tcp_proxy_service::TcpProxyService;
use easytier_core::proxy::tcp_socket_connector::TcpSocketProxyConnector;
use easytier_core::stats_manager::{LabelSet, LabelType, MetricName, StatsManager};
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::{
    Arc, Weak,
    atomic::{AtomicBool, Ordering},
};

use crate::common::error::Result;
use crate::common::global_ctx::{ArcGlobalCtx, GlobalCtx};
use crate::connector::{
    core_instance::runtime_socket_context,
    runtime::{RuntimeConnectorHost, runtime_connector_host},
};
use crate::peers::peer_manager::PeerManager;
use crate::proto::api::instance::{
    ListTcpProxyEntryRequest, ListTcpProxyEntryResponse, TcpProxyEntry, TcpProxyEntryState,
    TcpProxyEntryTransportType, TcpProxyRpc,
};
use crate::proto::rpc_types;
use crate::proto::rpc_types::controller::BaseController;
use crate::tunnel::packet_def::ZCPacket;

use super::CidrSet;

pub type NatDstTcpConnector = TcpSocketProxyConnector<RuntimeConnectorHost>;

#[derive(Clone)]
struct RuntimeTcpProxyAdapter {
    global_ctx: Arc<GlobalCtx>,
    stats_manager: Arc<StatsManager>,
    transport_type: TcpProxyEntryTransportType,
    smoltcp_enabled: Arc<AtomicBool>,
}

impl RuntimeTcpProxyAdapter {
    fn new(
        global_ctx: ArcGlobalCtx,
        stats_manager: Arc<StatsManager>,
        transport_type: TcpProxyEntryTransportType,
    ) -> Self {
        let smoltcp_enabled = Self::compute_smoltcp_enabled(&global_ctx);
        Self {
            global_ctx,
            stats_manager,
            transport_type,
            smoltcp_enabled: Arc::new(AtomicBool::new(smoltcp_enabled)),
        }
    }

    fn compute_smoltcp_enabled(_global_ctx: &ArcGlobalCtx) -> bool {
        #[cfg(feature = "smoltcp")]
        {
            _global_ctx.get_flags().use_smoltcp
                || _global_ctx.no_tun()
                || cfg!(any(
                    target_os = "android",
                    target_os = "ios",
                    all(target_os = "macos", feature = "macos-ne"),
                    target_env = "ohos"
                ))
        }

        #[cfg(not(feature = "smoltcp"))]
        {
            false
        }
    }

    fn latch_smoltcp_enabled(&self) {
        self.smoltcp_enabled.store(
            Self::compute_smoltcp_enabled(&self.global_ctx),
            Ordering::Relaxed,
        );
    }

    fn smoltcp_enabled(&self) -> bool {
        self.smoltcp_enabled.load(Ordering::Relaxed)
    }

    fn local_inet(&self) -> Option<Ipv4Inet> {
        if self.smoltcp_enabled() {
            Some(Ipv4Inet::new(Ipv4Addr::new(192, 88, 99, 254), 24).unwrap())
        } else {
            self.global_ctx.get_ipv4().as_ref().cloned()
        }
    }
}

impl ProxyRuntimeInfo for RuntimeTcpProxyAdapter {
    fn proxy_runtime_snapshot(&self) -> ProxyRuntimeSnapshot {
        let local_inet = self.local_inet();
        ProxyRuntimeSnapshot {
            local_inet,
            virtual_ipv4: self.global_ctx.get_ipv4().map(|inet| inet.address()),
            no_tun: self.global_ctx.no_tun(),
            enable_exit_node: self.global_ctx.enable_exit_node(),
            smoltcp_enabled: self.smoltcp_enabled(),
            latency_first: self.global_ctx.latency_first(),
        }
    }

    fn is_ip_local_virtual_ip(&self, ip: &IpAddr) -> bool {
        self.global_ctx.is_ip_local_virtual_ip(ip)
    }
}

impl TcpProxyRuntime for RuntimeTcpProxyAdapter {
    fn should_deny_tcp_proxy(&self, dst: SocketAddr) -> bool {
        self.global_ctx.should_deny_proxy(&dst, false)
    }

    fn record_tcp_proxy_connect(&self, ctx: TcpProxyConnectContext, socket_dst: SocketAddr) {
        self.stats_manager
            .get_counter(
                MetricName::TcpProxyConnect,
                LabelSet::new()
                    .with_label_type(LabelType::Protocol(
                        self.transport_type.as_str_name().to_string(),
                    ))
                    .with_label_type(LabelType::DstIp(socket_dst.ip().to_string()))
                    .with_label_type(LabelType::MappedDstIp(ctx.mapped_dst.ip().to_string())),
            )
            .inc();
    }
}

fn transport_type_for_mode(mode: TcpProxyMode) -> TcpProxyEntryTransportType {
    match mode {
        TcpProxyMode::Tcp => TcpProxyEntryTransportType::Tcp,
        TcpProxyMode::KcpSrc => TcpProxyEntryTransportType::Kcp,
        TcpProxyMode::QuicSrc => TcpProxyEntryTransportType::Quic,
    }
}

pub struct TcpProxy<C: TcpProxyDestinationConnector> {
    global_ctx: Arc<GlobalCtx>,
    peer_manager: Weak<PeerManager>,
    runtime: Arc<RuntimeTcpProxyAdapter>,
    service: Arc<TcpProxyService<RuntimeTcpProxyAdapter, RuntimeConnectorHost, C>>,
    transport_type: TcpProxyEntryTransportType,
}

impl<C: TcpProxyDestinationConnector> TcpProxy<C> {
    pub fn new(peer_manager: Arc<PeerManager>, connector: C, cidr_set: Arc<CidrSet>) -> Arc<Self> {
        let global_ctx = peer_manager.get_global_ctx();
        let transport_type = transport_type_for_mode(connector.proxy_mode());
        let runtime = Arc::new(RuntimeTcpProxyAdapter::new(
            global_ctx.clone(),
            peer_manager.stats_manager(),
            transport_type,
        ));
        let service = TcpProxyService::new_with_socket_context(
            peer_manager.core(),
            runtime.clone(),
            runtime_connector_host(global_ctx.clone()),
            Arc::new(connector),
            cidr_set.table(),
            runtime_socket_context(&global_ctx),
        );

        Arc::new(Self {
            global_ctx,
            peer_manager: Arc::downgrade(&peer_manager),
            runtime,
            service,
            transport_type,
        })
    }

    pub fn get_peer_manager(&self) -> Option<Arc<PeerManager>> {
        self.peer_manager.upgrade()
    }

    pub async fn start(self: &Arc<Self>, add_pipeline: bool) -> Result<()> {
        self.runtime.latch_smoltcp_enabled();
        self.service
            .start(add_pipeline)
            .await
            .map_err(|err| crate::common::error::Error::from(anyhow::Error::new(err)))?;
        Ok(())
    }

    pub fn stop(&self) {
        self.service.stop();
    }

    pub async fn register_peer_pipeline(self: &Arc<Self>) {
        self.service.register_peer_pipeline().await;
    }

    pub fn get_local_port(&self) -> u16 {
        self.service.engine().local_port()
    }

    pub fn get_my_peer_id(&self) -> u32 {
        self.peer_manager
            .upgrade()
            .map(|pm| pm.my_peer_id())
            .unwrap_or_default()
    }

    pub fn get_local_ip(&self) -> Option<Ipv4Addr> {
        self.get_local_inet().map(|inet| inet.address())
    }

    pub fn get_local_inet(&self) -> Option<Ipv4Inet> {
        self.runtime.local_inet()
    }

    pub fn get_global_ctx(&self) -> &ArcGlobalCtx {
        &self.global_ctx
    }

    pub fn is_smoltcp_enabled(&self) -> bool {
        self.runtime.smoltcp_enabled()
    }

    pub fn is_tcp_proxy_connection(&self, src: SocketAddr) -> bool {
        self.service.engine().is_tcp_proxy_connection(src)
    }

    pub async fn try_process_packet_from_nic(&self, zc_packet: &mut ZCPacket) -> bool {
        let snapshot = self.runtime.proxy_runtime_snapshot();
        self.service.engine().try_process_packet_from_nic(
            zc_packet,
            TcpProxyNicContext {
                local_inet: snapshot.local_inet,
                local_port: self.get_local_port(),
                my_peer_id: self.get_my_peer_id(),
                smoltcp_enabled: snapshot.smoltcp_enabled,
            },
        )
    }

    pub fn list_proxy_entries(&self) -> Vec<TcpProxyEntry> {
        let transport_type = self.transport_type;
        self.service
            .engine()
            .list_entries()
            .into_iter()
            .map(|entry| tcp_entry_snapshot_to_pb(entry, transport_type))
            .collect()
    }

    pub fn get_transport_type(&self) -> TcpProxyEntryTransportType {
        self.transport_type
    }
}

impl<C: TcpProxyDestinationConnector> Drop for TcpProxy<C> {
    fn drop(&mut self) {
        self.stop();
    }
}

#[async_trait::async_trait]
impl<C: TcpProxyDestinationConnector> ProxyService for TcpProxy<C> {
    async fn start(&self) -> anyhow::Result<()> {
        self.runtime.latch_smoltcp_enabled();
        self.service.start(true).await.map_err(anyhow::Error::new)
    }

    async fn stop(&self) {
        TcpProxy::stop(self);
    }
}

fn tcp_entry_snapshot_to_pb(
    entry: TcpNatEntrySnapshot,
    transport_type: TcpProxyEntryTransportType,
) -> TcpProxyEntry {
    TcpProxyEntry {
        src: Some(entry.src.into()),
        dst: Some(entry.dst.into()),
        start_time: entry.start_time,
        state: tcp_entry_state_to_pb(entry.state).into(),
        transport_type: transport_type.into(),
    }
}

fn tcp_entry_state_to_pb(state: CoreTcpNatEntryState) -> TcpProxyEntryState {
    match state {
        CoreTcpNatEntryState::SynReceived => TcpProxyEntryState::SynReceived,
        CoreTcpNatEntryState::ConnectingDst => TcpProxyEntryState::ConnectingDst,
        CoreTcpNatEntryState::Connected => TcpProxyEntryState::Connected,
        CoreTcpNatEntryState::ClosingSrc => TcpProxyEntryState::ClosingSrc,
        CoreTcpNatEntryState::ClosingDst => TcpProxyEntryState::ClosingDst,
        CoreTcpNatEntryState::Closed => TcpProxyEntryState::Closed,
    }
}

#[derive(Clone)]
pub struct TcpProxyRpcService<C: TcpProxyDestinationConnector> {
    tcp_proxy: Weak<TcpProxy<C>>,
}

#[async_trait::async_trait]
impl<C: TcpProxyDestinationConnector> TcpProxyRpc for TcpProxyRpcService<C> {
    type Controller = BaseController;

    async fn list_tcp_proxy_entry(
        &self,
        _: BaseController,
        _request: ListTcpProxyEntryRequest,
    ) -> std::result::Result<ListTcpProxyEntryResponse, rpc_types::error::Error> {
        let mut reply = ListTcpProxyEntryResponse::default();
        if let Some(tcp_proxy) = self.tcp_proxy.upgrade() {
            reply.entries = tcp_proxy.list_proxy_entries();
        }
        Ok(reply)
    }
}

impl<C: TcpProxyDestinationConnector> TcpProxyRpcService<C> {
    pub fn new(tcp_proxy: Arc<TcpProxy<C>>) -> Self {
        Self {
            tcp_proxy: Arc::downgrade(&tcp_proxy),
        }
    }
}
