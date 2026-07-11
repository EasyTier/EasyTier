use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::{
    Arc, Weak,
    atomic::{AtomicBool, Ordering},
};
use std::time::Duration;

use anyhow::Context;
use cidr::Ipv4Inet;
use easytier_core::instance::ProxyService;
use easytier_core::proxy::runtime::{
    ProxyRuntimeError, ProxyRuntimeInfo, ProxyRuntimeSnapshot, TcpProxyConnectContext,
    TcpProxyDstStream, TcpProxyRuntime,
};
use easytier_core::proxy::tcp_proxy_engine::{
    TcpNatEntrySnapshot, TcpNatEntryState as CoreTcpNatEntryState, TcpProxyMode, TcpProxyNicContext,
};
use easytier_core::proxy::tcp_proxy_service::TcpProxyService;
use easytier_core::socket::tcp::{TcpConnectOptions, VirtualTcpSocketFactory};
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::time::timeout;

use crate::common::error::Result;
use crate::common::global_ctx::{ArcGlobalCtx, GlobalCtx};
use crate::common::stats_manager::{LabelSet, LabelType, MetricName};
use crate::connector::runtime::RuntimeConnectorHost;
use crate::peers::peer_manager::PeerManager;
use crate::proto::api::instance::{
    ListTcpProxyEntryRequest, ListTcpProxyEntryResponse, TcpProxyEntry, TcpProxyEntryState,
    TcpProxyEntryTransportType, TcpProxyRpc,
};
use crate::proto::rpc_types;
use crate::proto::rpc_types::controller::BaseController;
use crate::tunnel::packet_def::ZCPacket;
use crate::tunnel::tcp_socket::RuntimeTcpSocket;

use super::CidrSet;

#[async_trait::async_trait]
pub(crate) trait NatDstConnector: Send + Sync + Clone + 'static {
    type DstStream: AsyncRead + AsyncWrite + Unpin + Send + 'static;

    async fn connect(&self, src: SocketAddr, dst: SocketAddr) -> anyhow::Result<Self::DstStream>;
    fn proxy_mode(&self) -> TcpProxyMode;
    fn transport_type(&self) -> TcpProxyEntryTransportType;
}

#[derive(Clone)]
pub struct NatDstTcpConnector {
    host: Arc<RuntimeConnectorHost>,
}

impl NatDstTcpConnector {
    pub fn new(global_ctx: ArcGlobalCtx) -> Self {
        Self {
            host: Arc::new(RuntimeConnectorHost::new(global_ctx)),
        }
    }
}

#[async_trait::async_trait]
impl NatDstConnector for NatDstTcpConnector {
    type DstStream = RuntimeTcpSocket;

    async fn connect(
        &self,
        _src: SocketAddr,
        nat_dst: SocketAddr,
    ) -> anyhow::Result<Self::DstStream> {
        timeout(
            Duration::from_secs(10),
            self.host.connect_tcp(TcpConnectOptions::proxy_nat(nat_dst)),
        )
        .await?
        .with_context(|| format!("connect to nat dst failed: {:?}", nat_dst))
    }

    fn proxy_mode(&self) -> TcpProxyMode {
        TcpProxyMode::Tcp
    }

    fn transport_type(&self) -> TcpProxyEntryTransportType {
        TcpProxyEntryTransportType::Tcp
    }
}

#[derive(Clone)]
struct RuntimeTcpProxyAdapter<C: NatDstConnector> {
    global_ctx: Arc<GlobalCtx>,
    connector: C,
    smoltcp_enabled: Arc<AtomicBool>,
}

impl<C: NatDstConnector> RuntimeTcpProxyAdapter<C> {
    fn new(global_ctx: ArcGlobalCtx, connector: C) -> Self {
        let smoltcp_enabled = Self::compute_smoltcp_enabled(&global_ctx);
        Self {
            global_ctx,
            connector,
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

impl<C: NatDstConnector> ProxyRuntimeInfo for RuntimeTcpProxyAdapter<C> {
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

#[async_trait::async_trait]
impl<C: NatDstConnector> TcpProxyRuntime for RuntimeTcpProxyAdapter<C> {
    fn should_deny_tcp_proxy(&self, dst: SocketAddr) -> bool {
        self.global_ctx.should_deny_proxy(&dst, false)
    }

    async fn connect_dst(
        &self,
        ctx: TcpProxyConnectContext,
    ) -> std::result::Result<Box<dyn TcpProxyDstStream>, ProxyRuntimeError> {
        let nat_dst = if self.global_ctx.is_ip_local_virtual_ip(&ctx.real_dst.ip()) {
            format!("127.0.0.1:{}", ctx.real_dst.port())
                .parse()
                .unwrap()
        } else {
            ctx.real_dst
        };

        self.global_ctx
            .stats_manager()
            .get_counter(
                MetricName::TcpProxyConnect,
                LabelSet::new()
                    .with_label_type(LabelType::Protocol(
                        self.connector.transport_type().as_str_name().to_string(),
                    ))
                    .with_label_type(LabelType::DstIp(nat_dst.ip().to_string()))
                    .with_label_type(LabelType::MappedDstIp(ctx.mapped_dst.ip().to_string())),
            )
            .inc();

        let stream = self.connector.connect(ctx.src, nat_dst).await?;

        Ok(Box::new(stream))
    }
}

pub struct TcpProxy<C: NatDstConnector> {
    global_ctx: Arc<GlobalCtx>,
    peer_manager: Weak<PeerManager>,
    cidr_set: CidrSet,
    runtime: Arc<RuntimeTcpProxyAdapter<C>>,
    service: Arc<TcpProxyService<RuntimeTcpProxyAdapter<C>, RuntimeConnectorHost>>,
    connector: C,
}

impl<C: NatDstConnector> TcpProxy<C> {
    pub fn new(peer_manager: Arc<PeerManager>, connector: C) -> Arc<Self> {
        let global_ctx = peer_manager.get_global_ctx();
        let cidr_set = CidrSet::new_without_updater(global_ctx.clone());
        let runtime = Arc::new(RuntimeTcpProxyAdapter::new(
            global_ctx.clone(),
            connector.clone(),
        ));
        let service = TcpProxyService::new(
            peer_manager.core(),
            runtime.clone(),
            Arc::new(RuntimeConnectorHost::new(global_ctx.clone())),
            cidr_set.table(),
            connector.proxy_mode(),
        );

        Arc::new(Self {
            global_ctx,
            peer_manager: Arc::downgrade(&peer_manager),
            cidr_set,
            runtime,
            service,
            connector,
        })
    }

    pub fn get_peer_manager(&self) -> Option<Arc<PeerManager>> {
        self.peer_manager.upgrade()
    }

    pub async fn start(self: &Arc<Self>, add_pipeline: bool) -> Result<()> {
        self.cidr_set.start_updater();
        self.runtime.latch_smoltcp_enabled();
        self.service
            .start(add_pipeline)
            .await
            .map_err(|err| crate::common::error::Error::from(anyhow::Error::new(err)))?;
        Ok(())
    }

    pub fn stop(&self) {
        self.service.stop();
        self.cidr_set.stop_updater();
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
        let transport_type = self.connector.transport_type();
        self.service
            .engine()
            .list_entries()
            .into_iter()
            .map(|entry| tcp_entry_snapshot_to_pb(entry, transport_type))
            .collect()
    }

    pub fn get_transport_type(&self) -> TcpProxyEntryTransportType {
        self.connector.transport_type()
    }
}

impl<C: NatDstConnector> Drop for TcpProxy<C> {
    fn drop(&mut self) {
        self.stop();
    }
}

#[async_trait::async_trait]
impl<C: NatDstConnector> ProxyService for TcpProxy<C> {
    async fn start(&self) -> anyhow::Result<()> {
        self.cidr_set.start_updater();
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
pub struct TcpProxyRpcService<C: NatDstConnector> {
    tcp_proxy: Weak<TcpProxy<C>>,
}

#[async_trait::async_trait]
impl<C: NatDstConnector> TcpProxyRpc for TcpProxyRpcService<C> {
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

impl<C: NatDstConnector> TcpProxyRpcService<C> {
    pub fn new(tcp_proxy: Arc<TcpProxy<C>>) -> Self {
        Self {
            tcp_proxy: Arc::downgrade(&tcp_proxy),
        }
    }
}
