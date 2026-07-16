use std::sync::{Arc, Weak};

use easytier_core::proxy::tcp_proxy_engine::{
    TcpNatEntrySnapshot, TcpNatEntryState as CoreTcpNatEntryState,
};
#[cfg(any(feature = "kcp", feature = "quic"))]
use easytier_core::proxy::wrapped_transport::{WrappedTransportKind, WrappedTransportRole};

use crate::proto::{
    api::instance::{
        ListTcpProxyEntryRequest, ListTcpProxyEntryResponse, TcpProxyEntry, TcpProxyEntryState,
        TcpProxyEntryTransportType, TcpProxyRpc,
    },
    rpc_types::{self, controller::BaseController},
};

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

#[derive(Clone, Copy)]
enum CoreTcpProxySource {
    Tcp,
    #[cfg(any(feature = "kcp", feature = "quic"))]
    Wrapped(WrappedTransportKind, WrappedTransportRole),
}

#[derive(Clone)]
pub struct CoreTcpProxyRpcService {
    core_instance: Weak<crate::instance::composition::NativeCoreInstance>,
    source: CoreTcpProxySource,
}

impl CoreTcpProxyRpcService {
    pub fn new(core_instance: &Arc<crate::instance::composition::NativeCoreInstance>) -> Self {
        Self {
            core_instance: Arc::downgrade(core_instance),
            source: CoreTcpProxySource::Tcp,
        }
    }

    #[cfg(any(feature = "kcp", feature = "quic"))]
    pub fn new_wrapped(
        core_instance: &Arc<crate::instance::composition::NativeCoreInstance>,
        transport: WrappedTransportKind,
        role: WrappedTransportRole,
    ) -> Self {
        Self {
            core_instance: Arc::downgrade(core_instance),
            source: CoreTcpProxySource::Wrapped(transport, role),
        }
    }
}

#[async_trait::async_trait]
impl TcpProxyRpc for CoreTcpProxyRpcService {
    type Controller = BaseController;

    async fn list_tcp_proxy_entry(
        &self,
        _: BaseController,
        _request: ListTcpProxyEntryRequest,
    ) -> std::result::Result<ListTcpProxyEntryResponse, rpc_types::error::Error> {
        let entries = self.core_instance.upgrade().map_or_else(Vec::new, |core| {
            let (snapshots, transport_type) = match self.source {
                CoreTcpProxySource::Tcp => (
                    core.tcp_proxy_entry_snapshots(),
                    TcpProxyEntryTransportType::Tcp,
                ),
                #[cfg(any(feature = "kcp", feature = "quic"))]
                CoreTcpProxySource::Wrapped(WrappedTransportKind::Kcp, role) => (
                    core.wrapped_tcp_proxy_entry_snapshots(WrappedTransportKind::Kcp, role),
                    TcpProxyEntryTransportType::Kcp,
                ),
                #[cfg(any(feature = "kcp", feature = "quic"))]
                CoreTcpProxySource::Wrapped(WrappedTransportKind::Quic, role) => (
                    core.wrapped_tcp_proxy_entry_snapshots(WrappedTransportKind::Quic, role),
                    TcpProxyEntryTransportType::Quic,
                ),
            };
            snapshots
                .into_iter()
                .map(|entry| tcp_entry_snapshot_to_pb(entry, transport_type))
                .collect()
        });
        Ok(ListTcpProxyEntryResponse { entries })
    }
}
