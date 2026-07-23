use std::{marker::PhantomData, sync::Arc};

use easytier_proto::{
    api::instance::{
        ListTcpProxyEntryRequest, ListTcpProxyEntryResponse, TcpProxyEntry, TcpProxyEntryState,
        TcpProxyEntryTransportType, TcpProxyRpc,
    },
    rpc_types::{self, controller::BaseController},
};

use crate::{
    gateway::proxy::{
        tcp_proxy_engine::{TcpNatEntrySnapshot, TcpNatEntryState as CoreTcpNatEntryState},
        wrapped_transport::{WrappedTransportKind, WrappedTransportRole},
    },
    instance::{
        CoreInstance, CoreInstanceHost,
        manager::{InstanceFactory, InstanceManager},
    },
};

use super::super::resolve_instance;

#[derive(Clone, Copy)]
enum TcpProxySource {
    Tcp,
    Wrapped(WrappedTransportKind, WrappedTransportRole),
}

pub(crate) struct TcpProxyManagementRpc<F, H>
where
    F: InstanceFactory,
{
    manager: Arc<InstanceManager<F>>,
    source: TcpProxySource,
    host: PhantomData<fn() -> H>,
}

impl<F, H> Clone for TcpProxyManagementRpc<F, H>
where
    F: InstanceFactory,
{
    fn clone(&self) -> Self {
        Self {
            manager: self.manager.clone(),
            source: self.source,
            host: PhantomData,
        }
    }
}

impl<F, H> TcpProxyManagementRpc<F, H>
where
    F: InstanceFactory<Instance = CoreInstance<H>>,
    H: CoreInstanceHost,
{
    pub(crate) fn tcp(manager: Arc<InstanceManager<F>>) -> Self {
        Self {
            manager,
            source: TcpProxySource::Tcp,
            host: PhantomData,
        }
    }

    pub(crate) fn wrapped(
        manager: Arc<InstanceManager<F>>,
        transport: WrappedTransportKind,
        role: WrappedTransportRole,
    ) -> Self {
        Self {
            manager,
            source: TcpProxySource::Wrapped(transport, role),
            host: PhantomData,
        }
    }
}

fn tcp_entry_snapshot_to_api(
    entry: TcpNatEntrySnapshot,
    transport_type: TcpProxyEntryTransportType,
) -> TcpProxyEntry {
    TcpProxyEntry {
        src: Some(entry.src.into()),
        dst: Some(entry.dst.into()),
        start_time: entry.start_time,
        state: match entry.state {
            CoreTcpNatEntryState::SynReceived => TcpProxyEntryState::SynReceived,
            CoreTcpNatEntryState::ConnectingDst => TcpProxyEntryState::ConnectingDst,
            CoreTcpNatEntryState::Connected => TcpProxyEntryState::Connected,
            CoreTcpNatEntryState::ClosingSrc => TcpProxyEntryState::ClosingSrc,
            CoreTcpNatEntryState::ClosingDst => TcpProxyEntryState::ClosingDst,
            CoreTcpNatEntryState::Closed => TcpProxyEntryState::Closed,
        }
        .into(),
        transport_type: transport_type.into(),
    }
}

#[async_trait::async_trait]
impl<F, H> TcpProxyRpc for TcpProxyManagementRpc<F, H>
where
    F: InstanceFactory<Instance = CoreInstance<H>>,
    H: CoreInstanceHost,
{
    type Controller = BaseController;

    async fn list_tcp_proxy_entry(
        &self,
        _: BaseController,
        request: ListTcpProxyEntryRequest,
    ) -> rpc_types::error::Result<ListTcpProxyEntryResponse> {
        let instance = resolve_instance(&self.manager, request.instance.as_ref())?;
        let (snapshots, transport_type) = match self.source {
            TcpProxySource::Tcp => (
                instance.tcp_proxy_entry_snapshots(),
                TcpProxyEntryTransportType::Tcp,
            ),
            TcpProxySource::Wrapped(transport, role) => {
                if !instance.wrapped_transport_is_started(transport, role) {
                    return Err(anyhow::anyhow!("wrapped TCP proxy is not available").into());
                }
                let transport_type = match transport {
                    WrappedTransportKind::Kcp => TcpProxyEntryTransportType::Kcp,
                    WrappedTransportKind::Quic => TcpProxyEntryTransportType::Quic,
                };
                (
                    instance.wrapped_tcp_proxy_entry_snapshots(transport, role),
                    transport_type,
                )
            }
        };
        Ok(ListTcpProxyEntryResponse {
            entries: snapshots
                .into_iter()
                .map(|entry| tcp_entry_snapshot_to_api(entry, transport_type))
                .collect(),
        })
    }
}
