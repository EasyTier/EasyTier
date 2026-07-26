use std::sync::Arc;

use crate::{
    config::runtime::CoreRuntimeConfigStore, connectivity::direct::DirectConnectorHost,
    connectivity::hole_punch::tcp::TcpHolePunchHost, gateway::proxy::cidr_table::ProxyCidrTable,
    listener::RunningListenerRegistry, peers::peer_manager::PeerManagerCore,
    process_runtime::ProtectedTcpPortRegistry, socket::SocketContext,
};

use super::{
    WrappedTransportDatagram, WrappedTransportDirections, WrappedTransportEngine,
    WrappedTransportEngineStart, WrappedTransportKind,
};

#[derive(Default)]
pub(super) struct WrappedTransportPacketState;

#[derive(Default)]
pub(super) struct WrappedTransportPacketPlane;

impl WrappedTransportPacketPlane {
    pub(super) fn has_partial_start(&self, _state: &WrappedTransportPacketState) -> bool {
        false
    }

    pub(super) fn clear_connect_ready(&self, _state: &mut WrappedTransportPacketState) {}

    pub(super) async fn stop_source(
        &self,
        _state: &mut WrappedTransportPacketState,
        _transport: WrappedTransportKind,
    ) {
    }

    pub(super) async fn stop_destination(&self, _state: &mut WrappedTransportPacketState) {}

    pub(super) async fn start_destinations(
        &self,
        _state: &mut WrappedTransportPacketState,
        _kcp_directions: WrappedTransportDirections,
        _quic_directions: WrappedTransportDirections,
        _kcp_available: bool,
        _quic_available: bool,
    ) -> anyhow::Result<()> {
        Ok(())
    }

    pub(super) fn engine_start(
        &self,
        _state: &WrappedTransportPacketState,
        _transport: WrappedTransportKind,
        directions: WrappedTransportDirections,
        my_peer_id: u32,
        datagrams: tokio::sync::mpsc::Sender<WrappedTransportDatagram>,
    ) -> WrappedTransportEngineStart {
        WrappedTransportEngineStart {
            directions,
            my_peer_id,
            datagrams,
        }
    }

    pub(super) async fn start_source(
        &self,
        _state: &mut WrappedTransportPacketState,
        _transport: WrappedTransportKind,
        _directions: WrappedTransportDirections,
    ) -> anyhow::Result<()> {
        Ok(())
    }

    pub(super) fn mark_source_connect_ready(
        &self,
        _state: &mut WrappedTransportPacketState,
        _transport: WrappedTransportKind,
        _directions: WrappedTransportDirections,
    ) {
    }

    #[allow(clippy::too_many_arguments)]
    pub(super) fn new<H>(
        _peer_manager: Arc<PeerManagerCore>,
        _runtime_config: CoreRuntimeConfigStore,
        _kcp: &Option<Arc<dyn WrappedTransportEngine>>,
        _quic: &Option<Arc<dyn WrappedTransportEngine>>,
        _host: Arc<H>,
        _protected_tcp_ports: Arc<ProtectedTcpPortRegistry>,
        _running_listeners: Arc<RunningListenerRegistry>,
        _cidr_table: Arc<ProxyCidrTable>,
        _socket_context: SocketContext,
    ) -> Self
    where
        H: DirectConnectorHost + TcpHolePunchHost,
    {
        Self
    }
}
