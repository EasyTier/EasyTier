use crate::gateway::proxy::tcp_proxy_engine::TcpNatEntrySnapshot;

use super::{WrappedTransportKind, WrappedTransportProxyModule};

impl WrappedTransportProxyModule {
    pub(crate) fn source_entry_snapshots(
        &self,
        transport: WrappedTransportKind,
    ) -> Vec<TcpNatEntrySnapshot> {
        match transport {
            WrappedTransportKind::Kcp => self.packet_plane.kcp_source.as_ref(),
            WrappedTransportKind::Quic => self.packet_plane.quic_source.as_ref(),
        }
        .map_or_else(Vec::new, |source| source.entry_snapshots())
    }

    pub(crate) fn source_is_started(&self, transport: WrappedTransportKind) -> bool {
        match transport {
            WrappedTransportKind::Kcp => self.packet_plane.kcp_source.as_ref(),
            WrappedTransportKind::Quic => self.packet_plane.quic_source.as_ref(),
        }
        .is_some_and(|source| source.is_started())
    }

    pub(crate) fn destination_entry_snapshots(
        &self,
        transport: WrappedTransportKind,
    ) -> Vec<TcpNatEntrySnapshot> {
        self.packet_plane
            .destination
            .as_ref()
            .map_or_else(Vec::new, |destination| {
                destination.entry_snapshots(transport)
            })
    }

    pub(crate) fn destination_is_started(&self, transport: WrappedTransportKind) -> bool {
        self.packet_plane
            .destination
            .as_ref()
            .is_some_and(|destination| destination.is_started(transport))
    }
}
