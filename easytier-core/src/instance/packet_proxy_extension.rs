use crate::gateway::proxy::{
    tcp_proxy_engine::TcpNatEntrySnapshot,
    wrapped_transport::{WrappedTransportKind, WrappedTransportRole},
};

use super::{CoreInstance, CoreInstanceHost};

impl<H> CoreInstance<H>
where
    H: CoreInstanceHost,
{
    pub fn tcp_proxy_entry_snapshots(&self) -> Vec<TcpNatEntrySnapshot> {
        self.packet_proxy.tcp_entry_snapshots()
    }

    pub fn wrapped_tcp_proxy_entry_snapshots(
        &self,
        transport: WrappedTransportKind,
        role: WrappedTransportRole,
    ) -> Vec<TcpNatEntrySnapshot> {
        self.wrapped_transport
            .proxy()
            .map_or_else(Vec::new, |proxy| match role {
                WrappedTransportRole::Source => proxy.source_entry_snapshots(transport),
                WrappedTransportRole::Destination => proxy.destination_entry_snapshots(transport),
            })
    }

    pub fn wrapped_transport_is_started(
        &self,
        transport: WrappedTransportKind,
        role: WrappedTransportRole,
    ) -> bool {
        self.wrapped_transport
            .proxy()
            .is_some_and(|proxy| match role {
                WrappedTransportRole::Source => proxy.source_is_started(transport),
                WrappedTransportRole::Destination => proxy.destination_is_started(transport),
            })
    }
}
