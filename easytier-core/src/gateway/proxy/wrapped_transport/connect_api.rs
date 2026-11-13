use std::net::SocketAddr;

use crate::gateway::proxy::traits::TcpProxyStream;

use super::{
    WrappedTransportKind, WrappedTransportPacketPlane, WrappedTransportPacketState,
    WrappedTransportProxyModule, packet_plane::connect_wrapped_transport_source,
};

impl WrappedTransportPacketPlane {
    fn source_connect_ready(
        &self,
        state: &WrappedTransportPacketState,
        transport: WrappedTransportKind,
    ) -> bool {
        match transport {
            WrappedTransportKind::Kcp => state.kcp_source_connect_ready,
            WrappedTransportKind::Quic => state.quic_source_connect_ready,
        }
    }
}

impl WrappedTransportProxyModule {
    pub(crate) async fn source_connect_ready(&self, transport: WrappedTransportKind) -> bool {
        let state = self.state.lock().await;
        state.active
            && self
                .packet_plane
                .source_connect_ready(&state.packet, transport)
    }

    pub(crate) async fn connect_source(
        &self,
        transport: WrappedTransportKind,
        src: SocketAddr,
        dst: SocketAddr,
    ) -> anyhow::Result<Box<dyn TcpProxyStream>> {
        let engine = {
            let state = self.state.lock().await;
            let ready = state.active
                && self
                    .packet_plane
                    .source_connect_ready(&state.packet, transport);
            if !ready {
                anyhow::bail!("{transport:?} source is not ready");
            }
            match transport {
                WrappedTransportKind::Kcp => self.kcp.clone(),
                WrappedTransportKind::Quic => self.quic.clone(),
            }
        }
        .ok_or_else(|| anyhow::anyhow!("{transport:?} engine is not available"))?;

        connect_wrapped_transport_source(&self.peer_manager, engine, src, dst).await
    }
}
