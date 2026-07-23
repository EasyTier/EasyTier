use std::{num::NonZeroUsize, sync::Arc, time::Duration};

use async_trait::async_trait;
use easytier_core::{
    connectivity::{
        protocol::{
            ClientProtocolUpgrader, ServerProtocolAdmission, ServerProtocolUpgrade,
            ServerProtocolUpgrader,
        },
        transport::ConnectedTransport,
    },
    socket::udp::UdpSession,
    tunnel::Tunnel,
};

use crate::{
    common::global_ctx::ArcGlobalCtx,
    socket::tcp::RuntimeTcpSocket,
    tunnel::websocket::{
        CONNECT_TIMEOUT, SERVER_HANDSHAKE_TIMEOUT, upgrade_accepted, upgrade_connected,
    },
};

use super::super::{ClientAdapter, ServerAdapter};

#[derive(Default)]
struct WebSocketAdapter;

fn supports_scheme(scheme: &str) -> bool {
    matches!(scheme, "ws" | "wss")
}

pub(super) fn client_adapter(_global_ctx: &ArcGlobalCtx) -> Option<ClientAdapter> {
    Some(Arc::new(WebSocketAdapter))
}

pub(super) fn server_adapter(_global_ctx: &ArcGlobalCtx) -> Option<ServerAdapter> {
    Some(Arc::new(WebSocketAdapter))
}

#[async_trait]
impl ClientProtocolUpgrader<RuntimeTcpSocket> for WebSocketAdapter {
    fn supports_scheme(&self, scheme: &str) -> bool {
        supports_scheme(scheme)
    }

    fn connect_timeout(&self, scheme: &str) -> Option<Duration> {
        supports_scheme(scheme).then_some(CONNECT_TIMEOUT)
    }

    async fn upgrade_client(
        &self,
        connected: ConnectedTransport<RuntimeTcpSocket>,
        requested_url: url::Url,
    ) -> anyhow::Result<Box<dyn Tunnel>> {
        let ConnectedTransport::Tcp(socket) = connected else {
            anyhow::bail!("WebSocket protocol requires a TCP transport");
        };
        Ok(upgrade_connected(socket, requested_url).await?)
    }
}

#[async_trait]
impl ServerProtocolUpgrader<RuntimeTcpSocket> for WebSocketAdapter {
    fn supports_scheme(&self, scheme: &str) -> bool {
        supports_scheme(scheme)
    }

    fn max_pending_tcp_upgrades(&self, scheme: &str) -> Option<NonZeroUsize> {
        supports_scheme(scheme).then_some(NonZeroUsize::MIN)
    }

    async fn upgrade_tcp(
        &self,
        socket: RuntimeTcpSocket,
        local_url: url::Url,
    ) -> anyhow::Result<ServerProtocolUpgrade> {
        Ok(ServerProtocolUpgrade::Tunnel(
            tokio::time::timeout(
                SERVER_HANDSHAKE_TIMEOUT,
                upgrade_accepted(socket, local_url),
            )
            .await??,
        ))
    }

    async fn upgrade_udp(
        &self,
        _session: UdpSession,
        _local_url: url::Url,
        _admission: Option<ServerProtocolAdmission>,
    ) -> anyhow::Result<ServerProtocolUpgrade> {
        anyhow::bail!("WebSocket protocol requires a TCP transport")
    }

    async fn upgrade_byte_stream(
        &self,
        _socket: RuntimeTcpSocket,
        _local_url: url::Url,
        _remote_url: Option<url::Url>,
    ) -> anyhow::Result<ServerProtocolUpgrade> {
        anyhow::bail!("WebSocket protocol requires a TCP transport")
    }
}
