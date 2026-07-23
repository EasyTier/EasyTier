use std::sync::Arc;

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
    tunnel::quic::{QuicAcceptedSession, upgrade_connected},
};

use super::super::{ClientAdapter, ServerAdapter};

#[derive(Default)]
struct QuicAdapter;

pub(super) fn client_adapter(_global_ctx: &ArcGlobalCtx) -> Option<ClientAdapter> {
    Some(Arc::new(QuicAdapter))
}

pub(super) fn server_adapter(_global_ctx: &ArcGlobalCtx) -> Option<ServerAdapter> {
    Some(Arc::new(QuicAdapter))
}

#[async_trait]
impl ClientProtocolUpgrader<RuntimeTcpSocket> for QuicAdapter {
    fn supports_scheme(&self, scheme: &str) -> bool {
        scheme == "quic"
    }

    async fn upgrade_client(
        &self,
        connected: ConnectedTransport<RuntimeTcpSocket>,
        requested_url: url::Url,
    ) -> anyhow::Result<Box<dyn Tunnel>> {
        let ConnectedTransport::Udp(session) = connected else {
            anyhow::bail!("QUIC protocol requires a UDP session");
        };
        Ok(upgrade_connected(session, requested_url).await?)
    }
}

#[async_trait]
impl ServerProtocolUpgrader<RuntimeTcpSocket> for QuicAdapter {
    fn supports_scheme(&self, scheme: &str) -> bool {
        scheme == "quic"
    }

    async fn upgrade_tcp(
        &self,
        _socket: RuntimeTcpSocket,
        _local_url: url::Url,
    ) -> anyhow::Result<ServerProtocolUpgrade> {
        anyhow::bail!("unsupported native TCP server protocol upgrader: quic")
    }

    async fn upgrade_udp(
        &self,
        session: UdpSession,
        local_url: url::Url,
        admission: Option<ServerProtocolAdmission>,
    ) -> anyhow::Result<ServerProtocolUpgrade> {
        let admission =
            admission.ok_or_else(|| anyhow::anyhow!("QUIC server admission permit is missing"))?;
        Ok(ServerProtocolUpgrade::Acceptor(Box::new(
            QuicAcceptedSession::new(session, local_url, admission)?,
        )))
    }

    async fn upgrade_byte_stream(
        &self,
        _socket: RuntimeTcpSocket,
        _local_url: url::Url,
        _remote_url: Option<url::Url>,
    ) -> anyhow::Result<ServerProtocolUpgrade> {
        anyhow::bail!("unsupported native byte-stream server protocol upgrader: quic")
    }
}
