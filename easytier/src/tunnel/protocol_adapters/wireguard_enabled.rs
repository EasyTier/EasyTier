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
    tunnel::wireguard::{WgConfig, upgrade_accepted, upgrade_connected},
};

use super::super::{ClientAdapter, ServerAdapter};

struct WireGuardAdapter {
    config: WgConfig,
}

impl WireGuardAdapter {
    fn new(global_ctx: &ArcGlobalCtx) -> Self {
        let identity = global_ctx.get_network_identity();
        Self {
            config: WgConfig::new_from_network_identity(
                &identity.network_name,
                &identity.network_secret.unwrap_or_default(),
            ),
        }
    }
}

pub(super) fn client_adapter(global_ctx: &ArcGlobalCtx) -> Option<ClientAdapter> {
    Some(Arc::new(WireGuardAdapter::new(global_ctx)))
}

pub(super) fn server_adapter(global_ctx: &ArcGlobalCtx) -> Option<ServerAdapter> {
    Some(Arc::new(WireGuardAdapter::new(global_ctx)))
}

#[async_trait]
impl ClientProtocolUpgrader<RuntimeTcpSocket> for WireGuardAdapter {
    fn supports_scheme(&self, scheme: &str) -> bool {
        scheme == "wg"
    }

    async fn upgrade_client(
        &self,
        connected: ConnectedTransport<RuntimeTcpSocket>,
        requested_url: url::Url,
    ) -> anyhow::Result<Box<dyn Tunnel>> {
        let ConnectedTransport::Udp(session) = connected else {
            anyhow::bail!("WireGuard protocol requires a UDP session");
        };
        Ok(upgrade_connected(session, requested_url, self.config.clone()).await?)
    }
}

#[async_trait]
impl ServerProtocolUpgrader<RuntimeTcpSocket> for WireGuardAdapter {
    fn supports_scheme(&self, scheme: &str) -> bool {
        scheme == "wg"
    }

    async fn upgrade_tcp(
        &self,
        _socket: RuntimeTcpSocket,
        _local_url: url::Url,
    ) -> anyhow::Result<ServerProtocolUpgrade> {
        anyhow::bail!("unsupported native TCP server protocol upgrader: wg")
    }

    async fn upgrade_udp(
        &self,
        session: UdpSession,
        _local_url: url::Url,
        _admission: Option<ServerProtocolAdmission>,
    ) -> anyhow::Result<ServerProtocolUpgrade> {
        Ok(ServerProtocolUpgrade::Tunnel(upgrade_accepted(
            session,
            self.config.clone(),
        )?))
    }

    async fn upgrade_byte_stream(
        &self,
        _socket: RuntimeTcpSocket,
        _local_url: url::Url,
        _remote_url: Option<url::Url>,
    ) -> anyhow::Result<ServerProtocolUpgrade> {
        anyhow::bail!("unsupported native byte-stream server protocol upgrader: wg")
    }
}
