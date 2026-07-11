use async_trait::async_trait;
use easytier_core::{
    connectivity::{
        protocol::{ClientProtocolUpgrader, raw},
        transport::ConnectedTransport,
    },
    tunnel::Tunnel,
};

use crate::{common::global_ctx::ArcGlobalCtx, tunnel::tcp_socket::RuntimeTcpSocket};

pub(crate) struct RuntimeClientProtocolUpgrader {
    global_ctx: ArcGlobalCtx,
}

impl RuntimeClientProtocolUpgrader {
    pub(crate) fn new(global_ctx: ArcGlobalCtx) -> Self {
        Self { global_ctx }
    }
}

#[async_trait]
impl ClientProtocolUpgrader<RuntimeTcpSocket> for RuntimeClientProtocolUpgrader {
    async fn upgrade_client(
        &self,
        connected: ConnectedTransport<RuntimeTcpSocket>,
        requested_url: url::Url,
    ) -> anyhow::Result<Box<dyn Tunnel>> {
        match requested_url.scheme() {
            "tcp" | "udp" => Ok(raw::upgrade_connected(connected, requested_url)?),
            #[cfg(feature = "websocket")]
            "ws" | "wss" => match connected {
                ConnectedTransport::Tcp(socket) => {
                    Ok(crate::tunnel::websocket::upgrade_connected(socket, requested_url).await?)
                }
                ConnectedTransport::Udp(_) => {
                    anyhow::bail!("WebSocket protocol requires a TCP transport")
                }
            },
            #[cfg(feature = "wireguard")]
            "wg" => match connected {
                ConnectedTransport::Udp(session) => {
                    use crate::tunnel::wireguard::{WgConfig, upgrade_connected};
                    let identity = self.global_ctx.get_network_identity();
                    let config = WgConfig::new_from_network_identity(
                        &identity.network_name,
                        &identity.network_secret.unwrap_or_default(),
                    );
                    Ok(upgrade_connected(session, requested_url, config).await?)
                }
                ConnectedTransport::Tcp(_) => {
                    anyhow::bail!("WireGuard protocol requires a UDP session")
                }
            },
            #[cfg(feature = "quic")]
            "quic" => match connected {
                ConnectedTransport::Udp(session) => {
                    Ok(crate::tunnel::quic::upgrade_connected(session, requested_url).await?)
                }
                ConnectedTransport::Tcp(_) => {
                    anyhow::bail!("QUIC protocol requires a UDP session")
                }
            },
            #[cfg(feature = "faketcp")]
            "faketcp" => match connected {
                ConnectedTransport::Tcp(socket) => {
                    Ok(crate::tunnel::fake_tcp::upgrade_connected_socket(
                        socket.into_fake_tcp()?,
                        requested_url,
                    )?)
                }
                ConnectedTransport::Udp(_) => {
                    anyhow::bail!("FakeTCP protocol requires a TCP transport")
                }
            },
            scheme => anyhow::bail!("unsupported client protocol upgrader: {scheme}"),
        }
    }
}
