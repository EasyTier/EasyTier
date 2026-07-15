use std::sync::Arc;

use async_trait::async_trait;
use easytier_core::{
    connectivity::{
        protocol::wireguard::WgConfig,
        protocol::{
            ClientProtocolUpgrader, CoreClientProtocolConfig, CoreClientProtocolUpgrader,
            CoreServerProtocolConfig, CoreServerProtocolUpgrader, ServerProtocolAdmission,
            ServerProtocolUpgrade, ServerProtocolUpgrader,
        },
        transport::ConnectedTransport,
    },
    socket::udp::UdpSession,
    tunnel::Tunnel,
};

use crate::{common::global_ctx::ArcGlobalCtx, socket::tcp::RuntimeTcpSocket};

pub(crate) struct RuntimeClientProtocolUpgrader {
    wireguard: WgConfig,
}

pub(crate) struct RuntimeServerProtocolUpgrader {
    wireguard: WgConfig,
}

impl RuntimeServerProtocolUpgrader {
    pub(crate) fn new(wireguard: WgConfig) -> Self {
        Self { wireguard }
    }
}

impl RuntimeClientProtocolUpgrader {
    pub(crate) fn new(wireguard: WgConfig) -> Self {
        Self { wireguard }
    }
}

fn runtime_wireguard_config(global_ctx: &ArcGlobalCtx) -> WgConfig {
    let identity = global_ctx.get_network_identity();
    WgConfig::new_from_network_identity(
        &identity.network_name,
        &identity.network_secret.unwrap_or_default(),
    )
}

pub(crate) fn runtime_client_protocol_upgrader(
    global_ctx: ArcGlobalCtx,
) -> Arc<dyn ClientProtocolUpgrader<RuntimeTcpSocket>> {
    let wireguard = runtime_wireguard_config(&global_ctx);
    Arc::new(CoreClientProtocolUpgrader::with_external(
        CoreClientProtocolConfig {
            unix: cfg!(unix),
            faketcp: cfg!(feature = "faketcp"),
        },
        Arc::new(RuntimeClientProtocolUpgrader::new(wireguard)),
    ))
}

pub(crate) fn runtime_server_protocol_upgrader(
    global_ctx: ArcGlobalCtx,
) -> Arc<dyn ServerProtocolUpgrader<RuntimeTcpSocket>> {
    let wireguard = runtime_wireguard_config(&global_ctx);
    Arc::new(CoreServerProtocolUpgrader::with_external(
        CoreServerProtocolConfig {
            unix: cfg!(unix),
            websocket: cfg!(feature = "websocket"),
            faketcp: cfg!(feature = "faketcp"),
            ..Default::default()
        },
        Arc::new(RuntimeServerProtocolUpgrader::new(wireguard)),
    ))
}

#[async_trait]
impl ClientProtocolUpgrader<RuntimeTcpSocket> for RuntimeClientProtocolUpgrader {
    fn supports_scheme(&self, scheme: &str) -> bool {
        match scheme {
            "ws" | "wss" => cfg!(feature = "websocket"),
            "wg" => cfg!(feature = "wireguard"),
            "quic" => cfg!(feature = "quic"),
            _ => false,
        }
    }

    async fn upgrade_client(
        &self,
        _connected: ConnectedTransport<RuntimeTcpSocket>,
        requested_url: url::Url,
    ) -> anyhow::Result<Box<dyn Tunnel>> {
        match requested_url.scheme() {
            #[cfg(feature = "websocket")]
            "ws" | "wss" => match _connected {
                ConnectedTransport::Tcp(socket) => {
                    Ok(crate::tunnel::websocket::upgrade_connected(socket, requested_url).await?)
                }
                ConnectedTransport::Udp(_) => {
                    anyhow::bail!("WebSocket protocol requires a TCP transport")
                }
                ConnectedTransport::ByteStream(_) => {
                    anyhow::bail!("WebSocket protocol requires a TCP transport")
                }
            },
            #[cfg(feature = "wireguard")]
            "wg" => match _connected {
                ConnectedTransport::Udp(session) => {
                    use crate::tunnel::wireguard::upgrade_connected;
                    Ok(upgrade_connected(session, requested_url, self.wireguard.clone()).await?)
                }
                ConnectedTransport::Tcp(_) => {
                    anyhow::bail!("WireGuard protocol requires a UDP session")
                }
                ConnectedTransport::ByteStream(_) => {
                    anyhow::bail!("WireGuard protocol requires a UDP session")
                }
            },
            #[cfg(feature = "quic")]
            "quic" => match _connected {
                ConnectedTransport::Udp(session) => {
                    Ok(crate::tunnel::quic::upgrade_connected(session, requested_url).await?)
                }
                ConnectedTransport::Tcp(_) => {
                    anyhow::bail!("QUIC protocol requires a UDP session")
                }
                ConnectedTransport::ByteStream(_) => {
                    anyhow::bail!("QUIC protocol requires a UDP session")
                }
            },
            scheme => anyhow::bail!("unsupported client protocol upgrader: {scheme}"),
        }
    }
}

#[async_trait]
impl ServerProtocolUpgrader<RuntimeTcpSocket> for RuntimeServerProtocolUpgrader {
    fn supports_scheme(&self, scheme: &str) -> bool {
        match scheme {
            "wg" => cfg!(feature = "wireguard"),
            "quic" => cfg!(feature = "quic"),
            _ => false,
        }
    }

    async fn upgrade_tcp(
        &self,
        _socket: RuntimeTcpSocket,
        local_url: url::Url,
    ) -> anyhow::Result<ServerProtocolUpgrade> {
        anyhow::bail!(
            "unsupported native TCP server protocol upgrader: {}",
            local_url.scheme()
        )
    }

    async fn upgrade_udp(
        &self,
        _session: UdpSession,
        local_url: url::Url,
        _admission: Option<ServerProtocolAdmission>,
    ) -> anyhow::Result<ServerProtocolUpgrade> {
        match local_url.scheme() {
            #[cfg(feature = "wireguard")]
            "wg" => {
                use crate::tunnel::wireguard::upgrade_accepted;
                Ok(ServerProtocolUpgrade::Tunnel(upgrade_accepted(
                    _session,
                    self.wireguard.clone(),
                )?))
            }
            #[cfg(feature = "quic")]
            "quic" => {
                let admission = _admission
                    .ok_or_else(|| anyhow::anyhow!("QUIC server admission permit is missing"))?;
                Ok(ServerProtocolUpgrade::Acceptor(Box::new(
                    crate::tunnel::quic::QuicAcceptedSession::new(_session, local_url, admission)?,
                )))
            }
            scheme => anyhow::bail!("unsupported native UDP server protocol upgrader: {scheme}"),
        }
    }

    async fn upgrade_byte_stream(
        &self,
        _socket: RuntimeTcpSocket,
        local_url: url::Url,
        _remote_url: Option<url::Url>,
    ) -> anyhow::Result<ServerProtocolUpgrade> {
        anyhow::bail!(
            "unsupported native byte-stream server protocol upgrader: {}",
            local_url.scheme()
        )
    }
}

#[cfg(test)]
mod tests {
    use crate::common::global_ctx::tests::get_mock_global_ctx;

    use super::*;

    #[tokio::test]
    async fn protocol_capabilities_follow_enabled_features() {
        let global_ctx = get_mock_global_ctx();
        let external = RuntimeClientProtocolUpgrader::new(runtime_wireguard_config(&global_ctx));

        assert!(!external.supports_scheme("tcp"));
        assert!(!external.supports_scheme("faketcp"));
        assert_eq!(external.supports_scheme("ws"), cfg!(feature = "websocket"));
        assert_eq!(external.supports_scheme("wss"), cfg!(feature = "websocket"));
        assert_eq!(external.supports_scheme("wg"), cfg!(feature = "wireguard"));
        assert_eq!(external.supports_scheme("quic"), cfg!(feature = "quic"));

        let upgrader = runtime_client_protocol_upgrader(global_ctx.clone());

        assert!(upgrader.supports_scheme("tcp"));
        assert!(upgrader.supports_scheme("udp"));
        assert!(upgrader.supports_scheme("ring"));
        assert_eq!(upgrader.supports_scheme("unix"), cfg!(unix));
        assert_eq!(upgrader.supports_scheme("ws"), cfg!(feature = "websocket"));
        assert_eq!(upgrader.supports_scheme("wss"), cfg!(feature = "websocket"));
        assert_eq!(upgrader.supports_scheme("wg"), cfg!(feature = "wireguard"));
        assert_eq!(upgrader.supports_scheme("quic"), cfg!(feature = "quic"));
        assert_eq!(
            upgrader.supports_scheme("faketcp"),
            cfg!(feature = "faketcp")
        );

        let server_external =
            RuntimeServerProtocolUpgrader::new(runtime_wireguard_config(&global_ctx));
        assert!(!server_external.supports_scheme("tcp"));
        assert!(!server_external.supports_scheme("udp"));
        assert!(!server_external.supports_scheme("ring"));
        assert_eq!(
            server_external.supports_scheme("wg"),
            cfg!(feature = "wireguard")
        );
        assert_eq!(
            server_external.supports_scheme("quic"),
            cfg!(feature = "quic")
        );

        let server = runtime_server_protocol_upgrader(global_ctx);
        assert!(server.supports_scheme("tcp"));
        assert!(server.supports_scheme("udp"));
        assert!(server.supports_scheme("ring"));
        assert_eq!(server.supports_scheme("unix"), cfg!(unix));
        assert_eq!(server.supports_scheme("ws"), cfg!(feature = "websocket"));
        assert_eq!(server.supports_scheme("wg"), cfg!(feature = "wireguard"));
        assert_eq!(server.supports_scheme("quic"), cfg!(feature = "quic"));
    }
}
