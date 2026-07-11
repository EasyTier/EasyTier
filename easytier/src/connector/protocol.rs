use std::sync::Arc;

use async_trait::async_trait;
use easytier_core::{
    connectivity::{
        protocol::{ClientProtocolUpgrader, CoreClientProtocolConfig, CoreClientProtocolUpgrader},
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

pub(crate) fn runtime_client_protocol_upgrader(
    global_ctx: ArcGlobalCtx,
) -> Arc<dyn ClientProtocolUpgrader<RuntimeTcpSocket>> {
    Arc::new(CoreClientProtocolUpgrader::with_external(
        CoreClientProtocolConfig {
            unix: cfg!(unix),
            faketcp: cfg!(feature = "faketcp"),
        },
        Arc::new(RuntimeClientProtocolUpgrader::new(global_ctx)),
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

#[cfg(test)]
mod tests {
    use easytier_core::connectivity::protocol::RawClientProtocolUpgrader;

    use crate::common::global_ctx::tests::get_mock_global_ctx;

    use super::*;

    #[tokio::test]
    async fn protocol_capabilities_follow_enabled_features() {
        let global_ctx = get_mock_global_ctx();
        let external = RuntimeClientProtocolUpgrader::new(global_ctx.clone());

        assert!(!external.supports_scheme("tcp"));
        assert!(!external.supports_scheme("faketcp"));
        assert_eq!(external.supports_scheme("ws"), cfg!(feature = "websocket"));
        assert_eq!(external.supports_scheme("wss"), cfg!(feature = "websocket"));
        assert_eq!(external.supports_scheme("wg"), cfg!(feature = "wireguard"));
        assert_eq!(external.supports_scheme("quic"), cfg!(feature = "quic"));

        let upgrader = runtime_client_protocol_upgrader(global_ctx);

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
    }

    #[test]
    fn core_raw_upgrader_needs_no_runtime_protocol_adapter() {
        let upgrader = RawClientProtocolUpgrader;
        let supports = |scheme| {
            <RawClientProtocolUpgrader as ClientProtocolUpgrader<RuntimeTcpSocket>>::supports_scheme(
                &upgrader, scheme,
            )
        };

        assert!(supports("tcp"));
        assert!(supports("udp"));
        assert!(!supports("quic"));
    }
}
