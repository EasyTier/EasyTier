use std::{num::NonZeroUsize, sync::Arc};

use async_trait::async_trait;
use easytier_core::{
    connectivity::{
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

#[cfg(feature = "wireguard")]
use crate::tunnel::wireguard::WgConfig;
use crate::{common::global_ctx::ArcGlobalCtx, socket::tcp::RuntimeTcpSocket};

pub(crate) struct RuntimeClientProtocolUpgrader {
    #[cfg(feature = "wireguard")]
    wireguard: WgConfig,
}

pub(crate) struct RuntimeServerProtocolUpgrader {
    #[cfg(feature = "wireguard")]
    wireguard: WgConfig,
}

#[cfg(feature = "wireguard")]
fn runtime_wireguard_config(global_ctx: &ArcGlobalCtx) -> WgConfig {
    let identity = global_ctx.get_network_identity();
    WgConfig::new_from_network_identity(
        &identity.network_name,
        &identity.network_secret.unwrap_or_default(),
    )
}

fn runtime_client_protocol_adapter(global_ctx: &ArcGlobalCtx) -> RuntimeClientProtocolUpgrader {
    #[cfg(not(feature = "wireguard"))]
    let _ = global_ctx;
    RuntimeClientProtocolUpgrader {
        #[cfg(feature = "wireguard")]
        wireguard: runtime_wireguard_config(global_ctx),
    }
}

fn runtime_server_protocol_adapter(global_ctx: &ArcGlobalCtx) -> RuntimeServerProtocolUpgrader {
    #[cfg(not(feature = "wireguard"))]
    let _ = global_ctx;
    RuntimeServerProtocolUpgrader {
        #[cfg(feature = "wireguard")]
        wireguard: runtime_wireguard_config(global_ctx),
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
        Arc::new(runtime_client_protocol_adapter(&global_ctx)),
    ))
}

pub(crate) fn runtime_server_protocol_upgrader(
    global_ctx: ArcGlobalCtx,
) -> Arc<dyn ServerProtocolUpgrader<RuntimeTcpSocket>> {
    Arc::new(CoreServerProtocolUpgrader::with_external(
        CoreServerProtocolConfig {
            unix: cfg!(unix),
            faketcp: cfg!(feature = "faketcp"),
            ..Default::default()
        },
        Arc::new(runtime_server_protocol_adapter(&global_ctx)),
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

    fn connect_timeout(&self, scheme: &str) -> Option<std::time::Duration> {
        match scheme {
            #[cfg(feature = "websocket")]
            "ws" | "wss" => Some(crate::tunnel::websocket::CONNECT_TIMEOUT),
            _ => None,
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
            "ws" | "wss" => cfg!(feature = "websocket"),
            "wg" => cfg!(feature = "wireguard"),
            "quic" => cfg!(feature = "quic"),
            _ => false,
        }
    }

    fn max_pending_tcp_upgrades(&self, scheme: &str) -> Option<NonZeroUsize> {
        match scheme {
            #[cfg(feature = "websocket")]
            "ws" | "wss" => Some(NonZeroUsize::MIN),
            _ => None,
        }
    }

    async fn upgrade_tcp(
        &self,
        _socket: RuntimeTcpSocket,
        local_url: url::Url,
    ) -> anyhow::Result<ServerProtocolUpgrade> {
        match local_url.scheme() {
            #[cfg(feature = "websocket")]
            "ws" | "wss" => Ok(ServerProtocolUpgrade::Tunnel(
                tokio::time::timeout(
                    crate::tunnel::websocket::SERVER_HANDSHAKE_TIMEOUT,
                    crate::tunnel::websocket::upgrade_accepted(_socket, local_url),
                )
                .await??,
            )),
            scheme => anyhow::bail!("unsupported native TCP server protocol upgrader: {scheme}"),
        }
    }

    async fn upgrade_udp(
        &self,
        _session: UdpSession,
        local_url: url::Url,
        _admission: Option<ServerProtocolAdmission>,
    ) -> anyhow::Result<ServerProtocolUpgrade> {
        match local_url.scheme() {
            #[cfg(feature = "websocket")]
            "ws" | "wss" => anyhow::bail!("WebSocket protocol requires a TCP transport"),
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
        match local_url.scheme() {
            #[cfg(feature = "websocket")]
            "ws" | "wss" => anyhow::bail!("WebSocket protocol requires a TCP transport"),
            scheme => {
                anyhow::bail!("unsupported native byte-stream server protocol upgrader: {scheme}")
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::common::global_ctx::tests::get_mock_global_ctx;

    use super::*;

    #[tokio::test]
    async fn protocol_capabilities_follow_enabled_features() {
        let global_ctx = get_mock_global_ctx();
        let external = runtime_client_protocol_adapter(&global_ctx);

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

        let server_external = runtime_server_protocol_adapter(&global_ctx);
        assert!(!server_external.supports_scheme("tcp"));
        assert!(!server_external.supports_scheme("udp"));
        assert!(!server_external.supports_scheme("ring"));
        assert_eq!(
            server_external.supports_scheme("ws"),
            cfg!(feature = "websocket")
        );
        assert_eq!(
            server_external.max_pending_tcp_upgrades("ws"),
            cfg!(feature = "websocket").then_some(NonZeroUsize::MIN)
        );
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

    #[cfg(feature = "websocket")]
    #[rstest::rstest]
    #[case("ws")]
    #[case("wss")]
    #[tokio::test]
    async fn runtime_websocket_upgraders_share_one_native_engine(#[case] scheme: &str) {
        use easytier_core::packet::ZCPacket;
        use futures::{SinkExt, StreamExt};

        let listener = tokio::net::TcpListener::bind(("127.0.0.1", 0))
            .await
            .unwrap();
        let addr = listener.local_addr().unwrap();
        let url: url::Url = format!("{scheme}://{addr}").parse().unwrap();
        let global_ctx = get_mock_global_ctx();
        let server = runtime_server_protocol_upgrader(global_ctx.clone());
        let client = runtime_client_protocol_upgrader(global_ctx);

        assert_eq!(
            client.connect_timeout(scheme),
            Some(crate::tunnel::websocket::CONNECT_TIMEOUT)
        );

        let server_url = url.clone();
        let server_task = tokio::spawn(async move {
            let (socket, _) = listener.accept().await.unwrap();
            let ServerProtocolUpgrade::Tunnel(tunnel) = server
                .upgrade_tcp(RuntimeTcpSocket::new(socket), server_url)
                .await
                .unwrap()
            else {
                panic!("WebSocket must upgrade directly to a tunnel");
            };
            crate::tunnel::common::tests::_tunnel_echo_server(tunnel, true).await;
        });

        tokio::time::timeout(std::time::Duration::from_secs(5), async {
            let socket = tokio::net::TcpStream::connect(addr).await.unwrap();
            let tunnel = client
                .upgrade_client(ConnectedTransport::Tcp(RuntimeTcpSocket::new(socket)), url)
                .await
                .unwrap();
            let (mut recv, mut send) = tunnel.split();
            send.send(ZCPacket::new_with_payload(b"runtime websocket seam"))
                .await
                .unwrap();
            let packet = recv.next().await.unwrap().unwrap();
            assert_eq!(packet.payload(), b"runtime websocket seam".as_slice());
            send.close().await.unwrap();
            server_task.await.unwrap();
        })
        .await
        .unwrap();
    }
}
