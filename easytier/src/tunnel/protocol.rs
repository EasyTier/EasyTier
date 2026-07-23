use std::sync::Arc;

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

use crate::{common::global_ctx::ArcGlobalCtx, socket::tcp::RuntimeTcpSocket};

#[path = "protocol_adapters/mod.rs"]
mod adapters;

pub(crate) struct RuntimeClientProtocolUpgrader {
    adapters: Vec<adapters::ClientAdapter>,
}

pub(crate) struct RuntimeServerProtocolUpgrader {
    adapters: Vec<adapters::ServerAdapter>,
}

fn runtime_client_protocol_adapter(global_ctx: &ArcGlobalCtx) -> RuntimeClientProtocolUpgrader {
    RuntimeClientProtocolUpgrader {
        adapters: adapters::client_adapters(global_ctx),
    }
}

fn runtime_server_protocol_adapter(global_ctx: &ArcGlobalCtx) -> RuntimeServerProtocolUpgrader {
    RuntimeServerProtocolUpgrader {
        adapters: adapters::server_adapters(global_ctx),
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
        },
        Arc::new(runtime_server_protocol_adapter(&global_ctx)),
    ))
}

#[async_trait]
impl ClientProtocolUpgrader<RuntimeTcpSocket> for RuntimeClientProtocolUpgrader {
    fn supports_scheme(&self, scheme: &str) -> bool {
        self.adapters
            .iter()
            .any(|adapter| adapter.supports_scheme(scheme))
    }

    fn connect_timeout(&self, scheme: &str) -> Option<std::time::Duration> {
        self.adapters
            .iter()
            .find(|adapter| adapter.supports_scheme(scheme))
            .and_then(|adapter| adapter.connect_timeout(scheme))
    }

    async fn upgrade_client(
        &self,
        connected: ConnectedTransport<RuntimeTcpSocket>,
        requested_url: url::Url,
    ) -> anyhow::Result<Box<dyn Tunnel>> {
        let scheme = requested_url.scheme().to_owned();
        let adapter = self
            .adapters
            .iter()
            .find(|adapter| adapter.supports_scheme(&scheme))
            .ok_or_else(|| anyhow::anyhow!("unsupported client protocol upgrader: {scheme}"))?;
        adapter.upgrade_client(connected, requested_url).await
    }
}

#[async_trait]
impl ServerProtocolUpgrader<RuntimeTcpSocket> for RuntimeServerProtocolUpgrader {
    fn supports_scheme(&self, scheme: &str) -> bool {
        self.adapters
            .iter()
            .any(|adapter| adapter.supports_scheme(scheme))
    }

    fn max_pending_tcp_upgrades(&self, scheme: &str) -> Option<std::num::NonZeroUsize> {
        self.adapters
            .iter()
            .find(|adapter| adapter.supports_scheme(scheme))
            .and_then(|adapter| adapter.max_pending_tcp_upgrades(scheme))
    }

    async fn upgrade_tcp(
        &self,
        socket: RuntimeTcpSocket,
        local_url: url::Url,
    ) -> anyhow::Result<ServerProtocolUpgrade> {
        let scheme = local_url.scheme().to_owned();
        let adapter = self
            .adapters
            .iter()
            .find(|adapter| adapter.supports_scheme(&scheme))
            .ok_or_else(|| {
                anyhow::anyhow!("unsupported native TCP server protocol upgrader: {scheme}")
            })?;
        adapter.upgrade_tcp(socket, local_url).await
    }

    async fn upgrade_udp(
        &self,
        session: UdpSession,
        local_url: url::Url,
        admission: Option<ServerProtocolAdmission>,
    ) -> anyhow::Result<ServerProtocolUpgrade> {
        let scheme = local_url.scheme().to_owned();
        let adapter = self
            .adapters
            .iter()
            .find(|adapter| adapter.supports_scheme(&scheme))
            .ok_or_else(|| {
                anyhow::anyhow!("unsupported native UDP server protocol upgrader: {scheme}")
            })?;
        adapter.upgrade_udp(session, local_url, admission).await
    }

    async fn upgrade_byte_stream(
        &self,
        socket: RuntimeTcpSocket,
        local_url: url::Url,
        remote_url: Option<url::Url>,
    ) -> anyhow::Result<ServerProtocolUpgrade> {
        let scheme = local_url.scheme().to_owned();
        let adapter = self
            .adapters
            .iter()
            .find(|adapter| adapter.supports_scheme(&scheme))
            .ok_or_else(|| {
                anyhow::anyhow!("unsupported native byte-stream server protocol upgrader: {scheme}")
            })?;
        adapter
            .upgrade_byte_stream(socket, local_url, remote_url)
            .await
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
            cfg!(feature = "websocket").then_some(std::num::NonZeroUsize::MIN)
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

    #[cfg(feature = "websocket")]
    #[tokio::test]
    async fn runtime_websocket_upgraders_reject_ws_client_for_wss_server() {
        let listener = tokio::net::TcpListener::bind(("127.0.0.1", 0))
            .await
            .unwrap();
        let addr = listener.local_addr().unwrap();
        let server_url: url::Url = format!("wss://{addr}").parse().unwrap();
        let client_url: url::Url = format!("ws://{addr}").parse().unwrap();
        let global_ctx = get_mock_global_ctx();
        let server = runtime_server_protocol_upgrader(global_ctx.clone());
        let client = runtime_client_protocol_upgrader(global_ctx);

        let server_task = tokio::spawn(async move {
            let (socket, _) = listener.accept().await.unwrap();
            assert!(
                server
                    .upgrade_tcp(RuntimeTcpSocket::new(socket), server_url)
                    .await
                    .is_err()
            );
        });

        tokio::time::timeout(std::time::Duration::from_secs(5), async {
            let socket = tokio::net::TcpStream::connect(addr).await.unwrap();
            assert!(
                client
                    .upgrade_client(
                        ConnectedTransport::Tcp(RuntimeTcpSocket::new(socket)),
                        client_url,
                    )
                    .await
                    .is_err()
            );
            server_task.await.unwrap();
        })
        .await
        .unwrap();
    }

    #[cfg(feature = "wireguard")]
    #[rstest::rstest]
    #[case("127.0.0.1:0")]
    #[case("[::1]:0")]
    #[tokio::test]
    async fn runtime_wireguard_upgraders_consume_core_udp_sessions(#[case] bind_addr: &str) {
        use crate::{
            common::netns::NetNS, host_runtime::native_host_runtime,
            socket::udp::new_runtime_udp_session_listener,
        };
        use easytier_core::{
            connectivity::transport::{UdpSessionMode, connect_udp},
            packet::ZCPacket,
            socket::SocketListener,
            socket::udp::{
                UdpBindOptions, UdpSessionAcceptKind, UdpSessionListenRequest, UdpSessionProtocol,
                VirtualUdpSocket,
            },
        };
        use futures::{SinkExt, StreamExt};

        let bind_addr = bind_addr.parse().unwrap();
        let mut listener = new_runtime_udp_session_listener(
            format!("wg://{bind_addr}").parse().unwrap(),
            UdpSessionListenRequest::new(
                UdpBindOptions::port_bound_listener(bind_addr).with_only_v6(bind_addr.is_ipv6()),
            ),
            UdpSessionAcceptKind::Classified(UdpSessionProtocol::WireGuard),
            NetNS::new(None),
        );
        listener.listen().await.unwrap();
        let remote_addr = listener.bound_socket().unwrap().local_addr().unwrap();
        let remote_url: url::Url = format!("wg://{remote_addr}").parse().unwrap();

        let global_ctx = get_mock_global_ctx();
        let server = runtime_server_protocol_upgrader(global_ctx.clone());
        let client = runtime_client_protocol_upgrader(global_ctx);
        let server_url = remote_url.clone();
        let server_task = tokio::spawn(async move {
            let session = listener.accept().await.unwrap();
            let ServerProtocolUpgrade::Tunnel(tunnel) =
                server.upgrade_udp(session, server_url, None).await.unwrap()
            else {
                panic!("WireGuard must upgrade directly to a tunnel");
            };
            crate::tunnel::common::tests::_tunnel_echo_server(tunnel, false).await;
        });

        tokio::time::timeout(std::time::Duration::from_secs(5), async {
            let connected = connect_udp(
                native_host_runtime(),
                remote_addr,
                Vec::new(),
                UdpBindOptions::direct_connect(),
                UdpSessionMode::Classified(UdpSessionProtocol::WireGuard),
            )
            .await
            .unwrap();
            let tunnel = client
                .upgrade_client(ConnectedTransport::Udp(connected), remote_url)
                .await
                .unwrap();
            let (mut recv, mut send) = tunnel.split();
            send.send(ZCPacket::new_with_payload(b"runtime WireGuard seam"))
                .await
                .unwrap();
            let packet = recv.next().await.unwrap().unwrap();
            assert_eq!(packet.payload(), b"runtime WireGuard seam".as_slice());
            let _ = send.close().await;
            server_task.abort();
            let _ = server_task.await;
        })
        .await
        .unwrap();
    }

    #[cfg(feature = "quic")]
    #[rstest::rstest]
    #[case("127.0.0.1:0")]
    #[case("[::1]:0")]
    #[tokio::test]
    async fn runtime_quic_upgraders_consume_core_udp_sessions(#[case] bind_addr: &str) {
        use crate::{
            common::netns::NetNS, host_runtime::native_host_runtime,
            socket::udp::new_runtime_udp_session_listener,
        };
        use easytier_core::{
            connectivity::{
                protocol::ServerProtocolAdmissionController,
                transport::{UdpSessionMode, connect_udp},
            },
            packet::ZCPacket,
            socket::SocketListener,
            socket::udp::{
                UdpBindOptions, UdpSessionAcceptKind, UdpSessionListenRequest, UdpSessionProtocol,
                VirtualUdpSocket,
            },
        };
        use futures::{SinkExt, StreamExt};

        let bind_addr = bind_addr.parse().unwrap();
        let mut listener = new_runtime_udp_session_listener(
            format!("quic://{bind_addr}").parse().unwrap(),
            UdpSessionListenRequest::new(
                UdpBindOptions::port_bound_listener(bind_addr).with_only_v6(bind_addr.is_ipv6()),
            ),
            UdpSessionAcceptKind::Classified(UdpSessionProtocol::Quic),
            NetNS::new(None),
        );
        listener.listen().await.unwrap();
        let remote_addr = listener.bound_socket().unwrap().local_addr().unwrap();
        let remote_url: url::Url = format!("quic://{remote_addr}").parse().unwrap();

        let global_ctx = get_mock_global_ctx();
        let server = runtime_server_protocol_upgrader(global_ctx.clone());
        let client = runtime_client_protocol_upgrader(global_ctx);
        let server_url = remote_url.clone();
        let server_task = tokio::spawn(async move {
            let session = listener.accept().await.unwrap();
            let admission = ServerProtocolAdmissionController::quic()
                .try_admit()
                .unwrap();
            let ServerProtocolUpgrade::Acceptor(mut accepted) = server
                .upgrade_udp(session, server_url, Some(admission))
                .await
                .unwrap()
            else {
                panic!("QUIC must keep accepting connections from its UDP session");
            };
            let tunnel = accepted.accept().await.unwrap();
            crate::tunnel::common::tests::_tunnel_echo_server(tunnel, false).await;
        });

        tokio::time::timeout(std::time::Duration::from_secs(5), async {
            let connected = connect_udp(
                native_host_runtime(),
                remote_addr,
                Vec::new(),
                UdpBindOptions::direct_connect(),
                UdpSessionMode::Classified(UdpSessionProtocol::Quic),
            )
            .await
            .unwrap();
            let tunnel = client
                .upgrade_client(ConnectedTransport::Udp(connected), remote_url)
                .await
                .unwrap();
            let (mut recv, mut send) = tunnel.split();
            send.send(ZCPacket::new_with_payload(b"runtime QUIC seam"))
                .await
                .unwrap();
            let packet = recv.next().await.unwrap().unwrap();
            assert_eq!(packet.payload(), b"runtime QUIC seam".as_slice());
            let _ = send.close().await;
            server_task.await.unwrap();
        })
        .await
        .unwrap();
    }
}
