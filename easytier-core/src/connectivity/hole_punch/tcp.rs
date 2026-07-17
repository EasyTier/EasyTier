use std::{
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
    sync::Arc,
    time::Duration,
};

use async_trait::async_trait;
use rand::Rng as _;

use crate::{
    config::PeerId,
    connectivity::{
        protocol::{ClientProtocolUpgrader, ServerProtocolUpgrade, ServerProtocolUpgrader},
        transport::ConnectedTransport,
    },
    socket::{
        IpVersion, SocketContext,
        tcp::{
            TcpBindOptions, TcpConnectOptions, TcpListenOptions, VirtualTcpListener,
            VirtualTcpListenerFactory, VirtualTcpSocketFactory,
        },
    },
    tunnel::Tunnel,
};

mod manager;

pub use manager::TcpHolePunchConnector;

pub trait TcpHolePunchHost: VirtualTcpListenerFactory + VirtualTcpSocketFactory {}

impl<T> TcpHolePunchHost for T where T: VirtualTcpListenerFactory + VirtualTcpSocketFactory {}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TcpHolePunchAdmission {
    Client,
    Server,
}

#[async_trait]
pub trait TcpHolePunchTunnelSink: Send + Sync + 'static {
    async fn add_client_tunnel(&self, tunnel: Box<dyn Tunnel>) -> anyhow::Result<()>;

    async fn add_server_tunnel(&self, tunnel: Box<dyn Tunnel>) -> anyhow::Result<()>;
}

#[derive(Debug, thiserror::Error)]
pub enum TcpHolePunchTransportError {
    #[error("TCP hole-punch protocol upgrade failed")]
    Upgrade(#[source] anyhow::Error),
    #[error("TCP hole-punch tunnel admission failed")]
    Admission(#[source] anyhow::Error),
}

#[async_trait]
pub trait TcpHolePunchTransportSink: Send + Sync + 'static {
    type ConnectedSocket;
    type AcceptedSocket;

    async fn add_connected_transport(
        &self,
        socket: Self::ConnectedSocket,
        requested_url: url::Url,
        admission: TcpHolePunchAdmission,
    ) -> Result<(), TcpHolePunchTransportError>;

    async fn add_accepted_transport(
        &self,
        socket: Self::AcceptedSocket,
        local_url: url::Url,
    ) -> Result<(), TcpHolePunchTransportError>;
}

pub struct ProtocolTcpHolePunchTransportSink<ConnectedSocket, AcceptedSocket, T> {
    client_protocol: Arc<dyn ClientProtocolUpgrader<ConnectedSocket>>,
    server_protocol: Arc<dyn ServerProtocolUpgrader<AcceptedSocket>>,
    tunnel_sink: Arc<T>,
}

impl<ConnectedSocket, AcceptedSocket, T>
    ProtocolTcpHolePunchTransportSink<ConnectedSocket, AcceptedSocket, T>
{
    pub fn new(
        client_protocol: Arc<dyn ClientProtocolUpgrader<ConnectedSocket>>,
        server_protocol: Arc<dyn ServerProtocolUpgrader<AcceptedSocket>>,
        tunnel_sink: Arc<T>,
    ) -> Self {
        Self {
            client_protocol,
            server_protocol,
            tunnel_sink,
        }
    }
}

#[async_trait]
impl<ConnectedSocket, AcceptedSocket, T> TcpHolePunchTransportSink
    for ProtocolTcpHolePunchTransportSink<ConnectedSocket, AcceptedSocket, T>
where
    ConnectedSocket: Send + 'static,
    AcceptedSocket: Send + 'static,
    T: TcpHolePunchTunnelSink,
{
    type ConnectedSocket = ConnectedSocket;
    type AcceptedSocket = AcceptedSocket;

    async fn add_connected_transport(
        &self,
        socket: ConnectedSocket,
        requested_url: url::Url,
        admission: TcpHolePunchAdmission,
    ) -> Result<(), TcpHolePunchTransportError> {
        let tunnel = self
            .client_protocol
            .upgrade_client(ConnectedTransport::Tcp(socket), requested_url)
            .await
            .map_err(TcpHolePunchTransportError::Upgrade)?;
        match admission {
            TcpHolePunchAdmission::Client => self.tunnel_sink.add_client_tunnel(tunnel).await,
            TcpHolePunchAdmission::Server => self.tunnel_sink.add_server_tunnel(tunnel).await,
        }
        .map_err(TcpHolePunchTransportError::Admission)
    }

    async fn add_accepted_transport(
        &self,
        socket: AcceptedSocket,
        local_url: url::Url,
    ) -> Result<(), TcpHolePunchTransportError> {
        let upgrade = self
            .server_protocol
            .upgrade_tcp(socket, local_url)
            .await
            .map_err(TcpHolePunchTransportError::Upgrade)?;
        let ServerProtocolUpgrade::Tunnel(tunnel) = upgrade else {
            return Err(TcpHolePunchTransportError::Upgrade(anyhow::anyhow!(
                "TCP hole-punch protocol returned a tunnel acceptor"
            )));
        };
        self.tunnel_sink
            .add_server_tunnel(tunnel)
            .await
            .map_err(TcpHolePunchTransportError::Admission)
    }
}

type ConnectedTcpSocket<H> = <H as VirtualTcpSocketFactory>::Socket;
type AcceptedTcpSocket<H> =
    <<H as VirtualTcpListenerFactory>::Listener as VirtualTcpListener>::Socket;

pub(super) type TcpHolePunchTransportSinkFor<H> = dyn TcpHolePunchTransportSink<
        ConnectedSocket = ConnectedTcpSocket<H>,
        AcceptedSocket = AcceptedTcpSocket<H>,
    >;

fn bind_addr_for_port(port: u16, is_v6: bool) -> SocketAddr {
    if is_v6 {
        SocketAddr::new(IpAddr::V6(Ipv6Addr::UNSPECIFIED), port)
    } else {
        SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), port)
    }
}

pub async fn select_local_port<H>(
    host: &H,
    context: SocketContext,
    is_v6: bool,
) -> anyhow::Result<u16>
where
    H: VirtualTcpListenerFactory,
{
    let bind_addr = bind_addr_for_port(0, is_v6);
    tracing::trace!(?bind_addr, is_v6, "tcp hole punch select local port");
    let context = context.with_ip_version(if is_v6 { IpVersion::V6 } else { IpVersion::V4 });
    let listener = host
        .bind_tcp(
            TcpListenOptions::hole_punch(bind_addr).with_bind(
                TcpBindOptions::default()
                    .with_context(context)
                    .with_local_addr(Some(bind_addr)),
            ),
        )
        .await?;
    let port = listener.local_addr()?.port();
    tracing::debug!(?bind_addr, port, "tcp hole punch selected local port");
    Ok(port)
}

// TCP supports simultaneous connect, so both peers may dial from the mapped port.
pub async fn try_connect_to_remote<H, AcceptedSocket>(
    host: Arc<H>,
    transport_sink: Arc<
        dyn TcpHolePunchTransportSink<
                ConnectedSocket = <H as VirtualTcpSocketFactory>::Socket,
                AcceptedSocket = AcceptedSocket,
            >,
    >,
    remote_mapped_addr: SocketAddr,
    local_port: u16,
    context: SocketContext,
    admission: TcpHolePunchAdmission,
    max_attempts: u32,
) -> anyhow::Result<()>
where
    H: VirtualTcpSocketFactory,
    AcceptedSocket: 'static,
{
    tracing::info!(
        ?remote_mapped_addr,
        local_port,
        "tcp hole punch server start connect loop"
    );

    let bind_addr = bind_addr_for_port(local_port, remote_mapped_addr.is_ipv6());
    let context = context.with_ip_version(if remote_mapped_addr.is_ipv6() {
        IpVersion::V6
    } else {
        IpVersion::V4
    });
    let requested_url: url::Url = format!("tcp://{remote_mapped_addr}").parse().unwrap();

    let start = crate::foundation::time::Instant::now();
    let mut attempts = 0_u32;
    while start.elapsed() < Duration::from_secs(10) && attempts < max_attempts {
        attempts = attempts.wrapping_add(1);
        let bind = TcpBindOptions::default()
            .with_context(context.clone())
            .with_local_addr(Some(bind_addr))
            .with_only_v6(true);
        let options =
            TcpConnectOptions::hole_punch(remote_mapped_addr, Some(bind_addr)).with_bind(bind);
        if let Ok(Ok(socket)) =
            crate::foundation::time::timeout(Duration::from_secs(3), host.connect_tcp(options))
                .await
        {
            let admission_result = transport_sink
                .add_connected_transport(socket, requested_url.clone(), admission)
                .await;
            match admission_result {
                Ok(()) => {}
                Err(TcpHolePunchTransportError::Upgrade(error)) => return Err(error),
                Err(TcpHolePunchTransportError::Admission(error)) => {
                    tracing::error!(
                        ?remote_mapped_addr,
                        local_port,
                        attempts,
                        ?error,
                        "tcp hole punch server connected and added client tunnel failed"
                    );
                    continue;
                }
            }

            tracing::info!(
                ?remote_mapped_addr,
                local_port,
                attempts,
                ?admission,
                "tcp hole punch server connected and added tunnel"
            );
            return Ok(());
        }
        tracing::trace!(
            ?remote_mapped_addr,
            local_port,
            attempts,
            "tcp hole punch server connect attempt failed"
        );
        let sleep_ms = rand::thread_rng().gen_range(10..100);
        crate::foundation::time::sleep(Duration::from_millis(sleep_ms)).await;
    }

    tracing::warn!(
        ?remote_mapped_addr,
        local_port,
        attempts,
        "tcp hole punch server connect loop timeout"
    );

    Err(anyhow::anyhow!(
        "tcp hole punch server connect loop timeout"
    ))
}

pub async fn accept_connections<L, ConnectedSocket>(
    listener: Arc<L>,
    transport_sink: Arc<
        dyn TcpHolePunchTransportSink<ConnectedSocket = ConnectedSocket, AcceptedSocket = L::Socket>,
    >,
    dst_peer_id: PeerId,
) -> anyhow::Result<()>
where
    L: VirtualTcpListener,
    ConnectedSocket: 'static,
{
    loop {
        match listener.accept().await {
            Ok((socket, _)) => {
                let local_url = format!("tcp://0.0.0.0:{}", listener.local_addr()?.port())
                    .parse()
                    .unwrap();
                if let Err(error) = transport_sink
                    .add_accepted_transport(socket, local_url)
                    .await
                {
                    tracing::error!(?error, "tcp hole punch transport admission error");
                    continue;
                }

                tracing::info!(
                    dst_peer_id,
                    "tcp hole punch initiator accepted and added server tunnel"
                );
            }
            Err(error) => {
                tracing::error!(?error, "tcp hole punch accept error");
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

    use super::*;

    #[derive(Default)]
    struct MockProtocols {
        client_upgrades: AtomicUsize,
        server_upgrades: AtomicUsize,
        fail_client_upgrade: AtomicBool,
    }

    #[async_trait]
    impl ClientProtocolUpgrader<()> for MockProtocols {
        fn supports_scheme(&self, scheme: &str) -> bool {
            scheme == "tcp"
        }

        async fn upgrade_client(
            &self,
            connected: ConnectedTransport<()>,
            _requested_url: url::Url,
        ) -> anyhow::Result<Box<dyn Tunnel>> {
            let ConnectedTransport::Tcp(()) = connected else {
                anyhow::bail!("expected TCP transport");
            };
            if self.fail_client_upgrade.load(Ordering::Relaxed) {
                anyhow::bail!("mock client upgrade failure");
            }
            self.client_upgrades.fetch_add(1, Ordering::Relaxed);
            Ok(crate::tunnel::ring::create_ring_tunnel_pair().0)
        }
    }

    #[async_trait]
    impl ServerProtocolUpgrader<()> for MockProtocols {
        fn supports_scheme(&self, scheme: &str) -> bool {
            scheme == "tcp"
        }

        async fn upgrade_tcp(
            &self,
            _socket: (),
            _local_url: url::Url,
        ) -> anyhow::Result<ServerProtocolUpgrade> {
            self.server_upgrades.fetch_add(1, Ordering::Relaxed);
            Ok(ServerProtocolUpgrade::Tunnel(
                crate::tunnel::ring::create_ring_tunnel_pair().0,
            ))
        }

        async fn upgrade_udp(
            &self,
            _session: crate::socket::udp::UdpSession,
            _local_url: url::Url,
            _admission: Option<crate::connectivity::protocol::ServerProtocolAdmission>,
        ) -> anyhow::Result<ServerProtocolUpgrade> {
            anyhow::bail!("unexpected UDP transport")
        }

        async fn upgrade_byte_stream(
            &self,
            _socket: (),
            _local_url: url::Url,
            _remote_url: Option<url::Url>,
        ) -> anyhow::Result<ServerProtocolUpgrade> {
            anyhow::bail!("unexpected byte stream")
        }
    }

    #[derive(Default)]
    struct MockTunnelSink {
        clients: AtomicUsize,
        servers: AtomicUsize,
        fail_client_admission: AtomicBool,
    }

    #[async_trait]
    impl TcpHolePunchTunnelSink for MockTunnelSink {
        async fn add_client_tunnel(&self, _tunnel: Box<dyn Tunnel>) -> anyhow::Result<()> {
            if self.fail_client_admission.load(Ordering::Relaxed) {
                anyhow::bail!("mock client admission failure");
            }
            self.clients.fetch_add(1, Ordering::Relaxed);
            Ok(())
        }

        async fn add_server_tunnel(&self, _tunnel: Box<dyn Tunnel>) -> anyhow::Result<()> {
            self.servers.fetch_add(1, Ordering::Relaxed);
            Ok(())
        }
    }

    #[tokio::test]
    async fn protocol_sink_upgrades_before_tcp_hole_punch_admission() {
        let protocols = Arc::new(MockProtocols::default());
        let tunnel_sink = Arc::new(MockTunnelSink::default());
        let sink = ProtocolTcpHolePunchTransportSink::new(
            protocols.clone(),
            protocols.clone(),
            tunnel_sink.clone(),
        );
        let url = url::Url::parse("tcp://198.51.100.1:11010").unwrap();

        sink.add_connected_transport((), url.clone(), TcpHolePunchAdmission::Client)
            .await
            .unwrap();
        sink.add_connected_transport((), url.clone(), TcpHolePunchAdmission::Server)
            .await
            .unwrap();
        sink.add_accepted_transport((), url).await.unwrap();

        assert_eq!(protocols.client_upgrades.load(Ordering::Relaxed), 2);
        assert_eq!(protocols.server_upgrades.load(Ordering::Relaxed), 1);
        assert_eq!(tunnel_sink.clients.load(Ordering::Relaxed), 1);
        assert_eq!(tunnel_sink.servers.load(Ordering::Relaxed), 2);

        protocols.fail_client_upgrade.store(true, Ordering::Relaxed);
        assert!(matches!(
            sink.add_connected_transport(
                (),
                url::Url::parse("tcp://198.51.100.1:11010").unwrap(),
                TcpHolePunchAdmission::Client,
            )
            .await,
            Err(TcpHolePunchTransportError::Upgrade(_))
        ));
        protocols
            .fail_client_upgrade
            .store(false, Ordering::Relaxed);
        tunnel_sink
            .fail_client_admission
            .store(true, Ordering::Relaxed);
        assert!(matches!(
            sink.add_connected_transport(
                (),
                url::Url::parse("tcp://198.51.100.1:11010").unwrap(),
                TcpHolePunchAdmission::Client,
            )
            .await,
            Err(TcpHolePunchTransportError::Admission(_))
        ));
    }

    #[test]
    fn bind_address_tracks_requested_family_and_port() {
        assert_eq!(
            bind_addr_for_port(1234, false),
            "0.0.0.0:1234".parse().unwrap()
        );
        assert_eq!(bind_addr_for_port(4321, true), "[::]:4321".parse().unwrap());
    }
}
