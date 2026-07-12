use std::{
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
    sync::Arc,
    time::Duration,
};

use async_trait::async_trait;
use rand::Rng as _;

use crate::{
    config::PeerId,
    connectivity::protocol::raw,
    peers::peer_manager::PeerManagerCore,
    proto::common::NatType,
    socket::tcp::{
        TcpBindOptions, TcpConnectOptions, TcpListenOptions, VirtualTcpListener,
        VirtualTcpListenerFactory, VirtualTcpSocketFactory,
    },
};

mod manager;

pub use manager::TcpHolePunchConnector;

#[async_trait]
pub trait TcpHolePunchHost: VirtualTcpListenerFactory + VirtualTcpSocketFactory {
    fn tcp_nat_type(&self) -> NatType;

    async fn tcp_port_mapping(&self, local_port: u16) -> anyhow::Result<SocketAddr>;
}

#[async_trait]
pub trait TcpHolePunchEnvironment: Send + Sync + 'static {
    fn tcp_nat_type(&self) -> NatType;

    async fn tcp_port_mapping(&self, local_port: u16) -> anyhow::Result<SocketAddr>;
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TcpHolePunchAdmission {
    Client,
    Server,
}

fn bind_addr_for_port(port: u16, is_v6: bool) -> SocketAddr {
    if is_v6 {
        SocketAddr::new(IpAddr::V6(Ipv6Addr::UNSPECIFIED), port)
    } else {
        SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), port)
    }
}

pub async fn select_local_port<H>(host: &H, is_v6: bool) -> anyhow::Result<u16>
where
    H: VirtualTcpListenerFactory,
{
    let bind_addr = bind_addr_for_port(0, is_v6);
    tracing::trace!(?bind_addr, is_v6, "tcp hole punch select local port");
    let listener = host
        .bind_tcp(TcpListenOptions::hole_punch(bind_addr))
        .await?;
    let port = listener.local_addr()?.port();
    tracing::debug!(?bind_addr, port, "tcp hole punch selected local port");
    Ok(port)
}

// TCP supports simultaneous connect, so both peers may dial from the mapped port.
pub async fn try_connect_to_remote<H>(
    host: Arc<H>,
    peer_manager: Arc<PeerManagerCore>,
    remote_mapped_addr: SocketAddr,
    local_port: u16,
    admission: TcpHolePunchAdmission,
    max_attempts: u32,
) -> anyhow::Result<()>
where
    H: VirtualTcpSocketFactory,
{
    tracing::info!(
        ?remote_mapped_addr,
        local_port,
        "tcp hole punch server start connect loop"
    );

    let bind_addr = bind_addr_for_port(local_port, remote_mapped_addr.is_ipv6());
    let requested_url: url::Url = format!("tcp://{remote_mapped_addr}").parse().unwrap();

    let start = crate::runtime_time::Instant::now();
    let mut attempts = 0_u32;
    while start.elapsed() < Duration::from_secs(10) && attempts < max_attempts {
        attempts = attempts.wrapping_add(1);
        let bind = TcpBindOptions::default()
            .with_local_addr(Some(bind_addr))
            .with_only_v6(true);
        let options =
            TcpConnectOptions::hole_punch(remote_mapped_addr, Some(bind_addr)).with_bind(bind);
        if let Ok(Ok(socket)) =
            crate::runtime_time::timeout(Duration::from_secs(3), host.connect_tcp(options)).await
        {
            let tunnel = raw::upgrade_connected_tcp(socket, requested_url.clone())?;
            let admission_result = match admission {
                TcpHolePunchAdmission::Client => peer_manager
                    .add_client_tunnel(tunnel, false)
                    .await
                    .map(|_| ()),
                TcpHolePunchAdmission::Server => {
                    peer_manager.add_tunnel_as_server(tunnel, false).await
                }
            };
            if let Err(error) = admission_result {
                tracing::error!(
                    ?remote_mapped_addr,
                    local_port,
                    attempts,
                    ?error,
                    "tcp hole punch server connected and added client tunnel failed"
                );
                continue;
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
        crate::runtime_time::sleep(Duration::from_millis(sleep_ms)).await;
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

pub async fn accept_connections<L>(
    listener: Arc<L>,
    peer_manager: Arc<PeerManagerCore>,
    dst_peer_id: PeerId,
) -> anyhow::Result<()>
where
    L: VirtualTcpListener,
{
    loop {
        match listener.accept().await {
            Ok((socket, _)) => {
                let local_url = format!("tcp://0.0.0.0:{}", listener.local_addr()?.port())
                    .parse()
                    .unwrap();
                let tunnel = match raw::upgrade_accepted_tcp_with_local_url(socket, local_url) {
                    Ok(tunnel) => tunnel,
                    Err(error) => {
                        tracing::error!(?error, "tcp hole punch upgrade accepted socket error");
                        continue;
                    }
                };
                if let Err(error) = peer_manager.add_tunnel_as_server(tunnel, false).await {
                    tracing::error!(?error, "tcp hole punch add tunnel error");
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
    use super::*;

    #[test]
    fn bind_address_tracks_requested_family_and_port() {
        assert_eq!(
            bind_addr_for_port(1234, false),
            "0.0.0.0:1234".parse().unwrap()
        );
        assert_eq!(bind_addr_for_port(4321, true), "[::]:4321".parse().unwrap());
    }
}
