use std::{net::SocketAddr, sync::Arc};

use futures::stream::FuturesUnordered;
use url::Url;

use crate::{
    proto::common::TunnelInfo,
    socket::udp::{
        UdpBindOptions, UdpSession, UdpSessionControlHandler, UdpSessionLayer, UdpSessionSocket,
        VirtualUdpSocketFactory,
    },
    tunnel::{Tunnel, TunnelError, udp::UdpTunnelUpgrader},
};

use super::first_success;

type SessionLayer<H> = UdpSessionLayer<<H as VirtualUdpSocketFactory>::Socket, H, H>;

pub(super) async fn connect_and_upgrade<H>(
    host: Arc<H>,
    remote_addr: SocketAddr,
    bind_addrs: Vec<SocketAddr>,
    default_bind: UdpBindOptions,
    requested_remote_addr: Url,
) -> anyhow::Result<Box<dyn Tunnel>>
where
    H: VirtualUdpSocketFactory + UdpSessionControlHandler<<H as VirtualUdpSocketFactory>::Socket>,
{
    let futures = FuturesUnordered::new();
    if bind_addrs.is_empty() {
        let local_addr = if remote_addr.is_ipv4() {
            "0.0.0.0:0".parse().expect("static IPv4 bind address")
        } else {
            "[::]:0".parse().expect("static IPv6 bind address")
        };
        let bind = default_bind
            .with_local_addr(Some(local_addr))
            .with_only_v6(true);
        futures.push(bind_and_connect(host.clone(), bind, remote_addr));
    } else {
        for bind_addr in bind_addrs {
            let bind = default_bind
                .clone()
                .with_local_addr(Some(bind_addr))
                .with_only_v6(true);
            futures.push(bind_and_connect(host.clone(), bind, remote_addr));
        }
    }
    let (layer, session) = first_success(futures).await?;
    upgrade_connected_session(session, layer, requested_remote_addr).map_err(Into::into)
}

async fn bind_and_connect<H>(
    host: Arc<H>,
    bind: UdpBindOptions,
    remote_addr: SocketAddr,
) -> anyhow::Result<(Arc<SessionLayer<H>>, UdpSession)>
where
    H: VirtualUdpSocketFactory + UdpSessionControlHandler<<H as VirtualUdpSocketFactory>::Socket>,
{
    let socket = host.bind_udp(bind).await?;
    let layer = Arc::new(
        UdpSessionLayer::new_with_control_handler_and_stun_responder(socket, host.clone(), host),
    );
    let session = layer.connect(remote_addr).await?;
    Ok((layer, session))
}

fn upgrade_connected_session<H>(
    session: UdpSession,
    layer: Arc<SessionLayer<H>>,
    requested_remote_addr: Url,
) -> Result<Box<dyn Tunnel>, TunnelError>
where
    H: VirtualUdpSocketFactory + UdpSessionControlHandler<<H as VirtualUdpSocketFactory>::Socket>,
{
    let info = connected_tunnel_info(
        session.local_addr()?,
        session.peer_addr()?,
        requested_remote_addr,
    );
    UdpTunnelUpgrader::with_keep_alive(info, layer).upgrade(session)
}

pub fn upgrade_accepted_session(session: UdpSession) -> Result<Box<dyn Tunnel>, TunnelError> {
    let info = accepted_tunnel_info(session.local_addr()?, session.peer_addr()?);
    UdpTunnelUpgrader::new(info).upgrade(session)
}

fn connected_tunnel_info(
    local_addr: SocketAddr,
    resolved_remote_addr: SocketAddr,
    requested_remote_addr: Url,
) -> TunnelInfo {
    TunnelInfo {
        tunnel_type: "udp".to_owned(),
        local_addr: Some(udp_url(local_addr).into()),
        remote_addr: Some(requested_remote_addr.into()),
        resolved_remote_addr: Some(udp_url(resolved_remote_addr).into()),
    }
}

fn accepted_tunnel_info(local_addr: SocketAddr, remote_addr: SocketAddr) -> TunnelInfo {
    let remote_url = udp_url(remote_addr);
    TunnelInfo {
        tunnel_type: "udp".to_owned(),
        local_addr: Some(udp_url(local_addr).into()),
        remote_addr: Some(remote_url.clone().into()),
        resolved_remote_addr: Some(remote_url.into()),
    }
}

fn udp_url(addr: SocketAddr) -> Url {
    let mut url = Url::parse("udp://0.0.0.0").expect("static UDP URL should be valid");
    url.set_ip_host(addr.ip())
        .expect("socket IP should be a valid URL host");
    url.set_port(Some(addr.port()))
        .expect("UDP URL should accept a port");
    url
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn udp_tunnel_metadata_preserves_requested_and_resolved_addresses() {
        let local_addr: SocketAddr = "127.0.0.1:1000".parse().unwrap();
        let peer_addr: SocketAddr = "127.0.0.1:2000".parse().unwrap();
        let requested_url: Url = "udp://example.com:2000".parse().unwrap();

        let connected = connected_tunnel_info(local_addr, peer_addr, requested_url.clone());
        assert_eq!(connected.remote_addr.unwrap().url, requested_url.as_str());
        let connected_resolved: Url = connected.resolved_remote_addr.unwrap().into();
        assert_eq!(connected_resolved.host_str(), Some("127.0.0.1"));
        assert_eq!(connected_resolved.port(), Some(2000));

        let accepted = accepted_tunnel_info(local_addr, peer_addr);
        assert_eq!(accepted.remote_addr, accepted.resolved_remote_addr);
    }
}
