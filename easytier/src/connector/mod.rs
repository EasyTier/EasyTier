use std::{
    net::{SocketAddr, SocketAddrV4, SocketAddrV6},
    sync::Arc,
};

use crate::{
    common::{error::Error, global_ctx::ArcGlobalCtx, network::IPCollector},
    tunnel::{
        quic::QUICTunnelConnector,
        ring::RingTunnelConnector,
        tcp::TcpTunnelConnector,
        udp::UdpTunnelConnector,
        wireguard::{WgConfig, WgTunnelConnector},
        TunnelConnector,
    },
};

pub mod direct;
pub mod manual;
pub mod udp_hole_punch;

async fn set_bind_addr_for_peer_connector(
    connector: &mut (impl TunnelConnector + ?Sized),
    is_ipv4: bool,
    ip_collector: &Arc<IPCollector>,
) {
    let ips = ip_collector.collect_ip_addrs().await;
    if is_ipv4 {
        let mut bind_addrs = vec![];
        for ipv4 in ips.interface_ipv4s {
            let socket_addr = SocketAddrV4::new(ipv4.parse().unwrap(), 0).into();
            bind_addrs.push(socket_addr);
        }
        connector.set_bind_addrs(bind_addrs);
    } else {
        let mut bind_addrs = vec![];
        for ipv6 in ips.interface_ipv6s {
            let socket_addr = SocketAddrV6::new(ipv6.parse().unwrap(), 0, 0, 0).into();
            bind_addrs.push(socket_addr);
        }
        connector.set_bind_addrs(bind_addrs);
    }
    let _ = connector;
}

pub async fn create_connector_by_url(
    url: &str,
    global_ctx: &ArcGlobalCtx,
) -> Result<Box<dyn TunnelConnector + 'static>, Error> {
    let url = url::Url::parse(url).map_err(|_| Error::InvalidUrl(url.to_owned()))?;
    match url.scheme() {
        "tcp" => {
            let dst_addr =
                crate::tunnels::check_scheme_and_get_socket_addr::<SocketAddr>(&url, "tcp")?;
            let mut connector = TcpTunnelConnector::new(url);
            set_bind_addr_for_peer_connector(
                &mut connector,
                dst_addr.is_ipv4(),
                &global_ctx.get_ip_collector(),
            )
            .await;
            return Ok(Box::new(connector));
        }
        "udp" => {
            let dst_addr =
                crate::tunnels::check_scheme_and_get_socket_addr::<SocketAddr>(&url, "udp")?;
            let mut connector = UdpTunnelConnector::new(url);
            set_bind_addr_for_peer_connector(
                &mut connector,
                dst_addr.is_ipv4(),
                &global_ctx.get_ip_collector(),
            )
            .await;
            return Ok(Box::new(connector));
        }
        "ring" => {
            crate::tunnels::check_scheme_and_get_socket_addr::<uuid::Uuid>(&url, "ring")?;
            let connector = RingTunnelConnector::new(url);
            return Ok(Box::new(connector));
        }
        "quic" => {
            let dst_addr =
                crate::tunnels::check_scheme_and_get_socket_addr::<SocketAddr>(&url, "quic")?;
            let mut connector = QUICTunnelConnector::new(url);
            set_bind_addr_for_peer_connector(
                &mut connector,
                dst_addr.is_ipv4(),
                &global_ctx.get_ip_collector(),
            )
            .await;
            return Ok(Box::new(connector));
        }
        "wg" => {
            let dst_addr =
                crate::tunnels::check_scheme_and_get_socket_addr::<SocketAddr>(&url, "wg")?;
            let nid = global_ctx.get_network_identity();
            let wg_config =
                WgConfig::new_from_network_identity(&nid.network_name, &nid.network_secret);
            let mut connector = WgTunnelConnector::new(url, wg_config);
            set_bind_addr_for_peer_connector(
                &mut connector,
                dst_addr.is_ipv4(),
                &global_ctx.get_ip_collector(),
            )
            .await;
            return Ok(Box::new(connector));
        }
        _ => {
            return Err(Error::InvalidUrl(url.into()));
        }
    }
}
