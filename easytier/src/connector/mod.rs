use std::{
    net::{SocketAddr, SocketAddrV4, SocketAddrV6},
    sync::Arc,
};

use http_connector::HttpTunnelConnector;

#[cfg(feature = "quic")]
use crate::tunnel::quic::QUICTunnelConnector;
#[cfg(feature = "wireguard")]
use crate::tunnel::wireguard::{WgConfig, WgTunnelConnector};
use crate::{
    common::{error::Error, global_ctx::ArcGlobalCtx, network::IPCollector},
    tunnel::{
        check_scheme_and_get_socket_addr, ring::RingTunnelConnector, tcp::TcpTunnelConnector,
        udp::UdpTunnelConnector, IpVersion, TunnelConnector,
    },
};

pub mod direct;
pub mod manual;
pub mod udp_hole_punch;

pub mod dns_connector;
pub mod http_connector;

async fn set_bind_addr_for_peer_connector(
    connector: &mut (impl TunnelConnector + ?Sized),
    is_ipv4: bool,
    ip_collector: &Arc<IPCollector>,
) {
    if cfg!(any(target_os = "android", target_env = "ohos")) {
        return;
    }

    let ips = ip_collector.collect_ip_addrs().await;
    if is_ipv4 {
        let mut bind_addrs = vec![];
        for ipv4 in ips.interface_ipv4s {
            let socket_addr = SocketAddrV4::new(ipv4.into(), 0).into();
            bind_addrs.push(socket_addr);
        }
        connector.set_bind_addrs(bind_addrs);
    } else {
        let mut bind_addrs = vec![];
        for ipv6 in ips.interface_ipv6s.iter().chain(ips.public_ipv6.iter()) {
            let socket_addr = SocketAddrV6::new(std::net::Ipv6Addr::from(*ipv6), 0, 0, 0).into();
            bind_addrs.push(socket_addr);
        }
        connector.set_bind_addrs(bind_addrs);
    }
    let _ = connector;
}

pub async fn create_connector_by_url(
    url: &str,
    global_ctx: &ArcGlobalCtx,
    ip_version: IpVersion,
) -> Result<Box<dyn TunnelConnector + 'static>, Error> {
    let url = url::Url::parse(url).map_err(|_| Error::InvalidUrl(url.to_owned()))?;
    let mut connector: Box<dyn TunnelConnector + 'static> = match url.scheme() {
        "tcp" => {
            let dst_addr =
                check_scheme_and_get_socket_addr::<SocketAddr>(&url, "tcp", ip_version).await?;
            let mut connector = TcpTunnelConnector::new(url);
            if global_ctx.config.get_flags().bind_device {
                set_bind_addr_for_peer_connector(
                    &mut connector,
                    dst_addr.is_ipv4(),
                    &global_ctx.get_ip_collector(),
                )
                .await;
            }
            Box::new(connector)
        }
        "udp" => {
            let dst_addr =
                check_scheme_and_get_socket_addr::<SocketAddr>(&url, "udp", ip_version).await?;
            let mut connector = UdpTunnelConnector::new(url);
            if global_ctx.config.get_flags().bind_device {
                set_bind_addr_for_peer_connector(
                    &mut connector,
                    dst_addr.is_ipv4(),
                    &global_ctx.get_ip_collector(),
                )
                .await;
            }
            Box::new(connector)
        }
        "http" | "https" => {
            let connector = HttpTunnelConnector::new(url, global_ctx.clone());
            Box::new(connector)
        }
        "ring" => {
            check_scheme_and_get_socket_addr::<uuid::Uuid>(&url, "ring", IpVersion::Both).await?;
            let connector = RingTunnelConnector::new(url);
            Box::new(connector)
        }
        #[cfg(feature = "quic")]
        "quic" => {
            let dst_addr =
                check_scheme_and_get_socket_addr::<SocketAddr>(&url, "quic", ip_version).await?;
            let mut connector = QUICTunnelConnector::new(url);
            if global_ctx.config.get_flags().bind_device {
                set_bind_addr_for_peer_connector(
                    &mut connector,
                    dst_addr.is_ipv4(),
                    &global_ctx.get_ip_collector(),
                )
                .await;
            }
            Box::new(connector)
        }
        #[cfg(feature = "wireguard")]
        "wg" => {
            let dst_addr =
                check_scheme_and_get_socket_addr::<SocketAddr>(&url, "wg", ip_version).await?;
            let nid = global_ctx.get_network_identity();
            let wg_config = WgConfig::new_from_network_identity(
                &nid.network_name,
                &nid.network_secret.unwrap_or_default(),
            );
            let mut connector = WgTunnelConnector::new(url, wg_config);
            if global_ctx.config.get_flags().bind_device {
                set_bind_addr_for_peer_connector(
                    &mut connector,
                    dst_addr.is_ipv4(),
                    &global_ctx.get_ip_collector(),
                )
                .await;
            }
            Box::new(connector)
        }
        #[cfg(feature = "websocket")]
        "ws" | "wss" => {
            use crate::tunnel::FromUrl;
            let dst_addr = SocketAddr::from_url(url.clone(), ip_version).await?;
            let mut connector = crate::tunnel::websocket::WSTunnelConnector::new(url);
            if global_ctx.config.get_flags().bind_device {
                set_bind_addr_for_peer_connector(
                    &mut connector,
                    dst_addr.is_ipv4(),
                    &global_ctx.get_ip_collector(),
                )
                .await;
            }
            Box::new(connector)
        }
        "txt" | "srv" => {
            if url.host_str().is_none() {
                return Err(Error::InvalidUrl(format!(
                    "host should not be empty in txt or srv url: {}",
                    url
                )));
            }
            let connector = dns_connector::DNSTunnelConnector::new(url, global_ctx.clone());
            Box::new(connector)
        }
        _ => {
            return Err(Error::InvalidUrl(url.into()));
        }
    };
    connector.set_ip_version(ip_version);

    Ok(connector)
}
