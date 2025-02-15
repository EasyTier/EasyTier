use crate::common::config::ConfigLoader;
#[cfg(feature = "quic")]
use crate::tunnel::quic::QUICTunnelConnector;
#[cfg(feature = "wireguard")]
use crate::tunnel::wireguard::{WgConfig, WgTunnelConnector};
use crate::{
    common::{error::Error, global_ctx::ArcGlobalCtx, network::IPCollector},
    tunnel::{
        check_scheme_and_get_socket_addr, ring::RingTunnelConnector, tcp::TcpTunnelConnector,
        udp::UdpTunnelConnector, TunnelConnector,
    },
};
use std::collections::HashMap;
use std::{
    net::{SocketAddr, SocketAddrV4, SocketAddrV6},
    sync::Arc,
};
use url::Url;
use crate::connector::manual::ManualConnectorManager;

pub mod direct;
pub mod manual;
pub mod udp_hole_punch;

async fn set_bind_addr_for_peer_connector(
    connector: &mut (impl TunnelConnector + ?Sized),
    is_ipv4: bool,
    ip_collector: &Arc<IPCollector>,
) {
    if cfg!(target_os = "android") {
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
        for ipv6 in ips.interface_ipv6s {
            let socket_addr = SocketAddrV6::new(ipv6.into(), 0, 0, 0).into();
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
    let mut remote_url_original = HashMap::new();
    match url.scheme() {
        "tcp" => {
            remote_url_original.insert(url.clone().to_string(), url.clone().to_string());
            global_ctx.config.set_remote_url_original(remote_url_original);
            let dst_addr = check_scheme_and_get_socket_addr::<SocketAddr>(&url, "tcp")?;
            let mut connector = TcpTunnelConnector::new(url);
            if global_ctx.config.get_flags().bind_device {
                set_bind_addr_for_peer_connector(
                    &mut connector,
                    dst_addr.is_ipv4(),
                    &global_ctx.get_ip_collector(),
                )
                .await;
            }
            return Ok(Box::new(connector));
        }
        "udp" => {
            remote_url_original.insert(url.clone().to_string(), url.clone().to_string());
            global_ctx.config.set_remote_url_original(remote_url_original);
            let dst_addr = check_scheme_and_get_socket_addr::<SocketAddr>(&url, "udp")?;
            let mut connector = UdpTunnelConnector::new(url);
            if global_ctx.config.get_flags().bind_device {
                set_bind_addr_for_peer_connector(
                    &mut connector,
                    dst_addr.is_ipv4(),
                    &global_ctx.get_ip_collector(),
                )
                .await;
            }
            return Ok(Box::new(connector));
        }
        "ring" => {
            remote_url_original.insert(url.clone().to_string(), url.clone().to_string());
            global_ctx.config.set_remote_url_original(remote_url_original);
            check_scheme_and_get_socket_addr::<uuid::Uuid>(&url, "ring")?;
            let connector = RingTunnelConnector::new(url);
            return Ok(Box::new(connector));
        }
        #[cfg(feature = "quic")]
        "quic" => {
            remote_url_original.insert(url.clone().to_string(), url.clone().to_string());
            global_ctx.config.set_remote_url_original(remote_url_original);
            let dst_addr = check_scheme_and_get_socket_addr::<SocketAddr>(&url, "quic")?;
            let mut connector = QUICTunnelConnector::new(url);
            if global_ctx.config.get_flags().bind_device {
                set_bind_addr_for_peer_connector(
                    &mut connector,
                    dst_addr.is_ipv4(),
                    &global_ctx.get_ip_collector(),
                )
                .await;
            }
            return Ok(Box::new(connector));
        }
        #[cfg(feature = "wireguard")]
        "wg" => {
            remote_url_original.insert(url.clone().to_string(), url.clone().to_string());
            global_ctx.config.set_remote_url_original(remote_url_original);
            let dst_addr = check_scheme_and_get_socket_addr::<SocketAddr>(&url, "wg")?;
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
            return Ok(Box::new(connector));
        }
        #[cfg(feature = "websocket")]
        "ws" | "wss" => {
            remote_url_original.insert(url.clone().to_string(), url.clone().to_string());
            global_ctx.config.set_remote_url_original(remote_url_original);
            use crate::tunnel::{FromUrl, IpVersion};
            let dst_addr = SocketAddr::from_url(url.clone(), IpVersion::Both)?;
            let mut connector = crate::tunnel::websocket::WSTunnelConnector::new(url);
            if global_ctx.config.get_flags().bind_device {
                set_bind_addr_for_peer_connector(
                    &mut connector,
                    dst_addr.is_ipv4(),
                    &global_ctx.get_ip_collector(),
                )
                .await;
            }
            return Ok(Box::new(connector));
        }
        "http" => {
            // 获取重定向后的 IP 与端口
            println!("handle http url：{}",url.clone().to_string());
            let (ip, port, query_type) = ManualConnectorManager::get_redirected_url(url.as_str()).await?;
            println!("redirect http url：ip：{}，port：{}，query_type:{}", ip.clone().to_string(), port.clone().to_string(), query_type.clone().to_string());
            // 组装新的 TCP URL
            // todo 这里可以递归调用，但是不会写。
            return match query_type.as_str() {
                "tcp" => {
                    // 处理 tcp 的逻辑
                    let new_url_str = format!("tcp://{}:{}", ip, port);
                    let new_url = Url::parse(&new_url_str).map_err(|e| Error::InvalidUrl(format!("failed to resolve the new url: {}", e)))?;
                    println!("handle tcp type urls：{} to：{}",url.clone().to_string(), new_url.clone().to_string());
                    let dst_addr = check_scheme_and_get_socket_addr::<SocketAddr>(&new_url, "tcp")?;
                    remote_url_original.insert(new_url.clone().to_string(), url.clone().to_string());
                    global_ctx.config.set_remote_url_original(remote_url_original);
                    let mut connector = TcpTunnelConnector::new(new_url);

                    if global_ctx.config.get_flags().bind_device {
                        set_bind_addr_for_peer_connector(
                            &mut connector,
                            dst_addr.is_ipv4(),
                            &global_ctx.get_ip_collector(),
                        )
                            .await;
                    }
                    Ok(Box::new(connector))
                },
                "udp" => {
                    // 处理 udp 的逻辑
                    let new_url_str = format!("udp://{}:{}", ip, port);
                    let new_url = Url::parse(&new_url_str).map_err(|e| Error::InvalidUrl(format!("failed to resolve the new url: {}", e)))?;
                    println!("handle udp type urls：{} to：{}",url.clone().to_string(), new_url.clone().to_string());
                    remote_url_original.insert(new_url.clone().to_string(), url.clone().to_string());
                    global_ctx.config.set_remote_url_original(remote_url_original);
                    let dst_addr = check_scheme_and_get_socket_addr::<SocketAddr>(&new_url, "udp")?;
                    let mut connector = UdpTunnelConnector::new(new_url);
                    if global_ctx.config.get_flags().bind_device {
                        set_bind_addr_for_peer_connector(
                            &mut connector,
                            dst_addr.is_ipv4(),
                            &global_ctx.get_ip_collector(),
                        )
                            .await;
                    }
                    Ok(Box::new(connector))
                },
                "ws" => {
                    let new_url_str = format!("ws://{}:{}", ip, port);
                    let new_url = Url::parse(&new_url_str).map_err(|e| Error::InvalidUrl(format!("解析新 URL 失败: {}", e)))?;
                    println!("handle ws type urls：{} to：{}",url.clone().to_string(), new_url.clone().to_string());
                    remote_url_original.insert(new_url.clone().to_string(), url.clone().to_string());
                    global_ctx.config.set_remote_url_original(remote_url_original);
                    use crate::tunnel::{FromUrl, IpVersion};
                    let dst_addr = SocketAddr::from_url(new_url.clone(), IpVersion::Both)?;
                    let mut connector = crate::tunnel::websocket::WSTunnelConnector::new(new_url);
                    if global_ctx.config.get_flags().bind_device {
                        set_bind_addr_for_peer_connector(
                            &mut connector,
                            dst_addr.is_ipv4(),
                            &global_ctx.get_ip_collector(),
                        )
                            .await;
                    }
                    Ok(Box::new(connector))
                },
                "wss" => {
                    let new_url_str = format!("wss://{}:{}", ip, port);
                    let new_url = Url::parse(&new_url_str).map_err(|e| Error::InvalidUrl(format!("failed to resolve the new url: {}", e)))?;
                    println!("handle wss type urls：{} to：{}",url.clone().to_string(), new_url.clone().to_string());
                    remote_url_original.insert(new_url.clone().to_string(), url.clone().to_string());
                    global_ctx.config.set_remote_url_original(remote_url_original);
                    use crate::tunnel::{FromUrl, IpVersion};
                    let dst_addr = SocketAddr::from_url(new_url.clone(), IpVersion::Both)?;
                    let mut connector = crate::tunnel::websocket::WSTunnelConnector::new(new_url);
                    if global_ctx.config.get_flags().bind_device {
                        set_bind_addr_for_peer_connector(
                            &mut connector,
                            dst_addr.is_ipv4(),
                            &global_ctx.get_ip_collector(),
                        )
                            .await;
                    }
                    Ok(Box::new(connector))
                },
                _ => {
                    // 默认情况，处理未知类型
                    println!("unknown 302 type：{}", query_type);
                    Err(Error::InvalidUrl(url.into()))
                },
            }
        }
        _ => {
            return Err(Error::InvalidUrl(url.into()));
        }
    }
}
