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
use std::time::Duration;
use reqwest::Client;
use trust_dns_resolver::{AsyncResolver};
use trust_dns_resolver::config::{ResolverConfig, ResolverOpts};
use url::Url;

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

    let old_url = url;
    let redirected_url = handle_url_type(url).await?; 
    let new_url = redirected_url.as_str(); 

    let url = url::Url::parse(new_url).map_err(|_| Error::InvalidUrl(new_url.to_owned()))?;
    
    let mut remote_url_original = HashMap::new();
    remote_url_original.insert(new_url.clone().to_string(), old_url.to_string());
    global_ctx.config.set_remote_url_original(remote_url_original);
    
    match url.scheme() {
        "tcp" => {
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
            check_scheme_and_get_socket_addr::<uuid::Uuid>(&url, "ring")?;
            let connector = RingTunnelConnector::new(url);
            return Ok(Box::new(connector));
        }
        #[cfg(feature = "quic")]
        "quic" => {
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
        _ => {
            return Err(Error::InvalidUrl(url.into()));
        }
    }
    
    pub async fn handle_url_type(original_url: &str) -> Result<String, Error> {
        if original_url.starts_with("http://") || original_url.starts_with("https://") {
            // 获取重定向后的 IP 与端口
            println!("handle http url：{}", original_url.to_string());
            let (host, port, query_type) = get_redirected_url(original_url).await?;
            println!("redirect http url：host：{}，port：{}，query_type:{}", host.clone().to_string(), port.clone().to_string(), query_type.clone().to_string());

            let redirected_url =  build_new_url_type(host, port, query_type).await?;
            return Ok(redirected_url);
        }
        if original_url.starts_with("txt://") {
            return Ok(get_txt_records(original_url.to_string()).await?);
        }
        Err(Error::InvalidUrl(original_url.into()))
    }

    pub async fn build_new_url_type(host: String, port: u16, query_type: String) -> Result<String, Error> {
        match query_type.as_str() {
            "tcp" => {
                // 处理 tcp 的逻辑
                let new_url_str = format!("tcp://{}:{}", host, port);
                Ok(new_url_str)
            },
            "udp" => {
                // 处理 udp 的逻辑
                let new_url_str = format!("udp://{}:{}", host, port);
                Ok(new_url_str)
            },
            "ws" => {
                let new_url_str = format!("ws://{}:{}", host, port);
                Ok(new_url_str)
            },
            "wss" => {
                let new_url_str = format!("wss://{}:{}", host, port);
                Ok(new_url_str)
            },
            _ => {
                // 默认情况，处理未知类型
                println!("{}: 未知类型的服务器地址：{} 请在重定向地址后面加 ?type=协议类型 （目前仅支持tcp udp ws wss）", chrono::Local::now().format("%Y-%m-%d %H:%M:%S"), query_type);
                Err(Error::InvalidUrl(query_type.into()))
            },
        }
    }

    pub async fn get_redirected_url(original_url: &str) -> Result<(String, u16, String), Error> {
        // 创建 HTTP 客户端，设置超时与重定向策略
        let client = Client::builder()
            .timeout(Duration::from_secs(30))
            // .redirect(reqwest::redirect::Policy::limited(3))
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .map_err(|e| Error::InvalidUrl(format!("building an http client failed: {}", e)))?;

        // 发送 HTTP 请求
        let response = client
            .get(original_url)
            .send()
            .await
            .map_err(|e| Error::InvalidUrl(format!("sending http request failed: {}", e)))?;

        // 获取重定向的 Location 头
        if let Some(location) = response.headers().get("Location") {
            let new_url = location
                .to_str()
                .map_err(|e| Error::InvalidUrl(format!("transformed Location failed: {}", e)))?;
            let parsed_url = Url::parse(new_url)
                .map_err(|e| Error::InvalidUrl(format!("resolve redirects url failed: {}", e)))?;

            // 提取主机和端口
            let host = parsed_url
                .host_str()
                .ok_or_else(|| Error::InvalidUrl("lack of hosts".to_string()))?
                .to_string();
            let port = parsed_url
                .port_or_known_default()
                .ok_or_else(|| Error::InvalidUrl("missing ports".to_string()))?;
            // 获取查询字符串，如果查询为空，则使用默认值 'type=tcp'
            let query = parsed_url.query()
                .map(|q| q.to_string())  // 如果有查询字符串，返回其字符串形式
                .unwrap_or_else(|| "type=tcp".to_string());  // 如果没有查询字符串，使用默认值
            let parsed_url = Url::parse(&format!("http://localhost?{}", query)).map_err(|e| Error::InvalidUrl(format!("parsing query failed: {}", e)))?;
            let query_type = parsed_url.query_pairs().find(|(key, _)| key == "type").map(|(_, value)| value.to_string()).unwrap_or_else(|| "unknown".to_string()).replace('/', "").to_lowercase();

            Ok((host, port, query_type))
        } else {
            Err(Error::InvalidUrl("no redirect address found".to_string()))
        }
    }

    pub async fn get_txt_records(original_url: String) -> Result<String, Error> {
        // 创建异步 DNS 解析器（以 tokio 为例）
        let resolver = AsyncResolver::tokio(ResolverConfig::default(), ResolverOpts::default()).map_err(|_| Error::InvalidUrl("Failed to create an asynchronous dns resolver".to_string()))?;

        // 异步查询 TXT 记录（注意这里的 .await）
        let txt_records = resolver.txt_lookup(original_url.replace("txt://", "")).await
            .map_err(|_| Error::InvalidUrl("Failed to get TXT records".to_string()))?;

        // 提取 TXT 记录中的字符串
        if let Some(txt_record) = txt_records.iter().next() {
            let txt_str = txt_record.to_string();

            // 判断是否是有效 URL
            if Url::parse(&txt_str).is_ok() {
                Ok(txt_str)
            } else {
                Err(Error::InvalidUrl("TXT record is not a valid URL".to_string()))
            }
        } else {
            Err(Error::InvalidUrl("No TXT records found".to_string()))
        }
    }
}



