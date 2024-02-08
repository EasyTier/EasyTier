use std::{ops::Deref, sync::Arc};

use crate::rpc::peer::GetIpListResponse;
use pnet::datalink::NetworkInterface;
use tokio::{
    sync::{Mutex, RwLock},
    task::JoinSet,
};

use super::{constants::DIRECT_CONNECTOR_IP_LIST_TIMEOUT_SEC, netns::NetNS};

struct InterfaceFilter {
    iface: NetworkInterface,
}

#[cfg(target_os = "linux")]
impl InterfaceFilter {
    async fn is_iface_bridge(&self) -> bool {
        let path = format!("/sys/class/net/{}/bridge", self.iface.name);
        tokio::fs::metadata(&path).await.is_ok()
    }

    async fn is_iface_phsical(&self) -> bool {
        let path = format!("/sys/class/net/{}/device", self.iface.name);
        tokio::fs::metadata(&path).await.is_ok()
    }

    async fn filter_iface(&self) -> bool {
        tracing::trace!(
            "filter linux iface: {:?}, is_point_to_point: {}, is_loopback: {}, is_up: {}, is_lower_up: {}, is_bridge: {}, is_physical: {}",
            self.iface,
            self.iface.is_point_to_point(),
            self.iface.is_loopback(),
            self.iface.is_up(),
            self.iface.is_lower_up(),
            self.is_iface_bridge().await,
            self.is_iface_phsical().await,
        );

        !self.iface.is_point_to_point()
            && !self.iface.is_loopback()
            && self.iface.is_up()
            && self.iface.is_lower_up()
            && (self.is_iface_bridge().await || self.is_iface_phsical().await)
    }
}

#[cfg(target_os = "macos")]
impl InterfaceFilter {
    async fn is_interface_physical(interface_name: &str) -> bool {
        let output = tokio::process::Command::new("networksetup")
            .args(&["-listallhardwareports"])
            .output()
            .await
            .expect("Failed to execute command");

        let stdout = std::str::from_utf8(&output.stdout).expect("Invalid UTF-8");

        let lines: Vec<&str> = stdout.lines().collect();

        for i in 0..lines.len() {
            let line = lines[i];

            if line.contains("Device:") && line.contains(interface_name) {
                let next_line = lines[i + 1];
                if next_line.contains("Virtual Interface") {
                    return false;
                } else {
                    return true;
                }
            }
        }

        false
    }

    async fn filter_iface(&self) -> bool {
        !self.iface.is_point_to_point()
            && !self.iface.is_loopback()
            && self.iface.is_up()
            && Self::is_interface_physical(&self.iface.name).await
    }
}

#[cfg(target_os = "windows")]
impl InterfaceFilter {
    async fn filter_iface(&self) -> bool {
        !self.iface.is_point_to_point() && !self.iface.is_loopback() && self.iface.is_up()
    }
}

pub async fn local_ipv4() -> std::io::Result<std::net::Ipv4Addr> {
    let socket = tokio::net::UdpSocket::bind("0.0.0.0:0").await?;
    socket.connect("8.8.8.8:80").await?;
    let addr = socket.local_addr()?;
    match addr.ip() {
        std::net::IpAddr::V4(ip) => Ok(ip),
        std::net::IpAddr::V6(_) => Err(std::io::Error::new(
            std::io::ErrorKind::AddrNotAvailable,
            "no ipv4 address",
        )),
    }
}

pub async fn local_ipv6() -> std::io::Result<std::net::Ipv6Addr> {
    let socket = tokio::net::UdpSocket::bind("[::]:0").await?;
    socket
        .connect("[2001:4860:4860:0000:0000:0000:0000:8888]:80")
        .await?;
    let addr = socket.local_addr()?;
    match addr.ip() {
        std::net::IpAddr::V6(ip) => Ok(ip),
        std::net::IpAddr::V4(_) => Err(std::io::Error::new(
            std::io::ErrorKind::AddrNotAvailable,
            "no ipv4 address",
        )),
    }
}

pub struct IPCollector {
    cached_ip_list: Arc<RwLock<GetIpListResponse>>,
    collect_ip_task: Mutex<JoinSet<()>>,
    net_ns: NetNS,
}

impl IPCollector {
    pub fn new(net_ns: NetNS) -> Self {
        Self {
            cached_ip_list: Arc::new(RwLock::new(GetIpListResponse::new())),
            collect_ip_task: Mutex::new(JoinSet::new()),
            net_ns,
        }
    }

    pub async fn collect_ip_addrs(&self) -> GetIpListResponse {
        let mut task = self.collect_ip_task.lock().await;
        if task.is_empty() {
            let cached_ip_list = self.cached_ip_list.clone();
            *cached_ip_list.write().await =
                Self::do_collect_ip_addrs(false, self.net_ns.clone()).await;
            let net_ns = self.net_ns.clone();
            task.spawn(async move {
                loop {
                    let ip_addrs = Self::do_collect_ip_addrs(true, net_ns.clone()).await;
                    *cached_ip_list.write().await = ip_addrs;
                    tokio::time::sleep(std::time::Duration::from_secs(
                        DIRECT_CONNECTOR_IP_LIST_TIMEOUT_SEC,
                    ))
                    .await;
                }
            });
        }

        return self.cached_ip_list.read().await.deref().clone();
    }

    #[tracing::instrument(skip(net_ns))]
    async fn do_collect_ip_addrs(with_public: bool, net_ns: NetNS) -> GetIpListResponse {
        let mut ret = crate::rpc::peer::GetIpListResponse {
            public_ipv4: "".to_string(),
            interface_ipv4s: vec![],
            public_ipv6: "".to_string(),
            interface_ipv6s: vec![],
        };

        if with_public {
            if let Some(v4_addr) =
                public_ip::addr_with(public_ip::http::ALL, public_ip::Version::V4).await
            {
                ret.public_ipv4 = v4_addr.to_string();
            }

            if let Some(v6_addr) = public_ip::addr_v6().await {
                ret.public_ipv6 = v6_addr.to_string();
            }
        }

        let _g = net_ns.guard();
        let ifaces = pnet::datalink::interfaces();
        for iface in ifaces {
            let f = InterfaceFilter {
                iface: iface.clone(),
            };

            if !f.filter_iface().await {
                continue;
            }

            for ip in iface.ips {
                let ip: std::net::IpAddr = ip.ip();
                if ip.is_loopback() || ip.is_multicast() {
                    continue;
                }
                if ip.is_ipv4() {
                    ret.interface_ipv4s.push(ip.to_string());
                } else if ip.is_ipv6() {
                    ret.interface_ipv6s.push(ip.to_string());
                }
            }
        }

        if let Ok(v4_addr) = local_ipv4().await {
            tracing::trace!("got local ipv4: {}", v4_addr);
            if !ret.interface_ipv4s.contains(&v4_addr.to_string()) {
                ret.interface_ipv4s.push(v4_addr.to_string());
            }
        }

        if let Ok(v6_addr) = local_ipv6().await {
            tracing::trace!("got local ipv6: {}", v6_addr);
            if !ret.interface_ipv6s.contains(&v6_addr.to_string()) {
                ret.interface_ipv6s.push(v6_addr.to_string());
            }
        }

        ret
    }
}
