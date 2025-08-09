use std::{net::IpAddr, ops::Deref, sync::Arc};

use pnet::datalink::NetworkInterface;
use tokio::{
    sync::{Mutex, RwLock},
    task::JoinSet,
};

use crate::proto::peer_rpc::GetIpListResponse;

use super::{netns::NetNS, stun::StunInfoCollectorTrait};

pub const CACHED_IP_LIST_TIMEOUT_SEC: u64 = 60;

struct InterfaceFilter {
    iface: NetworkInterface,
}

#[cfg(any(target_os = "android", target_env = "ohos"))]
impl InterfaceFilter {
    async fn filter_iface(&self) -> bool {
        true
    }
}

#[cfg(all(target_os = "linux", not(target_env = "ohos")))]
impl InterfaceFilter {
    async fn is_tun_tap_device(&self) -> bool {
        let path = format!("/sys/class/net/{}/tun_flags", self.iface.name);
        tokio::fs::metadata(&path).await.is_ok()
    }

    async fn has_valid_ip(&self) -> bool {
        self.iface
            .ips
            .iter()
            .map(|ip| ip.ip())
            .any(|ip| !ip.is_loopback() && !ip.is_unspecified() && !ip.is_multicast())
    }

    async fn filter_iface(&self) -> bool {
        tracing::trace!(
            "filter linux iface: {:?}, is_point_to_point: {}, is_loopback: {}, is_up: {}, is_lower_up: {}, is_tun: {}, has_valid_ip: {}",
            self.iface,
            self.iface.is_point_to_point(),
            self.iface.is_loopback(),
            self.iface.is_up(),
            self.iface.is_lower_up(),
            self.is_tun_tap_device().await,
            self.has_valid_ip().await
        );

        !self.iface.is_point_to_point()
            && !self.iface.is_loopback()
            && self.iface.is_up()
            && self.iface.is_lower_up()
            && !self.is_tun_tap_device().await
            && self.has_valid_ip().await
    }
}

#[cfg(any(target_os = "macos", target_os = "freebsd"))]
impl InterfaceFilter {
    #[cfg(target_os = "macos")]
    async fn is_interface_physical(&self) -> bool {
        let interface_name = &self.iface.name;
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

    #[cfg(target_os = "freebsd")]
    async fn is_interface_physical(&self) -> bool {
        // if mac addr is not zero, then it's physical interface
        self.iface.mac.map(|mac| !mac.is_zero()).unwrap_or(false)
    }

    async fn filter_iface(&self) -> bool {
        !self.iface.is_point_to_point()
            && !self.iface.is_loopback()
            && self.iface.is_up()
            && self.is_interface_physical().await
    }
}

#[cfg(target_os = "windows")]
impl InterfaceFilter {
    async fn filter_iface(&self) -> bool {
        tracing::debug!(
            "iface_name: {:?}, p2p: {:?}, is_up: {:?}, iface: {:?}",
            self.iface.name,
            self.iface.is_point_to_point(),
            self.iface.is_up(),
            self.iface
        );
        !self.iface.is_point_to_point()
            && !self.iface.is_loopback()
            && self
                .iface
                .ips
                .iter()
                .map(|ip| ip.ip())
                .any(|ip| !ip.is_loopback() && !ip.is_unspecified() && !ip.is_multicast())
            && self.iface.mac.map(|mac| !mac.is_zero()).unwrap_or(false)
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
    stun_info_collector: Arc<Box<dyn StunInfoCollectorTrait>>,
}

impl IPCollector {
    pub fn new<T: StunInfoCollectorTrait + 'static>(net_ns: NetNS, stun_info_collector: T) -> Self {
        Self {
            cached_ip_list: Arc::new(RwLock::new(GetIpListResponse::default())),
            collect_ip_task: Mutex::new(JoinSet::new()),
            net_ns,
            stun_info_collector: Arc::new(Box::new(stun_info_collector)),
        }
    }

    pub async fn collect_ip_addrs(&self) -> GetIpListResponse {
        let mut task = self.collect_ip_task.lock().await;
        if task.is_empty() {
            let cached_ip_list = self.cached_ip_list.clone();
            *cached_ip_list.write().await =
                Self::do_collect_local_ip_addrs(self.net_ns.clone()).await;
            let net_ns = self.net_ns.clone();
            let stun_info_collector = self.stun_info_collector.clone();
            let cached_ip_list = self.cached_ip_list.clone();
            task.spawn(async move {
                let mut last_fetch_iface_time = std::time::Instant::now();
                loop {
                    if last_fetch_iface_time.elapsed().as_secs() > CACHED_IP_LIST_TIMEOUT_SEC {
                        let ifaces = Self::do_collect_local_ip_addrs(net_ns.clone()).await;
                        *cached_ip_list.write().await = ifaces;
                        last_fetch_iface_time = std::time::Instant::now();
                    }

                    let stun_info = stun_info_collector.get_stun_info();
                    for ip in stun_info.public_ip.iter() {
                        let Ok(ip_addr) = ip.parse::<IpAddr>() else {
                            continue;
                        };

                        match ip_addr {
                            IpAddr::V4(v) => {
                                cached_ip_list.write().await.public_ipv4.replace(v.into());
                            }
                            IpAddr::V6(v) => {
                                cached_ip_list.write().await.public_ipv6.replace(v.into());
                            }
                        }
                    }

                    tracing::debug!(
                        "got public ip: {:?}, {:?}",
                        cached_ip_list.read().await.public_ipv4,
                        cached_ip_list.read().await.public_ipv6
                    );

                    let sleep_sec = if cached_ip_list.read().await.public_ipv4.is_some() {
                        CACHED_IP_LIST_TIMEOUT_SEC
                    } else {
                        3
                    };
                    tokio::time::sleep(std::time::Duration::from_secs(sleep_sec)).await;
                }
            });
        }

        self.cached_ip_list.read().await.deref().clone()
    }

    pub async fn collect_interfaces(net_ns: NetNS, filter: bool) -> Vec<NetworkInterface> {
        let _g = net_ns.guard();
        let ifaces = pnet::datalink::interfaces();
        let mut ret = vec![];
        for iface in ifaces {
            let f = InterfaceFilter {
                iface: iface.clone(),
            };

            if filter && !f.filter_iface().await {
                continue;
            }

            ret.push(iface);
        }

        ret
    }

    #[tracing::instrument(skip(net_ns))]
    async fn do_collect_local_ip_addrs(net_ns: NetNS) -> GetIpListResponse {
        let mut ret = GetIpListResponse::default();

        let ifaces = Self::collect_interfaces(net_ns.clone(), true).await;
        let _g = net_ns.guard();
        for iface in ifaces {
            for ip in iface.ips {
                let ip: std::net::IpAddr = ip.ip();
                if let std::net::IpAddr::V4(v4) = ip {
                    if ip.is_loopback() || ip.is_multicast() {
                        continue;
                    }
                    ret.interface_ipv4s.push(v4.into());
                }
            }
        }

        let ifaces = Self::collect_interfaces(net_ns.clone(), false).await;
        let _g = net_ns.guard();
        for iface in ifaces {
            for ip in iface.ips {
                let ip: std::net::IpAddr = ip.ip();
                if let std::net::IpAddr::V6(v6) = ip {
                    if v6.is_multicast() || v6.is_loopback() || v6.is_unicast_link_local() {
                        continue;
                    }
                    ret.interface_ipv6s.push(v6.into());
                }
            }
        }

        if let Ok(v4_addr) = local_ipv4().await {
            tracing::trace!("got local ipv4: {}", v4_addr);
            if !ret.interface_ipv4s.contains(&v4_addr.into()) {
                ret.interface_ipv4s.push(v4_addr.into());
            }
        }

        if let Ok(v6_addr) = local_ipv6().await {
            tracing::trace!("got local ipv6: {}", v6_addr);
            if !ret.interface_ipv6s.contains(&v6_addr.into()) {
                ret.interface_ipv6s.push(v6_addr.into());
            }
        }

        ret
    }
}
