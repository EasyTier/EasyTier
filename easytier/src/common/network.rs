#[cfg(target_os = "windows")]
use std::net::IpAddr;

#[cfg(target_os = "windows")]
use network_interface::{
    Addr as SystemAddr, NetworkInterface as SystemNetworkInterface, NetworkInterfaceConfig,
};
use pnet::datalink::NetworkInterface;
#[cfg(target_os = "windows")]
use pnet::{ipnetwork::IpNetwork, util::MacAddr};
#[cfg(all(target_os = "macos", not(feature = "macos-ne")))]
use tokio::sync::Mutex;

use crate::proto::peer_rpc::GetIpListResponse;

use super::netns::NetNS;

struct InterfaceFilter {
    iface: NetworkInterface,
}

#[cfg(any(
    target_os = "android",
    target_os = "ios",
    all(target_os = "macos", feature = "macos-ne"),
    target_env = "ohos"
))]
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

// Cache for networksetup command output
#[cfg(all(target_os = "macos", not(feature = "macos-ne")))]
static NETWORKSETUP_CACHE: std::sync::OnceLock<Mutex<(String, std::time::Instant)>> =
    std::sync::OnceLock::new();

#[cfg(any(
    all(target_os = "macos", not(feature = "macos-ne")),
    target_os = "freebsd"
))]
impl InterfaceFilter {
    #[cfg(all(target_os = "macos", not(feature = "macos-ne")))]
    async fn get_networksetup_output() -> String {
        use anyhow::Context;
        use std::time::{Duration, Instant};
        let cache = NETWORKSETUP_CACHE.get_or_init(|| Mutex::new((String::new(), Instant::now())));
        let mut cache_guard = cache.lock().await;

        // Check if cache is still valid (less than 1 minute old)
        if cache_guard.1.elapsed() < Duration::from_secs(60) && !cache_guard.0.is_empty() {
            return cache_guard.0.clone();
        }

        // Cache is expired or empty, fetch new data
        let stdout = tokio::process::Command::new("networksetup")
            .args(["-listallhardwareports"])
            .output()
            .await
            .with_context(|| "Failed to execute networksetup command")
            .and_then(|output| {
                std::str::from_utf8(&output.stdout)
                    .map(|s| s.to_string())
                    .with_context(|| "Failed to convert networksetup output to string")
            })
            .unwrap_or_else(|e| {
                tracing::error!("Failed to execute networksetup command: {:?}", e);
                String::new()
            });

        // Update cache
        cache_guard.0 = stdout.clone();
        cache_guard.1 = Instant::now();

        stdout
    }

    #[cfg(all(target_os = "macos", not(feature = "macos-ne")))]
    async fn is_interface_physical(&self) -> bool {
        let interface_name = &self.iface.name;
        let stdout = Self::get_networksetup_output().await;

        let lines: Vec<&str> = stdout.lines().collect();

        for i in 0..lines.len() {
            let line = lines[i];

            if line.contains("Device:") && line.contains(interface_name) {
                let next_line = lines[i + 1];
                return !next_line.contains("Virtual Interface");
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

pub(crate) async fn collect_interfaces(net_ns: NetNS, filter: bool) -> Vec<NetworkInterface> {
    #[cfg(target_os = "linux")]
    {
        return run_in_namespace(net_ns, move || async move {
            collect_interfaces_in_current_namespace(filter).await
        })
        .await;
    }

    #[cfg(not(target_os = "linux"))]
    {
        let _g = net_ns.guard();
        collect_interfaces_in_current_namespace(filter).await
    }
}

async fn collect_interfaces_in_current_namespace(filter: bool) -> Vec<NetworkInterface> {
    #[cfg(target_os = "windows")]
    let ifaces = collect_interfaces_windows();
    #[cfg(not(target_os = "windows"))]
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

#[cfg(target_os = "linux")]
async fn run_in_namespace<T, F, Fut>(net_ns: NetNS, operation: F) -> T
where
    T: Send + 'static,
    F: FnOnce() -> Fut + Send + 'static,
    Fut: std::future::Future<Output = T> + 'static,
{
    tokio::task::spawn_blocking(move || {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("build namespace-local runtime");
        net_ns.run(|| runtime.block_on(operation()))
    })
    .await
    .expect("namespace-local network operation panicked")
}

#[cfg(target_os = "windows")]
fn collect_interfaces_windows() -> Vec<NetworkInterface> {
    match SystemNetworkInterface::show() {
        Ok(ifaces) => ifaces.into_iter().map(convert_windows_interface).collect(),
        Err(e) => {
            tracing::warn!(
                ?e,
                "failed to enumerate interfaces via network-interface, falling back to pnet"
            );
            match std::panic::catch_unwind(pnet::datalink::interfaces) {
                Ok(ifaces) => ifaces,
                Err(_) => {
                    tracing::error!(
                        "failed to enumerate interfaces via both network-interface and pnet"
                    );
                    Vec::new()
                }
            }
        }
    }
}

#[cfg(target_os = "windows")]
fn convert_windows_interface(iface: SystemNetworkInterface) -> NetworkInterface {
    let mac = iface.mac_addr.as_deref().and_then(|mac| {
        mac.parse::<MacAddr>()
            .map_err(
                |e| tracing::debug!(iface = %iface.name, mac, ?e, "failed to parse interface mac"),
            )
            .ok()
    });

    let ips = iface
        .addr
        .into_iter()
        .filter_map(convert_windows_interface_addr)
        .collect();

    NetworkInterface {
        name: iface.name,
        description: String::new(),
        index: iface.index,
        mac,
        ips,
        // pnet does not populate Windows flags either, so keep the existing semantics.
        flags: 0,
    }
}

#[cfg(target_os = "windows")]
fn convert_windows_interface_addr(addr: SystemAddr) -> Option<IpNetwork> {
    match addr {
        SystemAddr::V4(addr) => {
            let netmask = addr
                .netmask
                .map(IpAddr::V4)
                .unwrap_or(IpAddr::V4(std::net::Ipv4Addr::new(255, 255, 255, 255)));
            IpNetwork::with_netmask(IpAddr::V4(addr.ip), netmask)
                .map_err(
                    |e| tracing::debug!(ip = %addr.ip, ?addr.netmask, ?e, "failed to convert ipv4"),
                )
                .ok()
        }
        SystemAddr::V6(addr) => {
            let netmask = addr
                .netmask
                .map(IpAddr::V6)
                .unwrap_or(IpAddr::V6(std::net::Ipv6Addr::from(u128::MAX)));
            IpNetwork::with_netmask(IpAddr::V6(addr.ip), netmask)
                .map_err(
                    |e| tracing::debug!(ip = %addr.ip, ?addr.netmask, ?e, "failed to convert ipv6"),
                )
                .ok()
        }
    }
}

#[tracing::instrument(skip(net_ns))]
pub(crate) async fn collect_local_ip_addrs(net_ns: NetNS) -> GetIpListResponse {
    #[cfg(target_os = "linux")]
    {
        return run_in_namespace(net_ns, || async {
            collect_local_ip_addrs_in_current_namespace().await
        })
        .await;
    }

    #[cfg(not(target_os = "linux"))]
    {
        let _g = net_ns.guard();
        collect_local_ip_addrs_in_current_namespace().await
    }
}

async fn collect_local_ip_addrs_in_current_namespace() -> GetIpListResponse {
    let mut ret = GetIpListResponse::default();

    let ifaces = collect_interfaces_in_current_namespace(true).await;
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

    let ifaces = collect_interfaces_in_current_namespace(false).await;
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

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(target_os = "linux")]
    #[tokio::test]
    async fn namespace_operation_does_not_migrate_between_os_threads() {
        let (before, after) = run_in_namespace(NetNS::new(None), || async {
            let before = std::thread::current().id();
            tokio::task::yield_now().await;
            (before, std::thread::current().id())
        })
        .await;

        assert_eq!(before, after);
    }
}
