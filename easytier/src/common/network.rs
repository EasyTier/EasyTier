use std::{collections::HashMap, net::IpAddr};

use network_interface::{NetworkInterface, NetworkInterfaceConfig};
#[cfg(all(target_os = "macos", not(feature = "macos-ne")))]
use tokio::sync::Mutex;

use crate::proto::peer_rpc::GetIpListResponse;

use super::netns::NetNS;

#[derive(Clone, Copy, Debug, Default)]
struct InterfaceState {
    is_point_to_point: bool,
    is_loopback: bool,
    is_up: bool,
    #[cfg(target_os = "linux")]
    is_lower_up: bool,
}

#[cfg(any(
    all(target_os = "linux", not(target_env = "ohos")),
    all(target_os = "macos", not(feature = "macos-ne")),
    target_os = "freebsd"
))]
fn collect_interface_states() -> HashMap<String, InterfaceState> {
    let mut states = HashMap::new();
    if let Ok(interfaces) = nix::ifaddrs::getifaddrs() {
        use nix::net::if_::InterfaceFlags;

        for interface in interfaces {
            let flags = interface.flags;
            #[cfg(target_os = "linux")]
            let is_lower_up = flags.contains(InterfaceFlags::IFF_LOWER_UP);
            states.insert(
                interface.interface_name,
                InterfaceState {
                    is_point_to_point: flags.contains(InterfaceFlags::IFF_POINTOPOINT),
                    is_loopback: flags.contains(InterfaceFlags::IFF_LOOPBACK),
                    is_up: flags.contains(InterfaceFlags::IFF_UP),
                    #[cfg(target_os = "linux")]
                    is_lower_up,
                },
            );
        }
    }
    states
}

#[cfg(not(any(
    all(target_os = "linux", not(target_env = "ohos")),
    all(target_os = "macos", not(feature = "macos-ne")),
    target_os = "freebsd"
)))]
fn collect_interface_states() -> HashMap<String, InterfaceState> {
    HashMap::new()
}

#[cfg(any(target_os = "freebsd", target_os = "windows"))]
fn has_nonzero_mac(iface: &NetworkInterface) -> bool {
    iface.mac_addr.as_deref().is_some_and(|mac| {
        let mut octets = mac.split([':', '-']);
        let mut nonzero = false;
        for _ in 0..6 {
            let Some(value) = octets
                .next()
                .and_then(|octet| u8::from_str_radix(octet, 16).ok())
            else {
                return false;
            };
            nonzero |= value != 0;
        }
        octets.next().is_none() && nonzero
    })
}

#[allow(dead_code)]
pub(crate) fn ip_mask_to_prefix(mask: IpAddr) -> Result<u8, ()> {
    match mask {
        IpAddr::V4(mask) => {
            let raw = u32::from(mask);
            let prefix = raw.leading_ones() as u8;
            let expected = if prefix == 0 {
                0
            } else {
                u32::MAX << (32 - prefix)
            };
            (raw == expected).then_some(prefix).ok_or(())
        }
        IpAddr::V6(mask) => {
            let raw = u128::from(mask);
            let prefix = raw.leading_ones() as u8;
            let expected = if prefix == 0 {
                0
            } else {
                u128::MAX << (128 - prefix)
            };
            (raw == expected).then_some(prefix).ok_or(())
        }
    }
}

struct InterfaceFilter {
    iface: NetworkInterface,
    state: InterfaceState,
}

fn interface_state(
    iface: &NetworkInterface,
    states: &HashMap<String, InterfaceState>,
) -> InterfaceState {
    states.get(&iface.name).copied().unwrap_or(InterfaceState {
        is_loopback: iface.internal,
        is_up: true,
        #[cfg(target_os = "linux")]
        is_lower_up: true,
        ..Default::default()
    })
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
            .addr
            .iter()
            .map(|ip| ip.ip())
            .any(|ip| !ip.is_loopback() && !ip.is_unspecified() && !ip.is_multicast())
    }

    async fn filter_iface(&self) -> bool {
        tracing::trace!(
            "filter linux iface: {:?}, is_point_to_point: {}, is_loopback: {}, is_up: {}, is_lower_up: {}, is_tun: {}, has_valid_ip: {}",
            self.iface,
            self.state.is_point_to_point,
            self.state.is_loopback,
            self.state.is_up,
            self.state.is_lower_up,
            self.is_tun_tap_device().await,
            self.has_valid_ip().await
        );

        !self.state.is_point_to_point
            && !self.state.is_loopback
            && self.state.is_up
            && self.state.is_lower_up
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
        has_nonzero_mac(&self.iface)
    }

    async fn filter_iface(&self) -> bool {
        !self.state.is_point_to_point
            && !self.state.is_loopback
            && self.state.is_up
            && self.is_interface_physical().await
    }
}

#[cfg(target_os = "windows")]
impl InterfaceFilter {
    async fn filter_iface(&self) -> bool {
        tracing::debug!(
            "iface_name: {:?}, p2p: {:?}, is_up: {:?}, iface: {:?}",
            self.iface.name,
            self.state.is_point_to_point,
            self.state.is_up,
            self.iface
        );
        !self.state.is_point_to_point
            && !self.state.is_loopback
            && self
                .iface
                .addr
                .iter()
                .map(|ip| ip.ip())
                .any(|ip| !ip.is_loopback() && !ip.is_unspecified() && !ip.is_multicast())
            && has_nonzero_mac(&self.iface)
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
        run_in_namespace(net_ns, move || async move {
            collect_interfaces_in_current_namespace(filter).await
        })
        .await
    }

    #[cfg(not(target_os = "linux"))]
    {
        let _g = net_ns.guard();
        collect_interfaces_in_current_namespace(filter).await
    }
}

#[cfg(feature = "faketcp")]
fn convert_pnet_interface(iface: pnet_datalink::NetworkInterface) -> NetworkInterface {
    let internal = iface.is_loopback();
    let addr = iface
        .ips
        .into_iter()
        .filter_map(|network| match (network.ip(), network.mask()) {
            (IpAddr::V4(ip), IpAddr::V4(netmask)) => {
                Some(network_interface::Addr::V4(network_interface::V4IfAddr {
                    ip,
                    broadcast: None,
                    netmask: Some(netmask),
                }))
            }
            (IpAddr::V6(ip), IpAddr::V6(netmask)) => {
                Some(network_interface::Addr::V6(network_interface::V6IfAddr {
                    ip,
                    broadcast: None,
                    netmask: Some(netmask),
                }))
            }
            _ => None,
        })
        .collect();
    NetworkInterface {
        name: iface.name,
        addr,
        mac_addr: iface.mac.map(|mac| mac.to_string()),
        index: iface.index,
        internal,
    }
}

async fn collect_interfaces_in_current_namespace(filter: bool) -> Vec<NetworkInterface> {
    let ifaces = match NetworkInterface::show() {
        Ok(ifaces) => ifaces,
        Err(error) => {
            tracing::warn!(?error, "failed to enumerate network interfaces");
            #[cfg(feature = "faketcp")]
            {
                match std::panic::catch_unwind(pnet_datalink::interfaces) {
                    Ok(ifaces) => ifaces.into_iter().map(convert_pnet_interface).collect(),
                    Err(_) => {
                        tracing::error!(
                            "failed to enumerate network interfaces via network-interface and pnet"
                        );
                        return Vec::new();
                    }
                }
            }
            #[cfg(not(feature = "faketcp"))]
            return Vec::new();
        }
    };
    let states = collect_interface_states();
    let mut ret = vec![];
    for iface in ifaces {
        let f = InterfaceFilter {
            iface: iface.clone(),
            state: interface_state(&iface, &states),
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
        for ip in iface.addr {
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
        for ip in iface.addr {
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

    #[test]
    fn converts_contiguous_ip_masks_to_prefixes() {
        assert_eq!(
            ip_mask_to_prefix(IpAddr::V4("255.255.254.0".parse().unwrap())),
            Ok(23)
        );
        assert_eq!(
            ip_mask_to_prefix(IpAddr::V6("ffff:ffff:ffff:ffff::".parse().unwrap())),
            Ok(64)
        );
        assert_eq!(
            ip_mask_to_prefix(IpAddr::V4("255.0.255.0".parse().unwrap())),
            Err(())
        );
    }

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
