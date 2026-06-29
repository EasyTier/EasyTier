#[cfg(target_os = "linux")]
use std::path::Path;
use std::sync::Arc;

#[cfg(target_os = "linux")]
use anyhow::Context;
use cidr::{Ipv6Cidr, Ipv6Inet};
#[cfg(target_os = "linux")]
use netlink_packet_route::route::{RouteAddress, RouteAttribute, RouteMessage, RouteType};
use tokio_util::sync::CancellationToken;

#[cfg(target_os = "linux")]
use crate::common::ifcfg::{
    add_ipv6_ndp_proxy, get_interface_index, list_ipv6_ndp_proxy, list_ipv6_route_messages,
    remove_ipv6_ndp_proxy,
};
use crate::common::{
    error::Error,
    global_ctx::{ArcGlobalCtx, GlobalCtxEvent},
    netns::NetNS,
};

const PUBLIC_IPV6_PROVIDER_RECONCILE_INTERVAL: std::time::Duration =
    std::time::Duration::from_secs(5);
const PUBLIC_IPV6_PROVIDER_RECONCILE_MAX_RETRIES: usize = 3;

#[cfg(target_os = "linux")]
#[derive(Debug, Clone, PartialEq, Eq)]
struct NdpProxyTarget {
    wan_iface: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct PublicIpv6ProviderActiveState {
    prefix: Ipv6Cidr,
    #[cfg(target_os = "linux")]
    ndp_proxy: Option<NdpProxyTarget>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum PublicIpv6ProviderRuntimeState {
    Disabled,
    Pending(String),
    Active(PublicIpv6ProviderActiveState),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct PublicIpv6ProviderConfigSnapshot {
    provider_enabled: bool,
    configured_prefix: Option<Ipv6Cidr>,
}

fn read_public_ipv6_provider_config_snapshot(
    global_ctx: &ArcGlobalCtx,
) -> PublicIpv6ProviderConfigSnapshot {
    PublicIpv6ProviderConfigSnapshot {
        provider_enabled: global_ctx.config.get_ipv6_public_addr_provider(),
        configured_prefix: global_ctx.config.get_ipv6_public_addr_prefix(),
    }
}

fn should_run_public_ipv6_provider_reconcile_task(
    config: PublicIpv6ProviderConfigSnapshot,
) -> bool {
    config.provider_enabled
}

pub(super) fn should_run_public_ipv6_provider_reconcile(global_ctx: &ArcGlobalCtx) -> bool {
    should_run_public_ipv6_provider_reconcile_task(read_public_ipv6_provider_config_snapshot(
        global_ctx,
    ))
}

fn is_global_routable_public_ipv6_prefix(prefix: Ipv6Cidr) -> bool {
    let addr = prefix.first_address();
    !addr.is_loopback()
        && !addr.is_multicast()
        && !addr.is_unicast_link_local()
        && !addr.is_unique_local()
        && !addr.is_unspecified()
}

pub(super) fn validate_public_ipv6_config_values(
    _ipv6: Option<Ipv6Inet>,
    provider_enabled: bool,
    _auto_enabled: bool,
    prefix: Option<Ipv6Cidr>,
) -> Result<(), Error> {
    if !provider_enabled {
        return Ok(());
    }

    ensure_public_ipv6_provider_supported()?;

    if let Some(prefix) = prefix
        && !is_global_routable_public_ipv6_prefix(prefix)
    {
        return Err(anyhow::anyhow!(
            "the prefix {} is not a valid global unicast IPv6 prefix; it must be a routable address range, not a private, link-local, or multicast address",
            prefix
        )
        .into());
    }

    Ok(())
}

pub(super) fn validate_public_ipv6_config(global_ctx: &ArcGlobalCtx) -> Result<(), Error> {
    validate_public_ipv6_config_values(
        global_ctx.get_ipv6(),
        global_ctx.config.get_ipv6_public_addr_provider(),
        global_ctx.config.get_ipv6_public_addr_auto(),
        global_ctx.config.get_ipv6_public_addr_prefix(),
    )
}

fn ensure_public_ipv6_provider_supported() -> Result<(), Error> {
    if cfg!(target_os = "linux") {
        return Ok(());
    }

    Err(anyhow::anyhow!(
        "the provider feature requires Linux; run without --ipv6-public-addr-provider on this node, or move the provider role to a Linux node. client mode (--ipv6-public-addr-auto) works on all platforms"
    )
    .into())
}

fn public_ipv6_provider_auto_detect_error() -> Error {
    anyhow::anyhow!(
        "no public IPv6 prefix found on this system; set --ipv6-public-addr-prefix manually, or check that your ISP has delegated an IPv6 prefix and a default-from route exists in the kernel routing table"
    )
    .into()
}

#[cfg(target_os = "linux")]
fn read_linux_proc_bool(path: &Path) -> Result<bool, Error> {
    let value = std::fs::read_to_string(path)
        .with_context(|| format!("failed to read {}", path.display()))?;
    match value.trim() {
        "0" => Ok(false),
        "1" => Ok(true),
        other => Err(anyhow::anyhow!("unexpected value '{}' in {}", other, path.display()).into()),
    }
}

#[cfg(target_os = "linux")]
fn write_linux_proc_bool(path: &Path, enabled: bool) -> Result<(), Error> {
    let value = if enabled { "1\n" } else { "0\n" };
    std::fs::write(path, value).with_context(|| format!("failed to write {}", path.display()))?;
    Ok(())
}

#[cfg(target_os = "linux")]
fn ensure_linux_ipv6_forwarding_at_paths(
    all_path: &Path,
    default_path: &Path,
) -> Result<bool, Error> {
    let all_enabled = read_linux_proc_bool(all_path)?;
    let default_enabled = read_linux_proc_bool(default_path)?;
    let mut changed = false;

    if !all_enabled {
        write_linux_proc_bool(all_path, true)?;
        changed = true;
    }

    if !default_enabled {
        write_linux_proc_bool(default_path, true)?;
        changed = true;
    }

    if !read_linux_proc_bool(all_path)? || !read_linux_proc_bool(default_path)? {
        return Err(anyhow::anyhow!(
            "failed to enable Linux IPv6 forwarding in {} and {}",
            all_path.display(),
            default_path.display()
        )
        .into());
    }

    Ok(changed)
}

#[cfg(target_os = "linux")]
fn ensure_linux_ipv6_forwarding() -> Result<bool, Error> {
    let all_path = Path::new("/proc/sys/net/ipv6/conf/all/forwarding");
    let default_path = Path::new("/proc/sys/net/ipv6/conf/default/forwarding");

    ensure_linux_ipv6_forwarding_at_paths(all_path, default_path).map_err(|err| {
        anyhow::anyhow!(
            "public IPv6 provider requires Linux IPv6 forwarding; failed to enable net.ipv6.conf.all.forwarding=1 and net.ipv6.conf.default.forwarding=1 automatically: {}. run with sufficient privileges or set them manually",
            err
        )
        .into()
    })
}

#[cfg(target_os = "linux")]
#[derive(Clone, Debug, PartialEq, Eq)]
struct DetectedIpv6Route {
    dst: Option<Ipv6Cidr>,
    src: Option<Ipv6Cidr>,
    ifindex: Option<u32>,
    kind: RouteType,
}

#[cfg(target_os = "linux")]
#[derive(Clone, Debug, PartialEq, Eq)]
struct DetectedPublicIpv6Prefix {
    prefix: Ipv6Cidr,
    ndp_proxy: Option<NdpProxyTarget>,
}

#[cfg(target_os = "linux")]
fn ipv6_cidr_from_route_addr(addr: RouteAddress, prefix_len: u8) -> Option<Ipv6Cidr> {
    match addr {
        RouteAddress::Inet6(addr) => Ipv6Cidr::new(addr, prefix_len).ok(),
        _ => None,
    }
}

#[cfg(target_os = "linux")]
impl TryFrom<RouteMessage> for DetectedIpv6Route {
    type Error = Error;

    fn try_from(message: RouteMessage) -> Result<Self, Self::Error> {
        let dst = message.attributes.iter().find_map(|attr| match attr {
            RouteAttribute::Destination(addr) => {
                ipv6_cidr_from_route_addr(addr.clone(), message.header.destination_prefix_length)
            }
            _ => None,
        });
        let src = message.attributes.iter().find_map(|attr| match attr {
            RouteAttribute::Source(addr) => {
                ipv6_cidr_from_route_addr(addr.clone(), message.header.source_prefix_length)
            }
            _ => None,
        });
        let ifindex = message.attributes.iter().find_map(|attr| match attr {
            RouteAttribute::Oif(index) => Some(*index),
            _ => None,
        });

        Ok(Self {
            dst,
            src,
            ifindex,
            kind: message.header.kind,
        })
    }
}

#[cfg(target_os = "linux")]
fn is_ipv6_default_route(dst: Option<Ipv6Cidr>) -> bool {
    dst.is_none() || dst == Some(Ipv6Cidr::new(std::net::Ipv6Addr::UNSPECIFIED, 0).unwrap())
}

#[cfg(target_os = "linux")]
fn detect_public_ipv6_prefix_from_routes(
    routes: &[DetectedIpv6Route],
    loopback_ifindex: u32,
) -> Option<DetectedPublicIpv6Prefix> {
    routes
        .iter()
        .filter_map(|route| {
            if !is_ipv6_default_route(route.dst) || route.kind != RouteType::Unicast {
                return None;
            }

            let prefix = route.src?;
            let wan_ifindex = route.ifindex?;
            if !is_global_routable_public_ipv6_prefix(prefix) {
                return None;
            }

            let delegated = routes.iter().any(|candidate| {
                candidate.dst == Some(prefix)
                    && candidate.ifindex.is_some()
                    && candidate.ifindex != Some(wan_ifindex)
                    && candidate.ifindex != Some(loopback_ifindex)
                    && candidate.kind == RouteType::Unicast
            });

            delegated.then_some(DetectedPublicIpv6Prefix {
                prefix,
                ndp_proxy: None,
            })
        })
        .min_by_key(|detected| detected.prefix.network_length())
}

#[cfg(target_os = "linux")]
#[derive(Clone, Debug, PartialEq, Eq)]
struct DetectedDefaultRouteIpv6Interface {
    interface_name: String,
    ifindex: u32,
    address: std::net::Ipv6Addr,
    prefix: Ipv6Cidr,
}

#[cfg(target_os = "linux")]
#[derive(Clone, Debug, PartialEq, Eq)]
struct DefaultRouteIpv6InterfaceCandidate {
    interface_name: String,
    ifindex: u32,
    address: std::net::Ipv6Addr,
    prefix_len: u8,
}

#[cfg(target_os = "linux")]
fn default_route_ifindices(routes: &[DetectedIpv6Route]) -> std::collections::BTreeSet<u32> {
    routes
        .iter()
        .filter(|route| is_ipv6_default_route(route.dst) && route.kind == RouteType::Unicast)
        .filter_map(|route| route.ifindex)
        .collect()
}

#[cfg(target_os = "linux")]
fn select_default_route_ipv6_interfaces(
    candidates: impl IntoIterator<Item = DefaultRouteIpv6InterfaceCandidate>,
    wan_ifindices: &std::collections::BTreeSet<u32>,
    max_prefix_len: u8,
) -> Vec<DetectedDefaultRouteIpv6Interface> {
    candidates
        .into_iter()
        .filter_map(|candidate| {
            if !wan_ifindices.contains(&candidate.ifindex) {
                return None;
            }

            if candidate.address.is_loopback()
                || candidate.address.is_multicast()
                || candidate.address.is_unicast_link_local()
                || candidate.address.is_unique_local()
                || candidate.address.is_unspecified()
            {
                return None;
            }

            if candidate.prefix_len == 0 || candidate.prefix_len > max_prefix_len {
                return None;
            }

            let prefix = Ipv6Inet::new(candidate.address, candidate.prefix_len)
                .ok()
                .map(|inet| inet.network())?;

            Some(DetectedDefaultRouteIpv6Interface {
                interface_name: candidate.interface_name,
                ifindex: candidate.ifindex,
                address: candidate.address,
                prefix,
            })
        })
        .collect()
}

#[cfg(target_os = "linux")]
fn detect_default_route_ipv6_interfaces(
    routes: &[DetectedIpv6Route],
    max_prefix_len: u8,
) -> Vec<DetectedDefaultRouteIpv6Interface> {
    use nix::ifaddrs::getifaddrs;
    use nix::sys::socket::SockaddrLike;
    use pnet::ipnetwork::ip_mask_to_prefix;

    let wan_ifindices = default_route_ifindices(routes);
    if wan_ifindices.is_empty() {
        return Vec::new();
    }

    let Ok(interfaces) = getifaddrs() else {
        return Vec::new();
    };

    let candidates = interfaces
        .filter_map(|iface| {
            let address = iface.address?;
            let netmask = iface.netmask?;
            let ifindex = get_interface_index(&iface.interface_name).ok()?;

            if address.family()? != nix::sys::socket::AddressFamily::Inet6 {
                return None;
            }

            let ipv6_addr = address.as_sockaddr_in6()?.ip();
            let netmask_ip = netmask.as_sockaddr_in6()?.ip();
            let prefix_len = ip_mask_to_prefix(std::net::IpAddr::V6(netmask_ip)).ok()?;

            Some(DefaultRouteIpv6InterfaceCandidate {
                interface_name: iface.interface_name,
                ifindex,
                address: ipv6_addr,
                prefix_len,
            })
        })
        .collect::<Vec<_>>();

    select_default_route_ipv6_interfaces(candidates, &wan_ifindices, max_prefix_len)
}

#[cfg(target_os = "linux")]
fn select_public_ipv6_prefix_from_default_route_interfaces(
    candidates: impl IntoIterator<Item = DetectedDefaultRouteIpv6Interface>,
) -> Option<DetectedPublicIpv6Prefix> {
    let iface = candidates
        .into_iter()
        .min_by_key(|iface| (iface.prefix.network_length(), iface.ifindex))?;
    Some(DetectedPublicIpv6Prefix {
        prefix: iface.prefix,
        ndp_proxy: Some(NdpProxyTarget {
            wan_iface: iface.interface_name,
        }),
    })
}

#[cfg(target_os = "linux")]
fn detect_public_ipv6_prefix_from_interfaces(
    routes: &[DetectedIpv6Route],
) -> Option<DetectedPublicIpv6Prefix> {
    select_public_ipv6_prefix_from_default_route_interfaces(detect_default_route_ipv6_interfaces(
        routes, 64,
    ))
}

#[cfg(target_os = "linux")]
fn ipv6_cidr_contains_cidr(outer: Ipv6Cidr, inner: Ipv6Cidr) -> bool {
    outer.contains(&inner.first_address()) && outer.contains(&inner.last_address())
}

#[cfg(target_os = "linux")]
fn detect_configured_prefix_ndp_proxy_target(
    routes: &[DetectedIpv6Route],
    prefix: Ipv6Cidr,
) -> Option<NdpProxyTarget> {
    let wan_ifindices = default_route_ifindices(routes);
    if wan_ifindices.is_empty() {
        return None;
    }

    let loopback_ifindex = get_interface_index("lo").ok();
    let routed = routes.iter().any(|route| {
        route.dst == Some(prefix)
            && route.kind == RouteType::Unicast
            && route.ifindex.is_some_and(|ifindex| {
                !wan_ifindices.contains(&ifindex) && Some(ifindex) != loopback_ifindex
            })
    });
    if routed {
        return None;
    }

    detect_default_route_ipv6_interfaces(routes, 128)
        .into_iter()
        .filter(|iface| {
            ipv6_cidr_contains_cidr(iface.prefix, prefix)
                || (iface.prefix.network_length() == 128 && prefix.contains(&iface.address))
        })
        .min_by_key(|iface| (iface.prefix.network_length(), iface.ifindex))
        .map(|iface| NdpProxyTarget {
            wan_iface: iface.interface_name,
        })
}

#[cfg(target_os = "linux")]
fn list_detected_ipv6_routes() -> Result<Vec<DetectedIpv6Route>, Error> {
    let routes = list_ipv6_route_messages().with_context(|| "failed to query linux ipv6 routes")?;
    routes
        .iter()
        .cloned()
        .map(DetectedIpv6Route::try_from)
        .collect::<Result<Vec<_>, _>>()
}

#[cfg(target_os = "linux")]
async fn detect_public_ipv6_prefix_linux() -> Result<Option<DetectedPublicIpv6Prefix>, Error> {
    let routes = list_detected_ipv6_routes()?;
    let loopback_ifindex =
        get_interface_index("lo").with_context(|| "failed to resolve linux loopback ifindex")?;

    if let Some(prefix) = detect_public_ipv6_prefix_from_routes(&routes, loopback_ifindex) {
        return Ok(Some(prefix));
    }

    // Fallback for DHCPv6 IA_NA / SLAAC — see https://github.com/EasyTier/EasyTier/issues/2333
    Ok(detect_public_ipv6_prefix_from_interfaces(&routes))
}

#[cfg(not(target_os = "linux"))]
async fn detect_public_ipv6_prefix_linux() -> Result<Option<Ipv6Cidr>, Error> {
    Ok(None)
}

fn invalid_public_ipv6_prefix_state(
    prefix: Ipv6Cidr,
    source: &str,
) -> PublicIpv6ProviderRuntimeState {
    PublicIpv6ProviderRuntimeState::Pending(format!(
        "the {} prefix {} is not a valid global unicast IPv6 prefix",
        source, prefix
    ))
}

#[cfg(target_os = "linux")]
fn active_public_ipv6_provider_state(
    prefix: Ipv6Cidr,
    ndp_proxy: Option<NdpProxyTarget>,
) -> PublicIpv6ProviderRuntimeState {
    PublicIpv6ProviderRuntimeState::Active(PublicIpv6ProviderActiveState { prefix, ndp_proxy })
}

#[cfg(not(target_os = "linux"))]
fn active_public_ipv6_provider_state(prefix: Ipv6Cidr) -> PublicIpv6ProviderRuntimeState {
    PublicIpv6ProviderRuntimeState::Active(PublicIpv6ProviderActiveState { prefix })
}

#[cfg(target_os = "linux")]
async fn resolve_public_ipv6_provider_runtime_state_linux(
    global_ctx: &ArcGlobalCtx,
    configured_prefix: Option<Ipv6Cidr>,
) -> PublicIpv6ProviderRuntimeState {
    let _g = global_ctx.net_ns.guard();

    if let Err(err) = ensure_linux_ipv6_forwarding() {
        return PublicIpv6ProviderRuntimeState::Pending(err.to_string());
    }

    if let Some(prefix) = configured_prefix {
        if !is_global_routable_public_ipv6_prefix(prefix) {
            return invalid_public_ipv6_prefix_state(prefix, "configured");
        }
        let ndp_proxy = match list_detected_ipv6_routes() {
            Ok(routes) => detect_configured_prefix_ndp_proxy_target(&routes, prefix),
            Err(err) => {
                tracing::warn!(
                    prefix = %prefix,
                    ?err,
                    "failed to detect NDP proxy target for configured public IPv6 prefix"
                );
                None
            }
        };
        return active_public_ipv6_provider_state(prefix, ndp_proxy);
    }

    match detect_public_ipv6_prefix_linux().await {
        Ok(Some(detected)) if is_global_routable_public_ipv6_prefix(detected.prefix) => {
            active_public_ipv6_provider_state(detected.prefix, detected.ndp_proxy)
        }
        Ok(Some(detected)) => invalid_public_ipv6_prefix_state(detected.prefix, "detected"),
        Ok(None) => PublicIpv6ProviderRuntimeState::Pending(
            public_ipv6_provider_auto_detect_error().to_string(),
        ),
        Err(err) => PublicIpv6ProviderRuntimeState::Pending(err.to_string()),
    }
}

async fn resolve_public_ipv6_provider_runtime_state(
    _global_ctx: &ArcGlobalCtx,
    config: PublicIpv6ProviderConfigSnapshot,
) -> PublicIpv6ProviderRuntimeState {
    if !config.provider_enabled {
        return PublicIpv6ProviderRuntimeState::Disabled;
    }

    #[cfg(target_os = "linux")]
    {
        return resolve_public_ipv6_provider_runtime_state_linux(
            _global_ctx,
            config.configured_prefix,
        )
        .await;
    }

    #[cfg(not(target_os = "linux"))]
    {
        let _ = config.configured_prefix;
        PublicIpv6ProviderRuntimeState::Pending(
            ensure_public_ipv6_provider_supported()
                .unwrap_err()
                .to_string(),
        )
    }
}

fn apply_public_ipv6_provider_runtime_state(
    global_ctx: &ArcGlobalCtx,
    state: &PublicIpv6ProviderRuntimeState,
) -> bool {
    let next_prefix = match state {
        PublicIpv6ProviderRuntimeState::Active(active) => Some(active.prefix),
        PublicIpv6ProviderRuntimeState::Disabled | PublicIpv6ProviderRuntimeState::Pending(_) => {
            None
        }
    };
    let prefix_changed = global_ctx.set_advertised_ipv6_public_addr_prefix(next_prefix);

    let next_provider_enabled = matches!(state, PublicIpv6ProviderRuntimeState::Active(_));
    let feature_changed =
        global_ctx.set_ipv6_public_addr_provider_feature_flag(next_provider_enabled);

    prefix_changed || feature_changed
}

fn try_apply_public_ipv6_provider_runtime_state(
    global_ctx: &ArcGlobalCtx,
    config: PublicIpv6ProviderConfigSnapshot,
    state: &PublicIpv6ProviderRuntimeState,
) -> Option<bool> {
    (read_public_ipv6_provider_config_snapshot(global_ctx) == config)
        .then(|| apply_public_ipv6_provider_runtime_state(global_ctx, state))
}

fn current_public_ipv6_provider_runtime_state(
    global_ctx: &ArcGlobalCtx,
) -> PublicIpv6ProviderRuntimeState {
    match (
        global_ctx.get_feature_flags().ipv6_public_addr_provider,
        global_ctx.get_advertised_ipv6_public_addr_prefix(),
    ) {
        (false, _) => PublicIpv6ProviderRuntimeState::Disabled,
        #[cfg(target_os = "linux")]
        (true, Some(prefix)) => active_public_ipv6_provider_state(prefix, None),
        #[cfg(not(target_os = "linux"))]
        (true, Some(prefix)) => active_public_ipv6_provider_state(prefix),
        (true, None) => PublicIpv6ProviderRuntimeState::Pending(
            "public IPv6 provider runtime is missing an advertised prefix".to_string(),
        ),
    }
}

async fn reconcile_public_ipv6_provider_runtime_with_state(
    global_ctx: &ArcGlobalCtx,
) -> (PublicIpv6ProviderRuntimeState, bool) {
    for attempt in 0..PUBLIC_IPV6_PROVIDER_RECONCILE_MAX_RETRIES {
        let config = read_public_ipv6_provider_config_snapshot(global_ctx);
        let next_state = resolve_public_ipv6_provider_runtime_state(global_ctx, config).await;

        if let Some(changed) =
            try_apply_public_ipv6_provider_runtime_state(global_ctx, config, &next_state)
        {
            return (next_state, changed);
        }

        tracing::debug!(
            attempt = attempt + 1,
            max_retries = PUBLIC_IPV6_PROVIDER_RECONCILE_MAX_RETRIES,
            "public IPv6 provider config changed during reconcile, retrying"
        );
    }

    tracing::warn!(
        max_retries = PUBLIC_IPV6_PROVIDER_RECONCILE_MAX_RETRIES,
        "skipping public IPv6 provider reconcile because config kept changing"
    );
    (
        current_public_ipv6_provider_runtime_state(global_ctx),
        false,
    )
}

pub(super) async fn reconcile_public_ipv6_provider_runtime(global_ctx: &ArcGlobalCtx) -> bool {
    reconcile_public_ipv6_provider_runtime_with_state(global_ctx)
        .await
        .1
}

#[cfg(target_os = "linux")]
#[derive(Default)]
struct NdpProxyRuntime {
    wan_iface: Option<String>,
    applied: std::collections::BTreeSet<std::net::Ipv6Addr>,
}

#[cfg(target_os = "linux")]
impl NdpProxyRuntime {
    fn reconcile(
        &mut self,
        global_ctx: &ArcGlobalCtx,
        state: &PublicIpv6ProviderRuntimeState,
    ) -> bool {
        let Some((prefix, target)) = ndp_proxy_target(state) else {
            return !self.clear_current(global_ctx);
        };

        let Some(tun_iface) = global_ctx.get_tun_device_name() else {
            self.clear_current(global_ctx);
            tracing::debug!("waiting for tun device before syncing NDP proxy entries");
            return self.cleanup_pending();
        };

        let _g = global_ctx.net_ns.guard();

        if self.wan_iface.as_deref() != Some(target.wan_iface.as_str()) {
            if !self.clear_current_locked() {
                tracing::warn!(
                    old_wan_iface = ?self.wan_iface,
                    new_wan_iface = %target.wan_iface,
                    remaining_entries = self.applied.len(),
                    "waiting to remove old NDP proxy entries before switching WAN interface"
                );
                return true;
            }
            self.wan_iface = Some(target.wan_iface.clone());
        }

        if let Err(err) = sync_ndp_proxy_entries(
            target.wan_iface.as_str(),
            tun_iface.as_str(),
            prefix,
            &mut self.applied,
        ) {
            tracing::warn!(
                wan_iface = %target.wan_iface,
                tun_iface = %tun_iface,
                ?err,
                "failed to sync NDP proxy entries"
            );
        }
        self.cleanup_pending()
    }

    fn clear_current(&mut self, global_ctx: &ArcGlobalCtx) -> bool {
        self.clear_current_in_netns(&global_ctx.net_ns)
    }

    fn clear_current_in_netns(&mut self, net_ns: &NetNS) -> bool {
        let _g = net_ns.guard();
        self.clear_current_locked()
    }

    fn clear_current_locked(&mut self) -> bool {
        let Some(wan_iface) = self.wan_iface.clone() else {
            return self.applied.is_empty();
        };

        match list_ipv6_ndp_proxy(wan_iface.as_str()) {
            Ok(current) => {
                let candidates = self.applied.iter().copied().collect::<Vec<_>>();
                clear_owned_ndp_proxy_entries(
                    wan_iface.as_str(),
                    &current,
                    &mut self.applied,
                    candidates,
                );
            }
            Err(err) if is_linux_missing_netlink_object_error(&err) => {
                tracing::trace!(
                    wan_iface = %wan_iface,
                    ?err,
                    "forgetting NDP proxy ownership because WAN interface is gone"
                );
                self.applied.clear();
            }
            Err(err) => {
                tracing::trace!(
                    wan_iface = %wan_iface,
                    ?err,
                    "failed to list NDP proxy entries before cleanup"
                );
            }
        }

        if self.applied.is_empty() {
            self.wan_iface = None;
            true
        } else {
            false
        }
    }

    fn cleanup_pending(&self) -> bool {
        self.wan_iface.is_some() && !self.applied.is_empty()
    }
}

#[cfg(target_os = "linux")]
fn is_linux_missing_netlink_object_error(err: &Error) -> bool {
    match err {
        Error::IOError(err) => {
            err.kind() == std::io::ErrorKind::NotFound
                || matches!(
                    err.raw_os_error(),
                    Some(nix::libc::ESRCH | nix::libc::ENODEV | nix::libc::ENXIO)
                )
        }
        _ => false,
    }
}

#[cfg(target_os = "linux")]
fn clear_owned_ndp_proxy_entries(
    wan_iface: &str,
    current: &std::collections::BTreeSet<std::net::Ipv6Addr>,
    applied: &mut std::collections::BTreeSet<std::net::Ipv6Addr>,
    candidates: Vec<std::net::Ipv6Addr>,
) -> Option<Error> {
    let mut first_err = None;
    for addr in candidates {
        if !current.contains(&addr) {
            applied.remove(&addr);
            continue;
        }

        if let Err(err) = remove_ipv6_ndp_proxy(wan_iface, addr) {
            if is_linux_missing_netlink_object_error(&err) {
                applied.remove(&addr);
            } else {
                tracing::trace!(
                    wan_iface = %wan_iface,
                    addr = %addr,
                    ?err,
                    "failed to remove NDP proxy entry"
                );
                first_err.get_or_insert(err);
            }
        } else {
            applied.remove(&addr);
        }
    }
    first_err
}

#[cfg(target_os = "linux")]
fn ndp_proxy_target(state: &PublicIpv6ProviderRuntimeState) -> Option<(Ipv6Cidr, &NdpProxyTarget)> {
    match state {
        PublicIpv6ProviderRuntimeState::Active(active) => active
            .ndp_proxy
            .as_ref()
            .map(|target| (active.prefix, target)),
        PublicIpv6ProviderRuntimeState::Disabled | PublicIpv6ProviderRuntimeState::Pending(_) => {
            None
        }
    }
}

#[cfg(target_os = "linux")]
fn ensure_linux_ndp_proxy_enabled(wan_iface: &str) -> Result<(), Error> {
    let path = Path::new("/proc/sys/net/ipv6/conf")
        .join(wan_iface)
        .join("proxy_ndp");
    if !read_linux_proc_bool(&path)? {
        write_linux_proc_bool(&path, true)?;
        tracing::info!(wan_iface = %wan_iface, "enabled Linux NDP proxy");
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn collect_public_ipv6_tun_routes(
    tun_iface: &str,
    prefix: Ipv6Cidr,
) -> Result<std::collections::BTreeSet<std::net::Ipv6Addr>, Error> {
    let tun_ifindex = match get_interface_index(tun_iface) {
        Ok(ifindex) => ifindex,
        Err(err) if is_linux_missing_netlink_object_error(&err) => {
            tracing::debug!(
                tun_iface = %tun_iface,
                ?err,
                "treating missing tun interface as empty public IPv6 route set"
            );
            return Ok(Default::default());
        }
        Err(err) => return Err(err),
    };
    Ok(list_ipv6_route_messages()?
        .into_iter()
        .filter(|route| {
            route.header.destination_prefix_length == 128 && route.header.kind == RouteType::Unicast
        })
        .filter(|route| {
            route
                .attributes
                .iter()
                .any(|attr| matches!(attr, RouteAttribute::Oif(idx) if *idx == tun_ifindex))
        })
        .filter_map(|route| {
            route.attributes.into_iter().find_map(|attr| match attr {
                RouteAttribute::Destination(RouteAddress::Inet6(addr)) => Some(addr),
                _ => None,
            })
        })
        .filter(|addr| !addr.is_unicast_link_local() && prefix.contains(addr))
        .collect())
}

#[cfg(target_os = "linux")]
fn sync_ndp_proxy_entries(
    wan_iface: &str,
    tun_iface: &str,
    prefix: Ipv6Cidr,
    applied: &mut std::collections::BTreeSet<std::net::Ipv6Addr>,
) -> Result<(), Error> {
    ensure_linux_ndp_proxy_enabled(wan_iface)?;

    let wanted = collect_public_ipv6_tun_routes(tun_iface, prefix)?;
    let current = list_ipv6_ndp_proxy(wan_iface)?;

    let mut first_err = None;
    for addr in wanted.difference(&current) {
        if let Err(err) = add_ipv6_ndp_proxy(wan_iface, *addr) {
            first_err.get_or_insert(err);
        } else {
            applied.insert(*addr);
            tracing::debug!(wan_iface = %wan_iface, addr = %addr, "added NDP proxy entry");
        }
    }

    let stale = applied.difference(&wanted).copied().collect::<Vec<_>>();
    let stale_cleanup_err =
        clear_owned_ndp_proxy_entries(wan_iface, &current, applied, stale.clone());
    if !stale.is_empty() {
        tracing::debug!(
            wan_iface = %wan_iface,
            stale_count = stale.len(),
            remaining_count = stale.iter().filter(|addr| applied.contains(addr)).count(),
            "synced stale NDP proxy entries"
        );
    }
    if let Some(err) = first_err.or(stale_cleanup_err) {
        return Err(err);
    }

    Ok(())
}

#[cfg(target_os = "linux")]
fn reconcile_ndp_proxy_runtime(
    runtime: &mut NdpProxyRuntime,
    global_ctx: &ArcGlobalCtx,
    state: &PublicIpv6ProviderRuntimeState,
) -> bool {
    runtime.reconcile(global_ctx, state)
}

#[cfg(target_os = "linux")]
fn cleanup_ndp_proxy_runtime(runtime: &mut NdpProxyRuntime, net_ns: &NetNS) {
    if !runtime.clear_current_in_netns(net_ns) {
        tracing::warn!(
            remaining_entries = runtime.applied.len(),
            wan_iface = ?runtime.wan_iface,
            "failed to clean all NDP proxy entries before stopping public IPv6 provider task"
        );
    }
}

#[cfg(not(target_os = "linux"))]
fn reconcile_ndp_proxy_runtime(
    _runtime: &mut (),
    _global_ctx: &ArcGlobalCtx,
    _state: &PublicIpv6ProviderRuntimeState,
) -> bool {
    false
}

#[cfg(not(target_os = "linux"))]
fn cleanup_ndp_proxy_runtime(_runtime: &mut (), _net_ns: &NetNS) {}

#[cfg(target_os = "linux")]
fn new_ndp_proxy_runtime() -> NdpProxyRuntime {
    NdpProxyRuntime::default()
}

#[cfg(not(target_os = "linux"))]
fn new_ndp_proxy_runtime() {}

fn should_reconcile_immediately(event: &GlobalCtxEvent) -> bool {
    matches!(
        event,
        GlobalCtxEvent::ConfigPatched(_)
            | GlobalCtxEvent::TunDeviceReady(_)
            | GlobalCtxEvent::TunDeviceError(_)
            | GlobalCtxEvent::PublicIpv6RoutesUpdated(_, _)
    )
}

async fn wait_for_public_ipv6_provider_reconcile_event(
    event_receiver: &mut tokio::sync::broadcast::Receiver<GlobalCtxEvent>,
    cancel_token: &CancellationToken,
    reconcile_interval: std::time::Duration,
) -> bool {
    let timer = tokio::time::sleep(reconcile_interval);
    tokio::pin!(timer);
    loop {
        tokio::select! {
            _ = cancel_token.cancelled() => return false,
            _ = &mut timer => return true,
            recv = event_receiver.recv() => match recv {
                Ok(event) if should_reconcile_immediately(&event) => return true,
                Ok(_) => {}
                Err(tokio::sync::broadcast::error::RecvError::Closed) => return false,
                Err(tokio::sync::broadcast::error::RecvError::Lagged(_)) => {
                    *event_receiver = event_receiver.resubscribe();
                    return true;
                }
            }
        }
    }
}

fn log_public_ipv6_provider_state_change(
    last_state: Option<&PublicIpv6ProviderRuntimeState>,
    next_state: &PublicIpv6ProviderRuntimeState,
    changed: bool,
) {
    if last_state != Some(next_state) {
        match next_state {
            PublicIpv6ProviderRuntimeState::Disabled if last_state.is_some() => {
                tracing::info!("public IPv6 provider disabled");
            }
            PublicIpv6ProviderRuntimeState::Disabled => {}
            PublicIpv6ProviderRuntimeState::Pending(reason) => {
                tracing::warn!(reason = %reason, "public IPv6 provider not ready");
            }
            PublicIpv6ProviderRuntimeState::Active(active) => {
                #[cfg(target_os = "linux")]
                {
                    if let Some(target) = active.ndp_proxy.as_ref() {
                        tracing::info!(
                            prefix = %active.prefix,
                            wan_iface = %target.wan_iface,
                            "public IPv6 provider is active with NDP proxy"
                        );
                    } else {
                        tracing::info!(
                            prefix = %active.prefix,
                            "public IPv6 provider is active"
                        );
                    }
                }
                #[cfg(not(target_os = "linux"))]
                tracing::info!(prefix = %active.prefix, "public IPv6 provider is active");
            }
        }
    } else if changed {
        tracing::info!("public IPv6 provider runtime state changed");
    }
}

pub(super) struct PublicIpv6ProviderReconcileTask {
    cancel_token: CancellationToken,
    handle: tokio::task::JoinHandle<()>,
}

impl PublicIpv6ProviderReconcileTask {
    pub(super) async fn shutdown(self) {
        self.cancel_token.cancel();
        if let Err(err) = self.handle.await {
            tracing::warn!(
                ?err,
                "public IPv6 provider reconcile task failed during shutdown"
            );
        }
    }
}

pub(super) fn run_public_ipv6_provider_reconcile_task(
    global_ctx: &ArcGlobalCtx,
) -> Option<PublicIpv6ProviderReconcileTask> {
    if !should_run_public_ipv6_provider_reconcile_task(read_public_ipv6_provider_config_snapshot(
        global_ctx,
    )) {
        return None;
    }

    let global_ctx = Arc::downgrade(global_ctx);
    let cancel_token = CancellationToken::new();
    let task_cancel_token = cancel_token.clone();
    let handle = tokio::spawn(async move {
        let Some(initial_ctx) = global_ctx.upgrade() else {
            return;
        };
        let net_ns = initial_ctx.net_ns.clone();
        let mut event_receiver = initial_ctx.subscribe();
        drop(initial_ctx);
        let mut last_state: Option<PublicIpv6ProviderRuntimeState> = None;
        let mut ndp_proxy_runtime = new_ndp_proxy_runtime();

        loop {
            let Some(global_ctx) = global_ctx.upgrade() else {
                tracing::debug!("global ctx dropped, stopping public ipv6 provider reconcile");
                break;
            };

            let (next_state, changed) =
                reconcile_public_ipv6_provider_runtime_with_state(&global_ctx).await;
            log_public_ipv6_provider_state_change(last_state.as_ref(), &next_state, changed);
            let _ = reconcile_ndp_proxy_runtime(&mut ndp_proxy_runtime, &global_ctx, &next_state);
            last_state = Some(next_state);

            if !wait_for_public_ipv6_provider_reconcile_event(
                &mut event_receiver,
                &task_cancel_token,
                PUBLIC_IPV6_PROVIDER_RECONCILE_INTERVAL,
            )
            .await
            {
                break;
            }
        }

        cleanup_ndp_proxy_runtime(&mut ndp_proxy_runtime, &net_ns);
    });
    Some(PublicIpv6ProviderReconcileTask {
        cancel_token,
        handle,
    })
}

#[cfg(test)]
mod tests {
    #[cfg(target_os = "linux")]
    use std::fs;
    #[cfg(target_os = "linux")]
    use std::path::PathBuf;
    #[cfg(target_os = "linux")]
    use std::process::Command;
    use std::sync::Arc;

    #[cfg(target_os = "linux")]
    use netlink_packet_route::route::RouteType;

    #[cfg(target_os = "linux")]
    use super::{
        DefaultRouteIpv6InterfaceCandidate, DetectedIpv6Route,
        detect_public_ipv6_prefix_from_interfaces, detect_public_ipv6_prefix_from_routes,
        detect_public_ipv6_prefix_linux, ensure_linux_ipv6_forwarding_at_paths,
        ensure_public_ipv6_provider_supported, public_ipv6_provider_auto_detect_error,
        select_default_route_ipv6_interfaces,
        select_public_ipv6_prefix_from_default_route_interfaces, sync_ndp_proxy_entries,
    };

    use super::{
        PublicIpv6ProviderConfigSnapshot, PublicIpv6ProviderRuntimeState,
        active_public_ipv6_provider_state, read_public_ipv6_provider_config_snapshot,
        should_run_public_ipv6_provider_reconcile_task,
        try_apply_public_ipv6_provider_runtime_state,
    };
    #[cfg(not(target_os = "linux"))]
    use super::{ensure_public_ipv6_provider_supported, public_ipv6_provider_auto_detect_error};
    use crate::common::{
        config::{ConfigLoader, TomlConfigLoader},
        error::Error,
        global_ctx::{GlobalCtx, GlobalCtxEvent},
    };

    #[cfg(target_os = "linux")]
    fn run_ip(args: &[&str]) {
        let output = Command::new("ip")
            .args(args)
            .output()
            .expect("failed to execute ip process");
        assert!(
            output.status.success(),
            "ip command failed: {:?}\nstdout: {}\nstderr: {}",
            args,
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr),
        );
    }

    #[cfg(target_os = "linux")]
    fn test_iface_name(tag: &str) -> String {
        format!("et{}{:x}", tag, std::process::id() & 0xffff)
    }

    #[cfg(target_os = "linux")]
    struct ScopedDummyLink {
        name: String,
    }

    #[cfg(target_os = "linux")]
    impl ScopedDummyLink {
        fn new(name: &str) -> Self {
            let _ = Command::new("ip").args(["link", "del", name]).output();
            run_ip(&["link", "add", name, "type", "dummy"]);
            run_ip(&["link", "set", name, "up"]);
            Self {
                name: name.to_string(),
            }
        }
    }

    #[cfg(target_os = "linux")]
    impl Drop for ScopedDummyLink {
        fn drop(&mut self) {
            let _ = Command::new("ip")
                .args(["link", "del", &self.name])
                .output();
        }
    }

    #[cfg(target_os = "linux")]
    fn temp_forwarding_paths(
        all_value: &str,
        default_value: &str,
    ) -> (tempfile::TempDir, PathBuf, PathBuf) {
        let dir = tempfile::tempdir().unwrap();
        let all_path = dir.path().join("all_forwarding");
        let default_path = dir.path().join("default_forwarding");
        fs::write(&all_path, all_value).unwrap();
        fs::write(&default_path, default_value).unwrap();
        (dir, all_path, default_path)
    }

    #[cfg(target_os = "linux")]
    fn route(
        dst: Option<&str>,
        src: Option<&str>,
        ifindex: Option<u32>,
        kind: RouteType,
    ) -> DetectedIpv6Route {
        DetectedIpv6Route {
            dst: dst.map(|cidr| cidr.parse().unwrap()),
            src: src.map(|cidr| cidr.parse().unwrap()),
            ifindex,
            kind,
        }
    }

    fn active_state(prefix: cidr::Ipv6Cidr) -> PublicIpv6ProviderRuntimeState {
        #[cfg(target_os = "linux")]
        {
            active_public_ipv6_provider_state(prefix, None)
        }
        #[cfg(not(target_os = "linux"))]
        {
            active_public_ipv6_provider_state(prefix)
        }
    }

    #[cfg(target_os = "linux")]
    fn detected_prefix(
        detected: Option<super::DetectedPublicIpv6Prefix>,
    ) -> Option<cidr::Ipv6Cidr> {
        detected.map(|detected| detected.prefix)
    }

    #[cfg(target_os = "linux")]
    fn iface_candidate(
        interface_name: &str,
        ifindex: u32,
        address: &str,
        prefix_len: u8,
    ) -> DefaultRouteIpv6InterfaceCandidate {
        DefaultRouteIpv6InterfaceCandidate {
            interface_name: interface_name.to_string(),
            ifindex,
            address: address.parse().unwrap(),
            prefix_len,
        }
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn test_detect_public_ipv6_prefix_from_routes_selects_delegated_prefix() {
        let routes = vec![
            route(None, Some("2001:db8:1::/56"), Some(2), RouteType::Unicast),
            route(Some("2001:db8:1::/56"), None, Some(3), RouteType::Unicast),
        ];

        assert_eq!(
            detected_prefix(detect_public_ipv6_prefix_from_routes(&routes, 1)),
            Some("2001:db8:1::/56".parse().unwrap())
        );
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn test_detect_public_ipv6_prefix_from_routes_rejects_non_public_prefixes() {
        let routes = vec![
            route(Some("::/0"), Some("fd00::/48"), Some(2), RouteType::Unicast),
            route(Some("fd00::/48"), None, Some(3), RouteType::Unicast),
            route(None, Some("fe80::/64"), Some(4), RouteType::Unicast),
            route(Some("fe80::/64"), None, Some(5), RouteType::Unicast),
            route(None, Some("ff00::/8"), Some(6), RouteType::Unicast),
            route(Some("ff00::/8"), None, Some(7), RouteType::Unicast),
            route(None, Some("::/0"), Some(8), RouteType::Unicast),
            route(Some("::/0"), None, Some(9), RouteType::Unicast),
        ];

        assert_eq!(
            detected_prefix(detect_public_ipv6_prefix_from_routes(&routes, 1)),
            None
        );
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn test_detect_public_ipv6_prefix_from_routes_requires_delegated_route() {
        let routes = vec![route(
            None,
            Some("2001:db8:1::/56"),
            Some(2),
            RouteType::Unicast,
        )];

        assert_eq!(
            detected_prefix(detect_public_ipv6_prefix_from_routes(&routes, 1)),
            None
        );
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn test_detect_public_ipv6_prefix_from_routes_rejects_non_unicast_default_route() {
        let routes = vec![
            route(None, Some("2001:db8:1::/56"), Some(2), RouteType::BlackHole),
            route(Some("2001:db8:1::/56"), None, Some(3), RouteType::Unicast),
        ];

        assert_eq!(
            detected_prefix(detect_public_ipv6_prefix_from_routes(&routes, 1)),
            None
        );
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn test_detect_public_ipv6_prefix_from_routes_rejects_loopback_delegation() {
        let routes = vec![
            route(None, Some("2001:db8:1::/56"), Some(2), RouteType::Unicast),
            route(Some("2001:db8:1::/56"), None, Some(1), RouteType::Unicast),
        ];

        assert_eq!(
            detected_prefix(detect_public_ipv6_prefix_from_routes(&routes, 1)),
            None
        );
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn test_detect_public_ipv6_prefix_from_routes_prefers_shortest_prefix() {
        let routes = vec![
            route(None, Some("2001:db8:1::/56"), Some(2), RouteType::Unicast),
            route(Some("2001:db8:1::/56"), None, Some(3), RouteType::Unicast),
            route(None, Some("2001:db8::/48"), Some(4), RouteType::Unicast),
            route(Some("2001:db8::/48"), None, Some(5), RouteType::Unicast),
        ];

        assert_eq!(
            detected_prefix(detect_public_ipv6_prefix_from_routes(&routes, 1)),
            Some("2001:db8::/48".parse().unwrap())
        );
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn test_detect_public_ipv6_prefix_from_routes_rejects_non_unicast_delegation() {
        let routes = vec![
            route(None, Some("2001:db8:1::/56"), Some(2), RouteType::Unicast),
            route(Some("2001:db8:1::/56"), None, Some(3), RouteType::BlackHole),
        ];

        assert_eq!(
            detected_prefix(detect_public_ipv6_prefix_from_routes(&routes, 1)),
            None
        );
    }

    #[test]
    fn test_public_ipv6_provider_auto_detect_error_mentions_manual_prefix() {
        let err = public_ipv6_provider_auto_detect_error();
        let msg = err.to_string();

        assert!(msg.contains("IPv6 prefix"), "{}", msg);
        assert!(msg.contains("ipv6-public-addr-prefix"), "{}", msg);
    }

    fn test_global_ctx() -> Arc<GlobalCtx> {
        Arc::new(GlobalCtx::new(TomlConfigLoader::default()))
    }

    #[tokio::test]
    async fn test_read_public_ipv6_provider_config_snapshot_reads_provider_fields() {
        let global_ctx = test_global_ctx();
        let prefix = "2001:db8::/48".parse().unwrap();
        global_ctx.config.set_ipv6_public_addr_provider(true);
        global_ctx.config.set_ipv6_public_addr_prefix(Some(prefix));

        assert_eq!(
            read_public_ipv6_provider_config_snapshot(&global_ctx),
            PublicIpv6ProviderConfigSnapshot {
                provider_enabled: true,
                configured_prefix: Some(prefix),
            }
        );
    }

    #[test]
    fn test_reconcile_task_runs_when_provider_enabled() {
        assert!(!should_run_public_ipv6_provider_reconcile_task(
            PublicIpv6ProviderConfigSnapshot {
                provider_enabled: false,
                configured_prefix: None,
            }
        ));
        assert!(should_run_public_ipv6_provider_reconcile_task(
            PublicIpv6ProviderConfigSnapshot {
                provider_enabled: true,
                configured_prefix: Some("2001:db8::/48".parse().unwrap()),
            }
        ));
        assert!(should_run_public_ipv6_provider_reconcile_task(
            PublicIpv6ProviderConfigSnapshot {
                provider_enabled: true,
                configured_prefix: None,
            }
        ));
    }

    #[tokio::test]
    async fn test_try_apply_public_ipv6_provider_runtime_state_rejects_stale_config() {
        let global_ctx = test_global_ctx();
        let prefix = "2001:db8::/48".parse().unwrap();
        let config = PublicIpv6ProviderConfigSnapshot {
            provider_enabled: true,
            configured_prefix: Some(prefix),
        };

        global_ctx.config.set_ipv6_public_addr_provider(false);
        global_ctx.config.set_ipv6_public_addr_prefix(None);

        let changed = try_apply_public_ipv6_provider_runtime_state(
            &global_ctx,
            config,
            &active_state(prefix),
        );

        assert_eq!(changed, None);
        assert_eq!(global_ctx.get_advertised_ipv6_public_addr_prefix(), None);
        assert!(!global_ctx.get_feature_flags().ipv6_public_addr_provider);
    }

    #[tokio::test]
    async fn test_try_apply_public_ipv6_provider_runtime_state_applies_matching_config() {
        let global_ctx = test_global_ctx();
        let prefix = "2001:db8::/48".parse().unwrap();
        global_ctx.config.set_ipv6_public_addr_provider(true);
        global_ctx.config.set_ipv6_public_addr_prefix(Some(prefix));
        let config = read_public_ipv6_provider_config_snapshot(&global_ctx);

        let changed = try_apply_public_ipv6_provider_runtime_state(
            &global_ctx,
            config,
            &active_state(prefix),
        );

        assert_eq!(changed, Some(true));
        assert_eq!(
            global_ctx.get_advertised_ipv6_public_addr_prefix(),
            Some(prefix)
        );
        assert!(global_ctx.get_feature_flags().ipv6_public_addr_provider);
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn test_public_ipv6_provider_platform_check_accepts_linux() {
        assert!(ensure_public_ipv6_provider_supported().is_ok());
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn test_ensure_linux_ipv6_forwarding_enables_all_and_default() {
        let (_dir, all_path, default_path) = temp_forwarding_paths("0\n", "0\n");

        let changed = ensure_linux_ipv6_forwarding_at_paths(&all_path, &default_path).unwrap();

        assert!(changed);
        assert_eq!(fs::read_to_string(&all_path).unwrap(), "1\n");
        assert_eq!(fs::read_to_string(&default_path).unwrap(), "1\n");
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn test_ensure_linux_ipv6_forwarding_is_noop_when_already_enabled() {
        let (_dir, all_path, default_path) = temp_forwarding_paths("1\n", "1\n");

        let changed = ensure_linux_ipv6_forwarding_at_paths(&all_path, &default_path).unwrap();

        assert!(!changed);
        assert_eq!(fs::read_to_string(&all_path).unwrap(), "1\n");
        assert_eq!(fs::read_to_string(&default_path).unwrap(), "1\n");
    }

    #[cfg(not(target_os = "linux"))]
    #[test]
    fn test_public_ipv6_provider_platform_check_reports_linux_only() {
        let err = ensure_public_ipv6_provider_supported().unwrap_err();
        let msg = err.to_string();

        assert!(msg.contains("Linux"), "{}", msg);
        assert!(msg.contains("ipv6-public-addr-auto"), "{}", msg);
    }

    #[cfg(target_os = "linux")]
    #[serial_test::serial]
    #[tokio::test]
    async fn test_detect_public_ipv6_prefix_linux_reads_netlink_routes_from_kernel() {
        let wan_if = test_iface_name("dw");
        let lan_if = test_iface_name("dl");
        let _wan = ScopedDummyLink::new(&wan_if);
        let _lan = ScopedDummyLink::new(&lan_if);

        run_ip(&[
            "-6",
            "addr",
            "add",
            "2001:db8:100:ffff::1/64",
            "dev",
            &wan_if,
        ]);
        run_ip(&[
            "-6",
            "route",
            "add",
            "default",
            "from",
            "2001:db8:100::/56",
            "dev",
            &wan_if,
        ]);
        run_ip(&["-6", "route", "add", "2001:db8:100::/56", "dev", &lan_if]);

        assert_eq!(
            detected_prefix(detect_public_ipv6_prefix_linux().await.unwrap()),
            Some("2001:db8:100::/56".parse().unwrap())
        );
    }

    #[cfg(target_os = "linux")]
    #[serial_test::serial]
    #[tokio::test]
    async fn test_detect_public_ipv6_prefix_linux_dhcpv6_ia_na_fallback() {
        // DHCPv6 IA_NA scenario: prefix is directly on the WAN interface,
        // with no delegated route on a LAN interface.
        // The route-based detection should fail, and the interface-scanning
        // fallback should pick up the prefix from the WAN address.
        let wan_if = test_iface_name("ia");
        let _wan = ScopedDummyLink::new(&wan_if);

        run_ip(&[
            "-6",
            "addr",
            "add",
            "2001:db8:aaaa:ffff::1/64",
            "dev",
            &wan_if,
        ]);
        run_ip(&[
            "-6",
            "route",
            "add",
            "default",
            "from",
            "2001:db8:aaaa::/64",
            "dev",
            &wan_if,
        ]);
        // Also add a /48 address+route pair to verify shortest-prefix preference
        run_ip(&["-6", "addr", "add", "2001:db8:bbbb::1/48", "dev", &wan_if]);
        run_ip(&[
            "-6",
            "route",
            "add",
            "default",
            "from",
            "2001:db8::/48",
            "dev",
            &wan_if,
        ]);

        // NO delegated route on a LAN interface — this is the IA_NA case
        // The fallback should find both prefixes via interface scanning and
        // prefer the shorter /48.
        let detected = detect_public_ipv6_prefix_linux().await.unwrap().unwrap();
        assert_eq!(detected.prefix, "2001:db8:bbbb::/48".parse().unwrap());
        assert_eq!(detected.ndp_proxy.unwrap().wan_iface, wan_if);
    }

    #[cfg(target_os = "linux")]
    #[serial_test::serial]
    #[tokio::test]
    async fn test_detect_public_ipv6_prefix_from_interfaces_uses_default_route_iface() {
        let wan_if = test_iface_name("dw");
        let other_if = test_iface_name("do");
        let _wan = ScopedDummyLink::new(&wan_if);
        let _other = ScopedDummyLink::new(&other_if);

        run_ip(&["-6", "addr", "add", "2001:db8:dddd::1/64", "dev", &wan_if]);
        run_ip(&["-6", "addr", "add", "2001:db8::1/48", "dev", &other_if]);

        let wan_ifindex = crate::common::ifcfg::get_interface_index(&wan_if).unwrap();
        let other_ifindex = crate::common::ifcfg::get_interface_index(&other_if).unwrap();
        let routes = vec![
            route(None, None, Some(wan_ifindex), RouteType::Unicast),
            route(
                Some("2001:db8::/48"),
                None,
                Some(other_ifindex),
                RouteType::Unicast,
            ),
        ];

        let detected = detect_public_ipv6_prefix_from_interfaces(&routes)
            .expect("fallback should select the default-route interface");
        assert_eq!(detected.prefix, "2001:db8:dddd::/64".parse().unwrap());
        assert_eq!(detected.ndp_proxy.unwrap().wan_iface, wan_if);
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn test_select_default_route_ipv6_interfaces_filters_candidates() {
        let wan_ifindices = [2u32].into_iter().collect();
        let candidates = vec![
            iface_candidate("wan0", 2, "2001:db8:100::1", 64),
            iface_candidate("nonwan0", 9, "2001:db8:200::1", 64),
            iface_candidate("loopback0", 2, "::1", 128),
            iface_candidate("linklocal0", 2, "fe80::1", 64),
            iface_candidate("ula0", 2, "fd00::1", 64),
            iface_candidate("multicast0", 2, "ff02::1", 64),
            iface_candidate("unspecified0", 2, "::", 64),
            iface_candidate("empty0", 2, "2001:db8:300::1", 0),
            iface_candidate("host0", 2, "2001:db8:400::1", 128),
        ];

        let selected = select_default_route_ipv6_interfaces(candidates, &wan_ifindices, 64);

        assert_eq!(selected.len(), 1);
        assert_eq!(selected[0].interface_name, "wan0");
        assert_eq!(selected[0].prefix, "2001:db8:100::/64".parse().unwrap());
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn test_select_default_route_ipv6_interfaces_strips_host_bits() {
        let wan_ifindices = [2u32].into_iter().collect();
        let candidates = vec![iface_candidate("wan0", 2, "2001:db8:aaaa::abcd", 64)];

        let selected = select_default_route_ipv6_interfaces(candidates, &wan_ifindices, 64);

        assert_eq!(selected.len(), 1);
        assert_eq!(selected[0].prefix, "2001:db8:aaaa::/64".parse().unwrap());
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn test_select_public_ipv6_prefix_tie_breaks_by_lowest_ifindex() {
        let wan_ifindices = [2u32, 3, 5].into_iter().collect();
        let candidates = vec![
            iface_candidate("wan5", 5, "2001:db8:5555::1", 48),
            iface_candidate("wan64", 3, "2001:db8:3333::1", 64),
            iface_candidate("wan2", 2, "2001:db9:2222::1", 48),
        ];
        let interfaces = select_default_route_ipv6_interfaces(candidates, &wan_ifindices, 64);

        let detected = select_public_ipv6_prefix_from_default_route_interfaces(interfaces)
            .expect("default-route public IPv6 prefix should be selected");

        assert_eq!(detected.prefix, "2001:db9:2222::/48".parse().unwrap());
        assert_eq!(detected.ndp_proxy.unwrap().wan_iface, "wan2");
    }

    #[cfg(target_os = "linux")]
    #[serial_test::serial]
    #[tokio::test]
    async fn test_configured_prefix_on_default_iface_gets_ndp_proxy_target() {
        let wan_if = test_iface_name("cp");
        let _wan = ScopedDummyLink::new(&wan_if);
        let configured_prefix = "2001:db8:feed::/64".parse().unwrap();

        run_ip(&["-6", "addr", "add", "2001:db8:feed::1/128", "dev", &wan_if]);

        let ifindex = crate::common::ifcfg::get_interface_index(&wan_if).unwrap();
        let routes = vec![route(None, None, Some(ifindex), RouteType::Unicast)];

        let target = super::detect_configured_prefix_ndp_proxy_target(&routes, configured_prefix)
            .expect("configured on-link prefix should require NDP proxy");
        assert_eq!(target.wan_iface, wan_if);
    }

    #[cfg(target_os = "linux")]
    #[serial_test::serial]
    #[tokio::test]
    async fn test_configured_prefix_broader_than_default_iface_does_not_get_ndp_proxy_target() {
        let wan_if = test_iface_name("cb");
        let _wan = ScopedDummyLink::new(&wan_if);
        let configured_prefix = "2001:db8:beef::/48".parse().unwrap();

        run_ip(&["-6", "addr", "add", "2001:db8:beef:1::1/64", "dev", &wan_if]);

        let ifindex = crate::common::ifcfg::get_interface_index(&wan_if).unwrap();
        let routes = vec![route(None, None, Some(ifindex), RouteType::Unicast)];

        assert_eq!(
            super::detect_configured_prefix_ndp_proxy_target(&routes, configured_prefix),
            None
        );
    }

    #[cfg(target_os = "linux")]
    #[serial_test::serial]
    #[tokio::test]
    async fn test_detect_public_ipv6_prefix_linux_dhcpv6_ia_na_single_prefix() {
        // DHCPv6 IA_NA: the WAN interface has a global prefix with a
        // default route. Use a /48 dummy prefix so the fallback prefers it
        // over any real /64 on the test machine.
        let wan_if = test_iface_name("ib");
        let _wan = ScopedDummyLink::new(&wan_if);

        run_ip(&["-6", "addr", "add", "2001:db8:cccc::1/48", "dev", &wan_if]);
        run_ip(&["-6", "route", "add", "default", "dev", &wan_if]);

        let detected = detect_public_ipv6_prefix_linux().await.unwrap().unwrap();
        assert_eq!(detected.prefix, "2001:db8:cccc::/48".parse().unwrap());
        assert_eq!(detected.ndp_proxy.unwrap().wan_iface, wan_if);
    }

    #[cfg(target_os = "linux")]
    #[serial_test::serial]
    #[tokio::test]
    async fn test_detect_public_ipv6_prefix_from_interfaces_skips_non_global() {
        // Create a dummy interface with only a link-local address.
        // The interface fallback should return None because there is no
        // global unicast address.
        let iface = test_iface_name("ng");
        let _link = ScopedDummyLink::new(&iface);

        // Bring up the interface so it auto-configures a link-local address
        run_ip(&["link", "set", &iface, "up"]);
        let ifindex = crate::common::ifcfg::get_interface_index(&iface).unwrap();
        let routes = vec![route(None, None, Some(ifindex), RouteType::Unicast)];

        // No global address added — only link-local should be present
        let result = detect_public_ipv6_prefix_from_interfaces(&routes);
        assert_eq!(detected_prefix(result), None);
    }

    #[cfg(target_os = "linux")]
    #[serial_test::serial]
    #[tokio::test]
    async fn test_ndp_proxy_sync_uses_configured_tun_iface_without_shell_neigh() {
        let wan_if = test_iface_name("nw");
        let tun_if = test_iface_name("nt");
        let _wan = ScopedDummyLink::new(&wan_if);
        let _tun = ScopedDummyLink::new(&tun_if);
        let addr = "2001:db8:abcd::123".parse::<std::net::Ipv6Addr>().unwrap();
        let prefix = "2001:db8:abcd::/64".parse().unwrap();
        let mut applied = std::collections::BTreeSet::new();

        run_ip(&["-6", "route", "add", &format!("{addr}/128"), "dev", &tun_if]);

        sync_ndp_proxy_entries(&wan_if, &tun_if, prefix, &mut applied).unwrap();
        assert!(
            crate::common::ifcfg::list_ipv6_ndp_proxy(&wan_if)
                .unwrap()
                .contains(&addr)
        );
        assert!(applied.contains(&addr));

        run_ip(&["-6", "route", "del", &format!("{addr}/128"), "dev", &tun_if]);
        sync_ndp_proxy_entries(&wan_if, &tun_if, prefix, &mut applied).unwrap();
        assert!(
            !crate::common::ifcfg::list_ipv6_ndp_proxy(&wan_if)
                .unwrap()
                .contains(&addr)
        );
        assert!(!applied.contains(&addr));
    }

    #[cfg(target_os = "linux")]
    #[serial_test::serial]
    #[tokio::test]
    async fn test_ndp_proxy_sync_does_not_delete_preexisting_proxy_entry() {
        let wan_if = test_iface_name("pw");
        let tun_if = test_iface_name("pt");
        let _wan = ScopedDummyLink::new(&wan_if);
        let _tun = ScopedDummyLink::new(&tun_if);
        let addr = "2001:db8:beef::123".parse::<std::net::Ipv6Addr>().unwrap();
        let prefix = "2001:db8:beef::/64".parse().unwrap();
        let mut applied = std::collections::BTreeSet::new();

        super::ensure_linux_ndp_proxy_enabled(&wan_if).unwrap();
        crate::common::ifcfg::add_ipv6_ndp_proxy(&wan_if, addr).unwrap();
        run_ip(&["-6", "route", "add", &format!("{addr}/128"), "dev", &tun_if]);

        sync_ndp_proxy_entries(&wan_if, &tun_if, prefix, &mut applied).unwrap();
        assert!(
            crate::common::ifcfg::list_ipv6_ndp_proxy(&wan_if)
                .unwrap()
                .contains(&addr)
        );
        assert!(!applied.contains(&addr));

        run_ip(&["-6", "route", "del", &format!("{addr}/128"), "dev", &tun_if]);
        sync_ndp_proxy_entries(&wan_if, &tun_if, prefix, &mut applied).unwrap();
        assert!(
            crate::common::ifcfg::list_ipv6_ndp_proxy(&wan_if)
                .unwrap()
                .contains(&addr)
        );
        assert!(!applied.contains(&addr));

        crate::common::ifcfg::remove_ipv6_ndp_proxy(&wan_if, addr).unwrap();
    }

    #[cfg(target_os = "linux")]
    #[serial_test::serial]
    #[tokio::test]
    async fn test_ndp_proxy_sync_removes_owned_entry_when_tun_iface_is_gone() {
        let wan_if = test_iface_name("gw");
        let _wan = ScopedDummyLink::new(&wan_if);
        let addr = "2001:db8:face::123".parse::<std::net::Ipv6Addr>().unwrap();
        let prefix = "2001:db8:face::/64".parse().unwrap();
        let mut applied = std::collections::BTreeSet::from([addr]);

        super::ensure_linux_ndp_proxy_enabled(&wan_if).unwrap();
        crate::common::ifcfg::add_ipv6_ndp_proxy(&wan_if, addr).unwrap();

        sync_ndp_proxy_entries(&wan_if, "missing-easytier-tun", prefix, &mut applied).unwrap();
        assert!(
            !crate::common::ifcfg::list_ipv6_ndp_proxy(&wan_if)
                .unwrap()
                .contains(&addr)
        );
        assert!(applied.is_empty());
    }

    #[cfg(target_os = "linux")]
    #[serial_test::serial]
    #[tokio::test]
    async fn test_cleanup_ndp_proxy_runtime_removes_owned_entry_on_task_exit() {
        let wan_if = test_iface_name("cw");
        let _wan = ScopedDummyLink::new(&wan_if);
        let addr = "2001:db8:cafe::123".parse::<std::net::Ipv6Addr>().unwrap();
        let mut runtime = super::NdpProxyRuntime {
            wan_iface: Some(wan_if.clone()),
            applied: std::collections::BTreeSet::from([addr]),
        };

        super::ensure_linux_ndp_proxy_enabled(&wan_if).unwrap();
        crate::common::ifcfg::add_ipv6_ndp_proxy(&wan_if, addr).unwrap();

        super::cleanup_ndp_proxy_runtime(&mut runtime, &crate::common::netns::NetNS::new(None));
        assert!(
            !crate::common::ifcfg::list_ipv6_ndp_proxy(&wan_if)
                .unwrap()
                .contains(&addr)
        );
        assert!(!runtime.cleanup_pending());
    }

    #[tokio::test]
    async fn test_wait_for_reconcile_ignores_unrelated_events_without_resetting_timer() {
        let (tx, mut rx) = tokio::sync::broadcast::channel(16);
        let cancel_token = tokio_util::sync::CancellationToken::new();
        let spam_task = tokio::spawn(async move {
            loop {
                if tx.send(GlobalCtxEvent::PeerAdded(1)).is_err() {
                    break;
                }
                tokio::time::sleep(std::time::Duration::from_millis(5)).await;
            }
        });

        let reconciled = tokio::time::timeout(
            std::time::Duration::from_millis(250),
            super::wait_for_public_ipv6_provider_reconcile_event(
                &mut rx,
                &cancel_token,
                std::time::Duration::from_millis(50),
            ),
        )
        .await
        .expect("unrelated events should not keep resetting the reconcile timer");

        spam_task.abort();
        assert!(reconciled);
    }

    #[cfg(target_os = "linux")]
    async fn wait_for_ndp_proxy_entry(wan_if: &str, addr: std::net::Ipv6Addr, present: bool) {
        for _ in 0..50 {
            let current = crate::common::ifcfg::list_ipv6_ndp_proxy(wan_if).unwrap();
            if current.contains(&addr) == present {
                return;
            }
            tokio::time::sleep(std::time::Duration::from_millis(20)).await;
        }

        let current = crate::common::ifcfg::list_ipv6_ndp_proxy(wan_if).unwrap();
        assert_eq!(current.contains(&addr), present);
    }

    #[cfg(target_os = "linux")]
    #[serial_test::serial]
    #[tokio::test]
    async fn test_reconcile_task_shutdown_removes_owned_ndp_proxy_entry() {
        let wan_if = test_iface_name("tw");
        let tun_if = test_iface_name("tt");
        let _wan = ScopedDummyLink::new(&wan_if);
        let _tun = ScopedDummyLink::new(&tun_if);
        let prefix = "2001:db8:fade::/64".parse().unwrap();
        let wan_addr = "2001:db8:fade::1";
        let leased_addr = "2001:db8:fade::123".parse::<std::net::Ipv6Addr>().unwrap();
        let global_ctx = test_global_ctx();

        run_ip(&[
            "-6",
            "addr",
            "add",
            &format!("{wan_addr}/128"),
            "dev",
            &wan_if,
        ]);
        run_ip(&["-6", "route", "add", "default", "dev", &wan_if]);
        run_ip(&[
            "-6",
            "route",
            "add",
            &format!("{leased_addr}/128"),
            "dev",
            &tun_if,
        ]);

        global_ctx.config.set_ipv6_public_addr_provider(true);
        global_ctx.config.set_ipv6_public_addr_prefix(Some(prefix));
        global_ctx.set_tun_device_ready(tun_if);

        let task = super::run_public_ipv6_provider_reconcile_task(&global_ctx)
            .expect("provider task should start when provider is enabled");
        wait_for_ndp_proxy_entry(&wan_if, leased_addr, true).await;

        task.shutdown().await;
        wait_for_ndp_proxy_entry(&wan_if, leased_addr, false).await;
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn test_missing_netlink_object_errors_release_ndp_ownership() {
        for errno in [
            nix::libc::ENOENT,
            nix::libc::ESRCH,
            nix::libc::ENODEV,
            nix::libc::ENXIO,
        ] {
            let err = Error::IOError(std::io::Error::from_raw_os_error(errno));
            assert!(super::is_linux_missing_netlink_object_error(&err));
        }
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn test_clear_owned_ndp_proxy_entries_forgets_already_absent_entry() {
        let addr = "2001:db8:dead::111".parse::<std::net::Ipv6Addr>().unwrap();
        let mut applied = std::collections::BTreeSet::from([addr]);
        let current = std::collections::BTreeSet::new();

        assert!(
            super::clear_owned_ndp_proxy_entries("missing", &current, &mut applied, vec![addr],)
                .is_none()
        );
        assert!(!applied.contains(&addr));
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn test_ndp_proxy_runtime_forgets_entries_when_wan_interface_is_gone() {
        let addr = "2001:db8:dead::123".parse::<std::net::Ipv6Addr>().unwrap();
        let mut runtime = super::NdpProxyRuntime {
            wan_iface: Some(test_iface_name("missing")),
            applied: std::collections::BTreeSet::from([addr]),
        };

        assert!(runtime.clear_current_locked());
        assert!(runtime.wan_iface.is_none());
        assert!(runtime.applied.is_empty());
    }

    #[cfg(target_os = "linux")]
    #[tokio::test]
    async fn test_ndp_proxy_runtime_finishes_cleanup_when_wan_interface_is_gone_after_disable() {
        let addr = "2001:db8:dead::456".parse::<std::net::Ipv6Addr>().unwrap();
        let global_ctx = test_global_ctx();
        let mut runtime = super::NdpProxyRuntime {
            wan_iface: Some(test_iface_name("missing")),
            applied: std::collections::BTreeSet::from([addr]),
        };

        assert!(!runtime.reconcile(&global_ctx, &PublicIpv6ProviderRuntimeState::Disabled));
        assert!(!runtime.cleanup_pending());
    }

    #[cfg(target_os = "linux")]
    #[serial_test::serial]
    #[tokio::test]
    async fn test_detect_public_ipv6_prefix_linux_prefers_shortest_prefix_from_kernel() {
        let wan_if_1 = test_iface_name("sw1");
        let lan_if_1 = test_iface_name("sl1");
        let wan_if_2 = test_iface_name("sw2");
        let lan_if_2 = test_iface_name("sl2");
        let _wan_1 = ScopedDummyLink::new(&wan_if_1);
        let _lan_1 = ScopedDummyLink::new(&lan_if_1);
        let _wan_2 = ScopedDummyLink::new(&wan_if_2);
        let _lan_2 = ScopedDummyLink::new(&lan_if_2);

        run_ip(&[
            "-6",
            "addr",
            "add",
            "2001:db8:3000:ffff::1/64",
            "dev",
            &wan_if_1,
        ]);
        run_ip(&[
            "-6",
            "route",
            "add",
            "default",
            "from",
            "2001:db8:3000::/56",
            "dev",
            &wan_if_1,
        ]);
        run_ip(&["-6", "route", "add", "2001:db8:3000::/56", "dev", &lan_if_1]);

        run_ip(&["-6", "addr", "add", "2001:db9:ffff::1/64", "dev", &wan_if_2]);
        run_ip(&[
            "-6",
            "route",
            "add",
            "default",
            "from",
            "2001:db9::/48",
            "dev",
            &wan_if_2,
        ]);
        run_ip(&["-6", "route", "add", "2001:db9::/48", "dev", &lan_if_2]);

        assert_eq!(
            detected_prefix(detect_public_ipv6_prefix_linux().await.unwrap()),
            Some("2001:db9::/48".parse().unwrap())
        );
    }
}
