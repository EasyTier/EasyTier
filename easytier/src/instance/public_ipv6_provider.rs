use std::{path::Path, sync::Arc};

use anyhow::Context;
use cidr::{Ipv6Cidr, Ipv6Inet};
#[cfg(target_os = "linux")]
use netlink_packet_route::route::{RouteAddress, RouteAttribute, RouteMessage, RouteType};

#[cfg(target_os = "linux")]
use crate::common::ifcfg::{get_interface_index, list_ipv6_route_messages};
use crate::common::{
    error::Error,
    global_ctx::{ArcGlobalCtx, GlobalCtxEvent},
};

const PUBLIC_IPV6_PROVIDER_RECONCILE_INTERVAL: std::time::Duration =
    std::time::Duration::from_secs(5);
const PUBLIC_IPV6_PROVIDER_RECONCILE_MAX_RETRIES: usize = 3;

#[derive(Debug, Clone, PartialEq, Eq)]
enum PublicIpv6ProviderRuntimeState {
    Disabled,
    Pending(String),
    Active(Ipv6Cidr),
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
    config.provider_enabled && config.configured_prefix.is_none()
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
    ipv6: Option<Ipv6Inet>,
    provider_enabled: bool,
    auto_enabled: bool,
    prefix: Option<Ipv6Cidr>,
) -> Result<(), Error> {
    if auto_enabled && ipv6.is_some() {
        return Err(anyhow::anyhow!(
            "cannot use --ipv6-public-addr-auto together with a manually set --ipv6; pick one or the other"
        )
        .into());
    }

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
) -> Option<Ipv6Cidr> {
    routes
        .iter()
        .filter_map(|route| {
            if !is_ipv6_default_route(route.dst) {
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

            delegated.then_some(prefix)
        })
        .min_by_key(|prefix| prefix.network_length())
}

#[cfg(target_os = "linux")]
async fn detect_public_ipv6_prefix_linux() -> Result<Option<Ipv6Cidr>, Error> {
    let routes = list_ipv6_route_messages().with_context(|| "failed to query linux ipv6 routes")?;
    let routes = routes
        .iter()
        .cloned()
        .map(DetectedIpv6Route::try_from)
        .collect::<Result<Vec<_>, _>>()?;
    let loopback_ifindex =
        get_interface_index("lo").with_context(|| "failed to resolve linux loopback ifindex")?;

    Ok(detect_public_ipv6_prefix_from_routes(
        &routes,
        loopback_ifindex,
    ))
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
        return PublicIpv6ProviderRuntimeState::Active(prefix);
    }

    match detect_public_ipv6_prefix_linux().await {
        Ok(Some(prefix)) if is_global_routable_public_ipv6_prefix(prefix) => {
            PublicIpv6ProviderRuntimeState::Active(prefix)
        }
        Ok(Some(prefix)) => invalid_public_ipv6_prefix_state(prefix, "detected"),
        Ok(None) => PublicIpv6ProviderRuntimeState::Pending(
            public_ipv6_provider_auto_detect_error().to_string(),
        ),
        Err(err) => PublicIpv6ProviderRuntimeState::Pending(err.to_string()),
    }
}

async fn resolve_public_ipv6_provider_runtime_state(
    global_ctx: &ArcGlobalCtx,
    config: PublicIpv6ProviderConfigSnapshot,
) -> PublicIpv6ProviderRuntimeState {
    if !config.provider_enabled {
        return PublicIpv6ProviderRuntimeState::Disabled;
    }

    #[cfg(target_os = "linux")]
    {
        return resolve_public_ipv6_provider_runtime_state_linux(
            global_ctx,
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
        PublicIpv6ProviderRuntimeState::Active(prefix) => Some(*prefix),
        PublicIpv6ProviderRuntimeState::Disabled | PublicIpv6ProviderRuntimeState::Pending(_) => {
            None
        }
    };
    let prefix_changed = global_ctx.set_advertised_ipv6_public_addr_prefix(next_prefix);

    let next_provider_enabled = matches!(state, PublicIpv6ProviderRuntimeState::Active(_));
    let feature_changed = {
        let mut feature_flags = global_ctx.get_feature_flags();
        if feature_flags.ipv6_public_addr_provider == next_provider_enabled {
            false
        } else {
            feature_flags.ipv6_public_addr_provider = next_provider_enabled;
            global_ctx.set_feature_flags(feature_flags);
            true
        }
    };

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
        (true, Some(prefix)) => PublicIpv6ProviderRuntimeState::Active(prefix),
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

pub(super) fn run_public_ipv6_provider_reconcile_task(global_ctx: &ArcGlobalCtx) {
    if !should_run_public_ipv6_provider_reconcile_task(read_public_ipv6_provider_config_snapshot(
        global_ctx,
    )) {
        return;
    }

    let global_ctx = Arc::downgrade(global_ctx);
    tokio::spawn(async move {
        let Some(initial_ctx) = global_ctx.upgrade() else {
            return;
        };
        let mut event_receiver = initial_ctx.subscribe();
        let mut last_state: Option<PublicIpv6ProviderRuntimeState> = None;

        loop {
            let Some(global_ctx) = global_ctx.upgrade() else {
                tracing::debug!("global ctx dropped, stopping public ipv6 provider reconcile");
                return;
            };

            let (next_state, changed) =
                reconcile_public_ipv6_provider_runtime_with_state(&global_ctx).await;
            if last_state.as_ref() != Some(&next_state) {
                match &next_state {
                    PublicIpv6ProviderRuntimeState::Disabled if last_state.is_some() => {
                        tracing::info!("public IPv6 provider disabled");
                    }
                    PublicIpv6ProviderRuntimeState::Disabled => {}
                    PublicIpv6ProviderRuntimeState::Pending(reason) => {
                        tracing::warn!(reason = %reason, "public IPv6 provider not ready");
                    }
                    PublicIpv6ProviderRuntimeState::Active(prefix) => {
                        tracing::info!(prefix = %prefix, "public IPv6 provider is active");
                    }
                }
            } else if changed {
                tracing::info!("public IPv6 provider runtime state changed");
            }
            last_state = Some(next_state);

            if matches!(
                last_state.as_ref(),
                Some(PublicIpv6ProviderRuntimeState::Disabled)
            ) {
                match event_receiver.recv().await {
                    Ok(GlobalCtxEvent::ConfigPatched(_)) => {}
                    Ok(_) => {}
                    Err(tokio::sync::broadcast::error::RecvError::Closed) => return,
                    Err(tokio::sync::broadcast::error::RecvError::Lagged(_)) => {
                        event_receiver = event_receiver.resubscribe();
                    }
                }
            } else {
                tokio::select! {
                    recv = event_receiver.recv() => match recv {
                        Ok(GlobalCtxEvent::ConfigPatched(_)) => {}
                        Ok(_) => {}
                        Err(tokio::sync::broadcast::error::RecvError::Closed) => return,
                        Err(tokio::sync::broadcast::error::RecvError::Lagged(_)) => {
                            event_receiver = event_receiver.resubscribe();
                        }
                    },
                    _ = tokio::time::sleep(PUBLIC_IPV6_PROVIDER_RECONCILE_INTERVAL) => {}
                }
            }
        }
    });
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
        DetectedIpv6Route, detect_public_ipv6_prefix_from_routes, detect_public_ipv6_prefix_linux,
        ensure_linux_ipv6_forwarding_at_paths, ensure_public_ipv6_provider_supported,
        public_ipv6_provider_auto_detect_error,
    };

    use super::{
        PublicIpv6ProviderConfigSnapshot, PublicIpv6ProviderRuntimeState,
        read_public_ipv6_provider_config_snapshot, should_run_public_ipv6_provider_reconcile_task,
        try_apply_public_ipv6_provider_runtime_state,
    };
    #[cfg(not(target_os = "linux"))]
    use super::{ensure_public_ipv6_provider_supported, public_ipv6_provider_auto_detect_error};
    use crate::common::{
        config::{ConfigLoader, TomlConfigLoader},
        global_ctx::GlobalCtx,
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

    #[cfg(target_os = "linux")]
    #[test]
    fn test_detect_public_ipv6_prefix_from_routes_selects_delegated_prefix() {
        let routes = vec![
            route(None, Some("2001:db8:1::/56"), Some(2), RouteType::Unicast),
            route(Some("2001:db8:1::/56"), None, Some(3), RouteType::Unicast),
        ];

        assert_eq!(
            detect_public_ipv6_prefix_from_routes(&routes, 1),
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

        assert_eq!(detect_public_ipv6_prefix_from_routes(&routes, 1), None);
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

        assert_eq!(detect_public_ipv6_prefix_from_routes(&routes, 1), None);
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn test_detect_public_ipv6_prefix_from_routes_rejects_loopback_delegation() {
        let routes = vec![
            route(None, Some("2001:db8:1::/56"), Some(2), RouteType::Unicast),
            route(Some("2001:db8:1::/56"), None, Some(1), RouteType::Unicast),
        ];

        assert_eq!(detect_public_ipv6_prefix_from_routes(&routes, 1), None);
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
            detect_public_ipv6_prefix_from_routes(&routes, 1),
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

        assert_eq!(detect_public_ipv6_prefix_from_routes(&routes, 1), None);
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
    fn test_reconcile_task_only_runs_for_auto_detect_provider() {
        assert!(!should_run_public_ipv6_provider_reconcile_task(
            PublicIpv6ProviderConfigSnapshot {
                provider_enabled: false,
                configured_prefix: None,
            }
        ));
        assert!(!should_run_public_ipv6_provider_reconcile_task(
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
            &PublicIpv6ProviderRuntimeState::Active(prefix),
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
            &PublicIpv6ProviderRuntimeState::Active(prefix),
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
            detect_public_ipv6_prefix_linux().await.unwrap(),
            Some("2001:db8:100::/56".parse().unwrap())
        );
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
            detect_public_ipv6_prefix_linux().await.unwrap(),
            Some("2001:db9::/48".parse().unwrap())
        );
    }
}
