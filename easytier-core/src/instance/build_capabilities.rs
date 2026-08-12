//! Compile-time capability selection for portable Instance validation.
//!
//! Cargo features are localized here so configuration validation remains one
//! unconditional path in `CoreInstance`.

use crate::config::{peers::PeerRuntimeSnapshot, runtime::CoreRuntimeConfig};

use super::CoreInstanceConfig;

const DHCP_IPV4_AVAILABLE: bool = cfg!(feature = "dhcp-ipv4");
const SMOLTCP_GATEWAY_AVAILABLE: bool = cfg!(feature = "proxy-smoltcp-stack");
const PACKET_PROXY_AVAILABLE: bool = cfg!(feature = "proxy-packet");
const PROXY_CIDR_MONITOR_AVAILABLE: bool = cfg!(feature = "proxy-cidr-monitor");
const WRAPPED_TRANSPORT_AVAILABLE: bool = cfg!(feature = "wrapped-transport");
const PUBLIC_IPV6_AVAILABLE: bool = cfg!(feature = "public-ipv6-provider");
const VPN_PORTAL_AVAILABLE: bool = cfg!(feature = "vpn-portal");

fn require(available: bool, requested: bool, capability: &str) -> anyhow::Result<()> {
    if requested && !available {
        anyhow::bail!("this build does not include {capability}");
    }
    Ok(())
}

fn validate_snapshot(
    runtime: &CoreRuntimeConfig,
    peer: &PeerRuntimeSnapshot,
) -> anyhow::Result<()> {
    let core = &peer.runtime.core;
    require(DHCP_IPV4_AVAILABLE, runtime.dhcp_ipv4, "DHCP IPv4")?;
    require(
        SMOLTCP_GATEWAY_AVAILABLE,
        runtime.gateway.socks5_bind.is_some() || !runtime.gateway.port_forwards.is_empty(),
        "the smoltcp gateway",
    )?;
    require(
        PROXY_CIDR_MONITOR_AVAILABLE,
        runtime
            .manual_routes
            .as_ref()
            .is_some_and(|routes| !routes.is_empty()),
        "the proxy CIDR monitor",
    )?;
    require(
        WRAPPED_TRANSPORT_AVAILABLE,
        !core.routes.proxy_networks.is_empty(),
        "proxy routing services",
    )?;
    require(
        PACKET_PROXY_AVAILABLE,
        runtime
            .proxy
            .should_start(!core.routes.proxy_networks.is_empty()),
        "packet proxy services",
    )?;
    require(
        PUBLIC_IPV6_AVAILABLE,
        runtime.public_ipv6_auto
            || runtime.public_ipv6_provider.provider_enabled
            || runtime.public_ipv6_provider.configured_prefix.is_some(),
        "public IPv6 services",
    )?;
    require(
        VPN_PORTAL_AVAILABLE,
        peer.vpn_portal_cidr.is_some(),
        "the VPN portal",
    )?;
    Ok(())
}

pub(super) fn validate(config: &CoreInstanceConfig) -> anyhow::Result<()> {
    validate_snapshot(&config.connectivity.runtime, &config.peer.snapshot)
}

pub(super) fn validate_runtime(
    config: &crate::config::runtime::CoreInstanceRuntimeConfig,
) -> anyhow::Result<()> {
    validate_snapshot(&config.services, &config.peer)
}
