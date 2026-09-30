//! Compile-time capability selection for portable Instance validation.

use super::CoreInstanceHostConfig;
use crate::config::InstanceConfigParsed;

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

pub(crate) fn validate(
    config: &InstanceConfigParsed,
    host: &CoreInstanceHostConfig,
) -> anyhow::Result<()> {
    require(DHCP_IPV4_AVAILABLE, config.dhcp, "DHCP IPv4")?;
    require(
        SMOLTCP_GATEWAY_AVAILABLE,
        config.socks5_proxy.is_some() || !config.port_forward.is_empty(),
        "the smoltcp gateway",
    )?;
    require(
        PROXY_CIDR_MONITOR_AVAILABLE,
        config
            .routes
            .as_ref()
            .is_some_and(|routes| !routes.is_empty()),
        "the proxy CIDR monitor",
    )?;
    require(
        WRAPPED_TRANSPORT_AVAILABLE,
        !config.proxy_network.is_empty(),
        "proxy routing services",
    )?;
    let has_proxy_networks = !config.proxy_network.is_empty();
    let should_start_packet_proxy =
        (has_proxy_networks || config.flags.enable_exit_node || host.force_exit_node)
            && (!config.flags.proxy_forward_by_system || config.flags.no_tun);
    require(
        PACKET_PROXY_AVAILABLE,
        should_start_packet_proxy,
        "packet proxy services",
    )?;
    require(
        PUBLIC_IPV6_AVAILABLE,
        config.ipv6_public_addr_auto
            || config.ipv6_public_addr_provider
            || config.ipv6_public_addr_prefix.is_some(),
        "public IPv6 services",
    )?;
    require(
        VPN_PORTAL_AVAILABLE,
        config.vpn_portal_config.is_some(),
        "the VPN portal",
    )
}
