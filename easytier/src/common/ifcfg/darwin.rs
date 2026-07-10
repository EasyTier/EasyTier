use std::net::Ipv4Addr;

use super::{Error, IfConfiguerTrait, cidr_to_subnet_mask, run_shell_cmd};
use async_trait::async_trait;
use cidr::{Ipv4Inet, Ipv6Inet};

pub struct MacIfConfiger {}
#[async_trait]
impl IfConfiguerTrait for MacIfConfiger {
    async fn add_ipv4_route(
        &self,
        name: &str,
        address: Ipv4Addr,
        cidr_prefix: u8,
        cost: Option<i32>,
    ) -> Result<(), Error> {
        run_shell_cmd(
            format!(
                "route -n add {} -netmask {} -interface {} -hopcount {}",
                address,
                cidr_to_subnet_mask(cidr_prefix),
                name,
                cost.unwrap_or(7)
            )
            .as_str(),
        )
        .await
    }

    async fn remove_ipv4_route(
        &self,
        name: &str,
        address: Ipv4Addr,
        cidr_prefix: u8,
    ) -> Result<(), Error> {
        run_shell_cmd(
            format!(
                "route -n delete {} -netmask {} -interface {}",
                address,
                cidr_to_subnet_mask(cidr_prefix),
                name
            )
            .as_str(),
        )
        .await
    }

    async fn add_ipv4_ip(
        &self,
        name: &str,
        address: Ipv4Addr,
        cidr_prefix: u8,
    ) -> Result<(), Error> {
        run_shell_cmd(
            format!(
                "ifconfig {} {:?}/{:?} {:?} up",
                name, address, cidr_prefix, address,
            )
            .as_str(),
        )
        .await
    }

    async fn set_link_status(&self, name: &str, up: bool) -> Result<(), Error> {
        run_shell_cmd(format!("ifconfig {} {}", name, if up { "up" } else { "down" }).as_str())
            .await
    }

    async fn remove_ip(&self, name: &str, ip: Option<Ipv4Inet>) -> Result<(), Error> {
        if let Some(ip) = ip {
            run_shell_cmd(format!("ifconfig {} inet {} delete", name, ip.address()).as_str()).await
        } else {
            run_shell_cmd(format!("ifconfig {} inet delete", name).as_str()).await
        }
    }

    async fn set_mtu(&self, name: &str, mtu: u32) -> Result<(), Error> {
        run_shell_cmd(format!("ifconfig {} mtu {}", name, mtu).as_str()).await
    }

    async fn add_ipv6_ip(
        &self,
        name: &str,
        address: std::net::Ipv6Addr,
        cidr_prefix: u8,
    ) -> Result<(), Error> {
        run_shell_cmd(format!("ifconfig {} inet6 {}/{} add", name, address, cidr_prefix).as_str())
            .await
    }

    async fn remove_ipv6(&self, name: &str, ip: Option<Ipv6Inet>) -> Result<(), Error> {
        if let Some(ip) = ip {
            run_shell_cmd(format!("ifconfig {} inet6 {} delete", name, ip.address()).as_str()).await
        } else {
            // Remove all IPv6 addresses is more complex on macOS, just succeed
            Ok(())
        }
    }

    async fn add_ipv6_route(
        &self,
        name: &str,
        address: std::net::Ipv6Addr,
        cidr_prefix: u8,
        cost: Option<i32>,
    ) -> Result<(), Error> {
        let cmd = if let Some(cost) = cost {
            format!(
                "route -n add -inet6 {}/{} -interface {} -hopcount {}",
                address, cidr_prefix, name, cost
            )
        } else {
            format!(
                "route -n add -inet6 {}/{} -interface {}",
                address, cidr_prefix, name
            )
        };
        run_shell_cmd(cmd.as_str()).await
    }

    async fn remove_ipv6_route(
        &self,
        name: &str,
        address: std::net::Ipv6Addr,
        cidr_prefix: u8,
    ) -> Result<(), Error> {
        run_shell_cmd(
            format!(
                "route -n delete -inet6 {}/{} -interface {}",
                address, cidr_prefix, name
            )
            .as_str(),
        )
        .await
    }
}

impl MacIfConfiger {
    /// Add a gateway-form route (UGSc). Unlike `-interface` routes, these do
    /// not break IP_BOUND_IF-scoped sockets: the kernel can still route
    /// interface-scoped traffic around them, which is essential for underlay
    /// sockets while broad routes hijack the address space.
    pub async fn add_ipv4_route_via_gateway(
        &self,
        address: Ipv4Addr,
        cidr_prefix: u8,
        gateway: Ipv4Addr,
    ) -> Result<(), Error> {
        run_shell_cmd(
            format!(
                "route -n add {} -netmask {} {}",
                address,
                cidr_to_subnet_mask(cidr_prefix),
                gateway
            )
            .as_str(),
        )
        .await
    }

    /// Remove a route by destination and mask, regardless of its form.
    pub async fn remove_ipv4_route_any(
        &self,
        address: Ipv4Addr,
        cidr_prefix: u8,
    ) -> Result<(), Error> {
        run_shell_cmd(
            format!(
                "route -n delete {} -netmask {}",
                address,
                cidr_to_subnet_mask(cidr_prefix)
            )
            .as_str(),
        )
        .await
    }

    /// Look up the routing-table entry for exactly `address/cidr_prefix`.
    ///
    /// `route get` always answers with its longest-prefix match (querying a
    /// missing 1.0.0.0/8 returns the default route), so exactness is enforced
    /// here by comparing the reported destination/mask against the query.
    /// Returns None when no entry with exactly this destination/mask exists,
    /// letting callers verify ownership (gateway/interface) before deleting.
    pub async fn query_ipv4_route_exact(
        &self,
        address: Ipv4Addr,
        cidr_prefix: u8,
    ) -> Option<RouteGetEntry> {
        let mask = cidr_to_subnet_mask(cidr_prefix);
        let output = tokio::process::Command::new("route")
            .args(["-n", "get", &address.to_string(), "-netmask", &mask.to_string()])
            .output()
            .await
            .ok()?;
        if !output.status.success() {
            return None;
        }
        let entry = parse_route_get_output(&String::from_utf8_lossy(&output.stdout))?;
        if entry.destination == address && entry.mask == mask {
            Some(entry)
        } else {
            None
        }
    }
}

/// A routing-table entry as reported by `route -n get`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RouteGetEntry {
    pub destination: Ipv4Addr,
    pub mask: Ipv4Addr,
    /// None for interface-form / on-link entries (no IPv4 gateway).
    pub gateway: Option<Ipv4Addr>,
    pub iface: Option<String>,
}

/// Parse the plain-text output of `route -n get`. `destination`/`mask` may be
/// the literal `default` (0.0.0.0); a HOST entry carries no mask line
/// (implicit /32); `gateway` is absent for interface-form routes and non-IP
/// (`link#N`, MAC) for on-link clones.
fn parse_route_get_output(output: &str) -> Option<RouteGetEntry> {
    fn parse_quad(s: &str) -> Option<Ipv4Addr> {
        if s == "default" {
            return Some(Ipv4Addr::UNSPECIFIED);
        }
        // route(8) may abbreviate trailing zero octets ("128.0" == 128.0.0.0)
        let parts: Vec<&str> = s.split('.').collect();
        if parts.is_empty() || parts.len() > 4 {
            return None;
        }
        let mut octets = [0u8; 4];
        for (i, part) in parts.iter().enumerate() {
            octets[i] = part.parse().ok()?;
        }
        Some(Ipv4Addr::from(octets))
    }

    let mut destination = None;
    let mut mask = None;
    let mut gateway = None;
    let mut iface = None;
    let mut is_host = false;
    for line in output.lines() {
        let Some((key, value)) = line.split_once(':') else {
            continue;
        };
        let value = value.trim();
        match key.trim() {
            "destination" => destination = parse_quad(value),
            "mask" => mask = parse_quad(value),
            "gateway" => gateway = value.parse().ok(),
            "interface" => iface = Some(value.to_string()),
            "flags" => is_host = value.contains("HOST"),
            _ => {}
        }
    }
    let mask = match mask {
        Some(m) => m,
        // HOST entries have an implicit /32; anything else without a mask
        // line has an unknown shape — report no entry rather than guessing
        None if is_host => Ipv4Addr::BROADCAST,
        None => return None,
    };
    Some(RouteGetEntry {
        destination: destination?,
        mask,
        gateway,
        iface,
    })
}

#[cfg(test)]
mod route_get_tests {
    use super::*;

    #[test]
    fn parses_gateway_form_split_route() {
        let out = "   route to: 1.0.0.0\ndestination: 1.0.0.0\n       mask: 255.0.0.0\n    gateway: 10.126.126.13\n  interface: utun6\n      flags: <UP,GATEWAY,DONE,STATIC,PRCLONING,GLOBAL>\n";
        assert_eq!(
            parse_route_get_output(out),
            Some(RouteGetEntry {
                destination: "1.0.0.0".parse().unwrap(),
                mask: "255.0.0.0".parse().unwrap(),
                gateway: Some("10.126.126.13".parse().unwrap()),
                iface: Some("utun6".to_string()),
            })
        );
    }

    #[test]
    fn parses_lpm_fallback_to_default() {
        // querying a missing 1.0.0.0/8 answers with the default route; the
        // reported destination/mask expose the mismatch for the caller
        let out = "   route to: 1.0.0.0\ndestination: default\n       mask: default\n    gateway: 192.168.2.1\n  interface: en0\n";
        let entry = parse_route_get_output(out).unwrap();
        assert_eq!(entry.destination, Ipv4Addr::UNSPECIFIED);
        assert_eq!(entry.mask, Ipv4Addr::UNSPECIFIED);
    }

    #[test]
    fn parses_host_entry_without_mask_line() {
        let out = "   route to: 192.168.2.1\ndestination: 192.168.2.1\n  interface: en0\n      flags: <UP,HOST,DONE,LLINFO,WASCLONED,IFSCOPE,IFREF,ROUTER>\n";
        let entry = parse_route_get_output(out).unwrap();
        assert_eq!(entry.mask, Ipv4Addr::BROADCAST);
        assert_eq!(entry.gateway, None);
    }

    #[test]
    fn parses_interface_form_without_gateway() {
        let out = "   route to: 192.168.2.0\ndestination: 192.168.2.0\n       mask: 255.255.255.0\n  interface: en0\n      flags: <UP,DONE,CLONING,STATIC>\n";
        let entry = parse_route_get_output(out).unwrap();
        assert_eq!(entry.gateway, None);
        assert_eq!(entry.iface.as_deref(), Some("en0"));
    }

    #[test]
    fn rejects_garbage_and_unknown_shapes() {
        assert_eq!(parse_route_get_output("route: not in table\n"), None);
        // destination without mask and without HOST flag: unknown shape
        let out = "destination: 10.0.0.0\n  interface: en0\n";
        assert_eq!(parse_route_get_output(out), None);
    }
}
