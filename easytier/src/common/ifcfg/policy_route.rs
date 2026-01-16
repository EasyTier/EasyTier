//! Linux policy routing management.
//!
//! Implements IP rule add/delete operations to associate fwmark with routing tables.

use std::net::IpAddr;

use anyhow::Context;
use nix::libc;

use netlink_packet_core::{
    NetlinkHeader, NetlinkMessage, NetlinkPayload, NLM_F_ACK, NLM_F_CREATE, NLM_F_EXCL,
    NLM_F_REQUEST,
};
use netlink_packet_route::{
    route::{RouteAttribute, RouteMessage, RouteProtocol, RouteScope, RouteType},
    rule::{RuleAction, RuleAttribute, RuleMessage},
    AddressFamily, RouteNetlinkMessage,
};
use netlink_sys::{protocols::NETLINK_ROUTE, Socket, SocketAddr};

use super::fwmark::*;
use super::Error;

/// IP Rule definition.
struct IpRule {
    priority: u32,
    fwmark: Option<u32>,
    fwmask: Option<u32>,
    table: Option<u8>,
    action: RuleAction,
}

/// Send a netlink rule request.
fn send_rule_request(msg: RuleMessage, is_delete: bool) -> Result<(), Error> {
    let mut socket = Socket::new(NETLINK_ROUTE)?;
    socket.bind_auto()?;
    socket.connect(&SocketAddr::new(0, 0))?;

    let nlmsg = if is_delete {
        RouteNetlinkMessage::DelRule(msg)
    } else {
        RouteNetlinkMessage::NewRule(msg)
    };

    let mut req: NetlinkMessage<RouteNetlinkMessage> =
        NetlinkMessage::new(NetlinkHeader::default(), NetlinkPayload::InnerMessage(nlmsg));

    req.header.flags =
        NLM_F_REQUEST | NLM_F_ACK | if !is_delete { NLM_F_CREATE | NLM_F_EXCL } else { 0 };
    req.finalize();

    let mut buf = vec![0; req.header.length as usize];
    req.serialize(&mut buf);

    tracing::trace!(?req, "sending rule request");
    socket.send(&buf, 0)?;

    let resp = socket.recv_from_full()?;
    let ret = NetlinkMessage::<RouteNetlinkMessage>::deserialize(&resp.0)
        .with_context(|| "Failed to deserialize netlink message")?;

    tracing::trace!(?ret, "rule response");

    match ret.payload {
        NetlinkPayload::Error(e) => {
            let code = e.code.map(|c| c.get()).unwrap_or(0);
            if code == 0 {
                Ok(())
            } else if is_delete && code == -libc::ENOENT {
                // Rule doesn't exist when deleting, ignore
                Ok(())
            } else if !is_delete && code == -libc::EEXIST {
                // Rule already exists when adding, ignore
                Ok(())
            } else {
                Err(e.to_io().into())
            }
        }
        _ => Ok(()),
    }
}

/// Build a RuleMessage from IpRule.
fn build_rule_message(rule: &IpRule, family: AddressFamily) -> RuleMessage {
    let mut msg = RuleMessage::default();
    msg.header.family = family;
    msg.header.action = rule.action;

    msg.attributes.push(RuleAttribute::Priority(rule.priority));

    if let Some(mark) = rule.fwmark {
        msg.attributes.push(RuleAttribute::FwMark(mark));
    }

    if let Some(mask) = rule.fwmask {
        msg.attributes.push(RuleAttribute::FwMask(mask));
    }

    if let Some(table) = rule.table {
        msg.attributes.push(RuleAttribute::Table(table as u32));
    }

    msg
}

/// Get the IP rules used by EasyTier.
fn get_easytier_rules() -> Vec<IpRule> {
    vec![
        // Bypass-marked traffic looks up main table (physical network)
        IpRule {
            priority: rule_priority(IP_RULE_OFFSET_MAIN),
            fwmark: Some(ET_BYPASS_MARK),
            fwmask: Some(ET_FWMARK_MASK),
            table: Some(RT_TABLE_MAIN),
            action: RuleAction::ToTable,
        },
        // Bypass-marked traffic looks up default table (fallback)
        IpRule {
            priority: rule_priority(IP_RULE_OFFSET_DEFAULT),
            fwmark: Some(ET_BYPASS_MARK),
            fwmask: Some(ET_FWMARK_MASK),
            table: Some(RT_TABLE_DEFAULT),
            action: RuleAction::ToTable,
        },
        // Bypass-marked traffic with no route returns unreachable (prevents loops)
        IpRule {
            priority: rule_priority(IP_RULE_OFFSET_UNREACHABLE),
            fwmark: Some(ET_BYPASS_MARK),
            fwmask: Some(ET_FWMARK_MASK),
            table: None,
            action: RuleAction::Unreachable,
        },
        // Regular traffic (no fwmark) looks up EasyTier routing table
        IpRule {
            priority: rule_priority(IP_RULE_OFFSET_VPN),
            fwmark: None,
            fwmask: None,
            table: Some(EASYTIER_ROUTE_TABLE),
            action: RuleAction::ToTable,
        },
    ]
}

/// Add all EasyTier IP rules.
pub fn add_ip_rules() -> Result<(), Error> {
    // Note: We don't delete existing rules first to avoid a brief period without rules.
    // send_rule_request already ignores EEXIST errors for add operations.
    let rules = get_easytier_rules();

    for rule in &rules {
        // IPv4
        let msg = build_rule_message(rule, AddressFamily::Inet);
        if let Err(e) = send_rule_request(msg, false) {
            tracing::warn!(?e, priority = rule.priority, "failed to add IPv4 rule");
        }

        // IPv6
        let msg = build_rule_message(rule, AddressFamily::Inet6);
        if let Err(e) = send_rule_request(msg, false) {
            tracing::warn!(?e, priority = rule.priority, "failed to add IPv6 rule");
        }
    }

    tracing::info!("EasyTier IP rules added");
    Ok(())
}

/// Delete all EasyTier IP rules.
pub fn del_ip_rules() -> Result<(), Error> {
    let rules = get_easytier_rules();

    for rule in &rules {
        // IPv4
        let msg = build_rule_message(rule, AddressFamily::Inet);
        let _ = send_rule_request(msg, true);

        // IPv6
        let msg = build_rule_message(rule, AddressFamily::Inet6);
        let _ = send_rule_request(msg, true);
    }

    tracing::info!("EasyTier IP rules removed");
    Ok(())
}

// ============================================================================
// PID File Management for Multi-Instance Support
// ============================================================================

const PID_DIR: &str = "/tmp/easytier";

/// Get the PID file path for the current process.
fn get_pid_file_path() -> std::path::PathBuf {
    std::path::PathBuf::from(PID_DIR).join(format!("et_{}.pid", std::process::id()))
}

/// Create PID file for this instance.
pub fn create_pid_file() -> Result<(), Error> {
    let pid_dir = std::path::Path::new(PID_DIR);
    if !pid_dir.exists() {
        std::fs::create_dir_all(pid_dir)?;
    }

    let pid_file = get_pid_file_path();
    std::fs::write(&pid_file, std::process::id().to_string())?;
    tracing::debug!(?pid_file, "created PID file");
    Ok(())
}

/// Remove PID file for this instance.
pub fn remove_pid_file() {
    let pid_file = get_pid_file_path();
    if pid_file.exists() {
        let _ = std::fs::remove_file(&pid_file);
        tracing::debug!(?pid_file, "removed PID file");
    }
}

/// Check if a PID is still alive.
fn is_pid_alive(pid: u32) -> bool {
    // Check if process exists by sending signal 0
    unsafe { libc::kill(pid as i32, 0) == 0 }
}

/// Count how many EasyTier instances are currently running.
fn count_alive_instances() -> usize {
    let pid_dir = std::path::Path::new(PID_DIR);
    if !pid_dir.exists() {
        return 0;
    }

    let current_pid = std::process::id();
    let mut count = 0;

    if let Ok(entries) = std::fs::read_dir(pid_dir) {
        for entry in entries.flatten() {
            let path = entry.path();
            if path.extension().map(|e| e == "pid").unwrap_or(false) {
                if let Ok(content) = std::fs::read_to_string(&path) {
                    if let Ok(pid) = content.trim().parse::<u32>() {
                        // Skip our own PID
                        if pid == current_pid {
                            continue;
                        }
                        if is_pid_alive(pid) {
                            count += 1;
                        } else {
                            // Clean up stale PID file
                            let _ = std::fs::remove_file(&path);
                            tracing::debug!(?path, pid, "cleaned up stale PID file");
                        }
                    }
                }
            }
        }
    }

    count
}

/// Delete IP rules only if this is the last instance.
///
/// Returns true if rules were deleted, false if other instances are still running.
pub fn del_ip_rules_if_last() -> bool {
    // First remove our own PID file
    remove_pid_file();

    // Check if there are other alive instances
    let other_instances = count_alive_instances();
    if other_instances > 0 {
        tracing::info!(
            other_instances,
            "other EasyTier instances are running, keeping IP rules"
        );
        return false;
    }

    // We are the last instance, delete the rules
    if let Err(e) = del_ip_rules() {
        tracing::warn!(?e, "failed to delete IP rules");
    }
    true
}

/// Add a throw route to the EasyTier routing table.
///
/// A throw route terminates lookup and returns "no route", used to exclude local subnets.
pub fn add_throw_route(destination: IpAddr, prefix: u8) -> Result<(), Error> {
    let mut msg = RouteMessage::default();

    msg.header.table = EASYTIER_ROUTE_TABLE;
    msg.header.protocol = RouteProtocol::Static;
    msg.header.scope = RouteScope::Universe;
    msg.header.kind = RouteType::Throw;

    match destination {
        IpAddr::V4(addr) => {
            msg.header.address_family = AddressFamily::Inet;
            msg.header.destination_prefix_length = prefix;
            msg.attributes.push(RouteAttribute::Destination(
                netlink_packet_route::route::RouteAddress::Inet(addr),
            ));
        }
        IpAddr::V6(addr) => {
            msg.header.address_family = AddressFamily::Inet6;
            msg.header.destination_prefix_length = prefix;
            msg.attributes.push(RouteAttribute::Destination(
                netlink_packet_route::route::RouteAddress::Inet6(addr),
            ));
        }
    }

    let mut socket = Socket::new(NETLINK_ROUTE)?;
    socket.bind_auto()?;
    socket.connect(&SocketAddr::new(0, 0))?;

    let nlmsg = RouteNetlinkMessage::NewRoute(msg);
    let mut req: NetlinkMessage<RouteNetlinkMessage> =
        NetlinkMessage::new(NetlinkHeader::default(), NetlinkPayload::InnerMessage(nlmsg));

    req.header.flags = NLM_F_REQUEST | NLM_F_ACK | NLM_F_CREATE;
    req.finalize();

    let mut buf = vec![0; req.header.length as usize];
    req.serialize(&mut buf);
    socket.send(&buf, 0)?;

    let resp = socket.recv_from_full()?;
    let ret = NetlinkMessage::<RouteNetlinkMessage>::deserialize(&resp.0)
        .with_context(|| "Failed to deserialize netlink message")?;

    match ret.payload {
        NetlinkPayload::Error(e) => {
            let code = e.code.map(|c| c.get()).unwrap_or(0);
            if code == 0 || code == -libc::EEXIST {
                Ok(())
            } else {
                Err(e.to_io().into())
            }
        }
        _ => Ok(()),
    }
}

/// Delete a throw route.
pub fn del_throw_route(destination: IpAddr, prefix: u8) -> Result<(), Error> {
    let mut msg = RouteMessage::default();

    msg.header.table = EASYTIER_ROUTE_TABLE;
    msg.header.protocol = RouteProtocol::Static;
    msg.header.scope = RouteScope::Universe;
    msg.header.kind = RouteType::Throw;

    match destination {
        IpAddr::V4(addr) => {
            msg.header.address_family = AddressFamily::Inet;
            msg.header.destination_prefix_length = prefix;
            msg.attributes.push(RouteAttribute::Destination(
                netlink_packet_route::route::RouteAddress::Inet(addr),
            ));
        }
        IpAddr::V6(addr) => {
            msg.header.address_family = AddressFamily::Inet6;
            msg.header.destination_prefix_length = prefix;
            msg.attributes.push(RouteAttribute::Destination(
                netlink_packet_route::route::RouteAddress::Inet6(addr),
            ));
        }
    }

    let mut socket = Socket::new(NETLINK_ROUTE)?;
    socket.bind_auto()?;
    socket.connect(&SocketAddr::new(0, 0))?;

    let nlmsg = RouteNetlinkMessage::DelRoute(msg);
    let mut req: NetlinkMessage<RouteNetlinkMessage> =
        NetlinkMessage::new(NetlinkHeader::default(), NetlinkPayload::InnerMessage(nlmsg));

    req.header.flags = NLM_F_REQUEST | NLM_F_ACK;
    req.finalize();

    let mut buf = vec![0; req.header.length as usize];
    req.serialize(&mut buf);
    socket.send(&buf, 0)?;

    // Check response, but ignore ENOENT (route doesn't exist)
    let resp = socket.recv_from_full()?;
    if let Ok(ret) = NetlinkMessage::<RouteNetlinkMessage>::deserialize(&resp.0) {
        if let NetlinkPayload::Error(e) = ret.payload {
            let code = e.code.map(|c| c.get()).unwrap_or(0);
            if code != 0 && code != -libc::ENOENT {
                tracing::warn!(
                    ?destination,
                    prefix,
                    code,
                    "failed to delete throw route"
                );
            }
        }
    }
    Ok(())
}

/// Add throw routes for all local network interfaces.

pub fn add_local_throw_routes(exclude_iface: &str) -> Result<(), Error> {
    use network_interface::{NetworkInterface, NetworkInterfaceConfig};

    let interfaces = NetworkInterface::show().map_err(|e| anyhow::anyhow!("{}", e))?;

    for iface in interfaces {
        // Skip the EasyTier TUN interface itself
        if iface.name == exclude_iface {
            continue;
        }

        // Skip loopback
        if iface.name == "lo" || iface.name.starts_with("lo") {
            continue;
        }

        for addr in iface.addr {
            let (ip, prefix) = match addr {
                network_interface::Addr::V4(v4) => {
                    let prefix = v4.netmask.map(|m| {
                        let bits: u32 = u32::from(m);
                        bits.count_ones() as u8
                    }).unwrap_or(24);
                    // Skip host routes and default routes
                    if prefix == 32 || prefix == 0 {
                        continue;
                    }
                    (std::net::IpAddr::V4(v4.ip), prefix)
                }
                network_interface::Addr::V6(v6) => {
                    let prefix = v6.netmask.map(|m| {
                        let bits: u128 = u128::from(m);
                        bits.count_ones() as u8
                    }).unwrap_or(64);
                    // Skip link-local, host routes
                    if v6.ip.is_loopback() || prefix == 128 || prefix == 0 {
                        continue;
                    }
                    // Skip link-local addresses (fe80::/10)
                    if (v6.ip.segments()[0] & 0xffc0) == 0xfe80 {
                        continue;
                    }
                    (std::net::IpAddr::V6(v6.ip), prefix)
                }
            };

            // Calculate network address
            let network_addr = match ip {
                std::net::IpAddr::V4(v4) => {
                    let mask = if prefix == 0 { 0 } else { !0u32 << (32 - prefix) };
                    let network = u32::from(v4) & mask;
                    std::net::IpAddr::V4(std::net::Ipv4Addr::from(network))
                }
                std::net::IpAddr::V6(v6) => {
                    let mask = if prefix == 0 { 0 } else { !0u128 << (128 - prefix) };
                    let network = u128::from(v6) & mask;
                    std::net::IpAddr::V6(std::net::Ipv6Addr::from(network))
                }
            };

            if let Err(e) = add_throw_route(network_addr, prefix) {
                tracing::debug!(
                    ?e,
                    iface = %iface.name,
                    cidr = %format!("{}/{}", network_addr, prefix),
                    "failed to add throw route for local subnet"
                );
            } else {
                tracing::info!(
                    iface = %iface.name,
                    cidr = %format!("{}/{}", network_addr, prefix),
                    "added throw route for local subnet"
                );
            }
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_rule_lifecycle() {
        // This test requires root privileges
        if let Err(e) = add_ip_rules() {
            if let Some(os_err) = e.source().and_then(|e| e.downcast_ref::<std::io::Error>()) {
                if os_err.raw_os_error() == Some(libc::EPERM) {
                    eprintln!("Skipping test: root required");
                    return;
                }
            }
            panic!("add_ip_rules failed: {:?}", e);
        }

        // Cleanup
        del_ip_rules().unwrap();
    }
}
