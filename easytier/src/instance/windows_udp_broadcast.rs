use std::net::Ipv4Addr;

use easytier_core::gateway::udp_broadcast::PhysicalInterface;

#[cfg(all(windows, feature = "tun"))]
mod runtime;
#[cfg(all(windows, feature = "tun"))]
pub(crate) use runtime::start;

fn join_addr_equals(field: &str, addrs: &[Ipv4Addr]) -> String {
    addrs
        .iter()
        .map(|addr| format!("{field} == {addr}"))
        .collect::<Vec<_>>()
        .join(" or ")
}

fn build_windivert_udp_filter(physical_interfaces: &[PhysicalInterface]) -> String {
    let mut src_addrs = Vec::new();
    let mut directed_broadcasts = Vec::new();

    for iface in physical_interfaces {
        if !src_addrs.contains(&iface.address()) {
            src_addrs.push(iface.address());
        }
        if !directed_broadcasts.contains(&iface.directed_broadcast()) {
            directed_broadcasts.push(iface.directed_broadcast());
        }
    }

    if src_addrs.is_empty() {
        return "false".to_owned();
    }

    let src_filter = join_addr_equals("ip.SrcAddr", &src_addrs);
    let mut dst_filters = vec!["ip.DstAddr == 255.255.255.255".to_owned()];
    if !directed_broadcasts.is_empty() {
        dst_filters.push(join_addr_equals("ip.DstAddr", &directed_broadcasts));
    }
    dst_filters.push("(ip.DstAddr >= 224.0.0.0 and ip.DstAddr <= 239.255.255.255)".to_owned());

    format!(
        "outbound and ip and udp and ({}) and ({})",
        src_filter,
        dst_filters.join(" or ")
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn windows_udp_broadcast_windivert_filter_is_constrained() {
        let interfaces = vec![
            PhysicalInterface::from_ip_and_prefix(Ipv4Addr::new(192, 168, 1, 7), 24).unwrap(),
            PhysicalInterface::from_ip_and_prefix(Ipv4Addr::new(169, 254, 13, 10), 16).unwrap(),
            PhysicalInterface::from_ip_and_prefix(Ipv4Addr::new(169, 254, 156, 121), 16).unwrap(),
        ];

        let filter = build_windivert_udp_filter(&interfaces);

        assert!(filter.starts_with("outbound and ip and udp and "));
        assert!(filter.contains("ip.SrcAddr == 192.168.1.7"));
        assert!(filter.contains("ip.SrcAddr == 169.254.13.10"));
        assert!(filter.contains("ip.DstAddr == 255.255.255.255"));
        assert!(filter.contains("ip.DstAddr == 192.168.1.255"));
        assert!(filter.contains("ip.DstAddr == 169.254.255.255"));
        assert!(filter.contains("ip.DstAddr >= 224.0.0.0"));
        assert!(filter.contains("ip.DstAddr <= 239.255.255.255"));
        assert_eq!(filter.matches("ip.DstAddr == 169.254.255.255").count(), 1);
    }
}
