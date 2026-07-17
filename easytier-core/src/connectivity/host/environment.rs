//! Host network facts and slow operations used by connector orchestration.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use serde::{Deserialize, Serialize};
use url::Url;

use crate::{
    connectivity::manual::ManualInterfaceAddrs, proto::peer_rpc::GetIpListResponse,
    socket::udp::PreferredIpv6Source,
};

/// Host-observed facts consumed by core connector policy.
///
/// The host normalizes this snapshot before constructing an instance. Core
/// owns all selection and connection policy applied to these facts.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct HostConnectorEnvironmentSnapshot {
    pub public_ipv4: Option<Ipv4Addr>,
    pub interface_ipv4s: Vec<Ipv4Addr>,
    pub public_ipv6: Option<Ipv6Addr>,
    pub interface_ipv6s: Vec<Ipv6Addr>,
    pub mapped_listeners: Vec<Url>,
    pub local_ips: Vec<IpAddr>,
    pub protected_tcp_ports: Vec<u16>,
    pub preferred_ipv6_sources: Vec<PreferredIpv6Source>,
}

impl HostConnectorEnvironmentSnapshot {
    pub(super) fn ip_list(&self) -> GetIpListResponse {
        GetIpListResponse {
            public_ipv4: self.public_ipv4.map(Into::into),
            interface_ipv4s: self
                .interface_ipv4s
                .iter()
                .copied()
                .map(Into::into)
                .collect(),
            public_ipv6: self.public_ipv6.map(Into::into),
            interface_ipv6s: self
                .interface_ipv6s
                .iter()
                .copied()
                .map(Into::into)
                .collect(),
            listeners: Default::default(),
        }
    }

    pub(super) fn manual_interface_addrs(&self) -> ManualInterfaceAddrs {
        ManualInterfaceAddrs {
            interface_ipv4s: self.interface_ipv4s.clone(),
            interface_ipv6s: self.interface_ipv6s.clone(),
            public_ipv6: self.public_ipv6,
        }
    }

    pub(super) fn preferred_ipv6_source(&self, ip: Ipv6Addr) -> Option<PreferredIpv6Source> {
        if ip.is_loopback()
            || ip.is_unspecified()
            || ip.is_unique_local()
            || ip.is_unicast_link_local()
            || ip.is_multicast()
        {
            return None;
        }
        self.preferred_ipv6_sources
            .iter()
            .find(|source| source.ip == ip)
            .copied()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn snapshot() -> HostConnectorEnvironmentSnapshot {
        HostConnectorEnvironmentSnapshot {
            public_ipv4: Some("198.51.100.1".parse().unwrap()),
            interface_ipv4s: vec!["192.0.2.1".parse().unwrap()],
            public_ipv6: Some("2001:db8::1".parse().unwrap()),
            interface_ipv6s: vec!["2001:db8::2".parse().unwrap()],
            mapped_listeners: vec!["tcp://198.51.100.1:11010".parse().unwrap()],
            local_ips: vec!["192.0.2.1".parse().unwrap()],
            protected_tcp_ports: vec![11010],
            preferred_ipv6_sources: vec![
                PreferredIpv6Source {
                    ip: "2001:db8::2".parse().unwrap(),
                    ifindex: 7,
                },
                PreferredIpv6Source {
                    ip: "fd00::1".parse().unwrap(),
                    ifindex: 8,
                },
            ],
        }
    }

    #[test]
    fn projects_normalized_snapshot() {
        let snapshot = snapshot();
        assert_eq!(
            serde_json::from_slice::<HostConnectorEnvironmentSnapshot>(
                &serde_json::to_vec(&snapshot).unwrap()
            )
            .unwrap(),
            snapshot
        );
        assert_eq!(
            snapshot.manual_interface_addrs().public_ipv6,
            Some("2001:db8::1".parse().unwrap())
        );
        assert_eq!(
            snapshot.ip_list().interface_ipv4s,
            vec![Ipv4Addr::new(192, 0, 2, 1).into()]
        );
        assert_eq!(
            snapshot.preferred_ipv6_source("2001:db8::2".parse().unwrap()),
            Some(PreferredIpv6Source {
                ip: "2001:db8::2".parse().unwrap(),
                ifindex: 7,
            })
        );
        assert_eq!(
            snapshot.preferred_ipv6_source("fd00::1".parse().unwrap()),
            None
        );
    }
}
