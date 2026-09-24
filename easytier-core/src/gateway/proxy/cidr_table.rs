use std::net::IpAddr;
#[cfg(any(test, feature = "proxy-packet"))]
use std::net::Ipv4Addr;

use parking_lot::RwLock;

use crate::config::{IpPrefix, ProxyNetworkConfig};

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProxyCidrRule {
    pub cidr: cidr::Ipv4Cidr,
    pub mapped_cidr: Option<cidr::Ipv4Cidr>,
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct ProxyCidrSnapshot {
    pub rules: Vec<ProxyCidrRule>,
}

impl ProxyCidrSnapshot {
    pub fn from_proxy_networks(networks: &[ProxyNetworkConfig]) -> Self {
        Self {
            rules: networks.iter().filter_map(proxy_cidr_rule).collect(),
        }
    }
}

fn ipv4_cidr(prefix: &IpPrefix) -> Option<cidr::Ipv4Cidr> {
    let IpAddr::V4(address) = prefix.address else {
        return None;
    };
    cidr::Ipv4Cidr::new(address, prefix.prefix_len).ok()
}

fn proxy_cidr_rule(config: &ProxyNetworkConfig) -> Option<ProxyCidrRule> {
    Some(ProxyCidrRule {
        cidr: ipv4_cidr(&config.real)?,
        mapped_cidr: config.mapped.as_ref().and_then(ipv4_cidr),
    })
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct ProxyCidrEntry {
    real_cidr: cidr::Ipv4Cidr,
    mapped_cidr: cidr::Ipv4Cidr,
}

#[derive(Debug, Default)]
pub struct ProxyCidrTable {
    entries: RwLock<Vec<ProxyCidrEntry>>,
}

impl ProxyCidrTable {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn from_snapshot(snapshot: ProxyCidrSnapshot) -> Self {
        let table = Self::new();
        table.update_snapshot(snapshot);
        table
    }

    pub fn update_snapshot(&self, snapshot: ProxyCidrSnapshot) {
        let entries = snapshot
            .rules
            .into_iter()
            .map(|rule| ProxyCidrEntry {
                real_cidr: rule.cidr,
                mapped_cidr: rule.mapped_cidr.unwrap_or(rule.cidr),
            })
            .collect();
        *self.entries.write() = entries;
    }

    #[cfg(feature = "proxy-packet")]
    pub fn is_empty(&self) -> bool {
        self.entries.read().is_empty()
    }

    #[cfg(any(test, feature = "proxy-packet"))]
    pub fn lookup_v4(&self, ipv4: Ipv4Addr) -> Option<Ipv4Addr> {
        self.entries
            .read()
            .iter()
            .find_map(|entry| entry.lookup_v4(ipv4))
    }
}

impl ProxyCidrEntry {
    #[cfg(any(test, feature = "proxy-packet"))]
    fn lookup_v4(&self, ipv4: Ipv4Addr) -> Option<Ipv4Addr> {
        if !self.mapped_cidr.contains(&ipv4) {
            return None;
        }

        if self.mapped_cidr == self.real_cidr {
            return Some(ipv4);
        }

        let origin_network_bits = self.real_cidr.first().address().to_bits();
        let network_mask = self.mapped_cidr.mask().to_bits();
        let converted_ip = (ipv4.to_bits() & !network_mask) | origin_network_bits;
        Some(Ipv4Addr::from(converted_ip))
    }
}

#[cfg(test)]
mod tests {
    use crate::config::{IpPrefix, ProxyNetworkConfig};

    use super::*;

    #[test]
    fn lookup_returns_original_ip_for_unmapped_cidr() {
        let table = ProxyCidrTable::from_snapshot(ProxyCidrSnapshot {
            rules: vec![ProxyCidrRule {
                cidr: "127.0.0.0/24".parse().unwrap(),
                mapped_cidr: None,
            }],
        });

        assert_eq!(
            table.lookup_v4("127.0.0.42".parse().unwrap()),
            Some("127.0.0.42".parse().unwrap())
        );
        assert_eq!(table.lookup_v4("127.0.1.42".parse().unwrap()), None);
    }

    #[test]
    fn lookup_converts_mapped_cidr_to_real_cidr() {
        let table = ProxyCidrTable::from_snapshot(ProxyCidrSnapshot {
            rules: vec![ProxyCidrRule {
                cidr: "127.0.0.0/24".parse().unwrap(),
                mapped_cidr: Some("10.10.10.0/24".parse().unwrap()),
            }],
        });

        assert_eq!(
            table.lookup_v4("10.10.10.42".parse().unwrap()),
            Some("127.0.0.42".parse().unwrap())
        );
    }

    #[test]
    fn snapshot_normalizes_proxy_network_config() {
        let snapshot = ProxyCidrSnapshot::from_proxy_networks(&[ProxyNetworkConfig {
            real: IpPrefix {
                address: "192.0.2.0".parse().unwrap(),
                prefix_len: 24,
            },
            mapped: Some(IpPrefix {
                address: "198.51.100.0".parse().unwrap(),
                prefix_len: 24,
            }),
        }]);
        let table = ProxyCidrTable::from_snapshot(snapshot);

        assert_eq!(
            table.lookup_v4("198.51.100.42".parse().unwrap()),
            Some("192.0.2.42".parse().unwrap())
        );
    }
}
