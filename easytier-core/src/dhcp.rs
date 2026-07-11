use std::{collections::HashSet, net::Ipv4Addr};

use cidr::Ipv4Inet;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DhcpIpv4Decision {
    WaitForPeers,
    Unchanged,
    Change {
        previous: Option<Ipv4Inet>,
        next: Option<Ipv4Inet>,
    },
}

#[derive(Debug)]
pub struct DhcpIpv4Allocator {
    default_subnet: Ipv4Inet,
    current: Option<Ipv4Inet>,
}

impl Default for DhcpIpv4Allocator {
    fn default() -> Self {
        Self::new(Ipv4Inet::new(Ipv4Addr::new(10, 126, 126, 0), 24).unwrap())
    }
}

impl DhcpIpv4Allocator {
    pub fn new(default_subnet: Ipv4Inet) -> Self {
        Self {
            default_subnet,
            current: None,
        }
    }

    pub fn current(&self) -> Option<Ipv4Inet> {
        self.current
    }

    pub fn reset(&mut self) {
        self.current = None;
    }

    pub fn commit(&mut self, next: Option<Ipv4Inet>) {
        self.current = next;
    }

    pub fn evaluate(&self, has_routes: bool, used_ipv4: &HashSet<Ipv4Inet>) -> DhcpIpv4Decision {
        if !has_routes {
            return DhcpIpv4Decision::WaitForPeers;
        }

        let subnet = used_ipv4.iter().next().unwrap_or(&self.default_subnet);
        if let Some(current) = self.current
            && current.network() == subnet.network()
            && !used_ipv4.contains(&current)
        {
            return DhcpIpv4Decision::Unchanged;
        }

        let next = subnet.network().iter().find(|candidate| {
            candidate.address() != subnet.first_address()
                && candidate.address() != subnet.last_address()
                && !used_ipv4.contains(candidate)
        });
        if self.current == next {
            return DhcpIpv4Decision::Unchanged;
        }

        DhcpIpv4Decision::Change {
            previous: self.current,
            next,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn waits_until_at_least_one_route_exists() {
        let allocator = DhcpIpv4Allocator::default();

        assert_eq!(
            allocator.evaluate(false, &HashSet::new()),
            DhcpIpv4Decision::WaitForPeers
        );
    }

    #[test]
    fn uses_default_subnet_when_routes_have_no_ipv4() {
        let allocator = DhcpIpv4Allocator::default();

        assert_eq!(
            allocator.evaluate(true, &HashSet::new()),
            DhcpIpv4Decision::Change {
                previous: None,
                next: Some("10.126.126.1/24".parse().unwrap()),
            }
        );
    }

    #[test]
    fn keeps_current_address_when_it_is_free_in_the_selected_subnet() {
        let mut allocator = DhcpIpv4Allocator::default();
        allocator.commit(Some("10.1.2.8/24".parse().unwrap()));
        let used = HashSet::from(["10.1.2.2/24".parse().unwrap()]);

        assert_eq!(allocator.evaluate(true, &used), DhcpIpv4Decision::Unchanged);
    }

    #[test]
    fn selects_first_available_host_after_a_conflict() {
        let mut allocator = DhcpIpv4Allocator::default();
        allocator.commit(Some("10.1.2.1/24".parse().unwrap()));
        let used = HashSet::from([
            "10.1.2.1/24".parse().unwrap(),
            "10.1.2.2/24".parse().unwrap(),
        ]);

        assert_eq!(
            allocator.evaluate(true, &used),
            DhcpIpv4Decision::Change {
                previous: Some("10.1.2.1/24".parse().unwrap()),
                next: Some("10.1.2.3/24".parse().unwrap()),
            }
        );
    }

    #[test]
    fn reset_forgets_the_previous_interface_address() {
        let mut allocator = DhcpIpv4Allocator::default();
        allocator.commit(Some("10.1.2.8/24".parse().unwrap()));

        allocator.reset();

        assert_eq!(allocator.current(), None);
    }
}
