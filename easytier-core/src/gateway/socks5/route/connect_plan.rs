use std::net::{IpAddr, Ipv4Addr, SocketAddr};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Socks5TcpRoute {
    Kernel,
    Smoltcp,
    Kcp,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct Socks5TcpConnectPlan {
    destination: SocketAddr,
    has_smoltcp_net: bool,
    kcp_available: bool,
}

impl Socks5TcpConnectPlan {
    pub fn new(
        destination: SocketAddr,
        local_virtual_ip: Option<IpAddr>,
        has_smoltcp_net: bool,
        kcp_available: bool,
    ) -> Self {
        let destination = if local_virtual_ip == Some(destination.ip()) {
            SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), destination.port())
        } else {
            destination
        };

        Self {
            destination,
            has_smoltcp_net,
            kcp_available,
        }
    }

    pub fn destination(self) -> SocketAddr {
        self.destination
    }

    pub fn needs_virtual_network_lookup(self) -> bool {
        self.has_smoltcp_net && !self.destination.ip().is_loopback()
    }

    pub fn route(
        self,
        destination_in_virtual_network: bool,
        destination_allows_kcp: bool,
    ) -> Socks5TcpRoute {
        if !self.needs_virtual_network_lookup() || !destination_in_virtual_network {
            Socks5TcpRoute::Kernel
        } else if self.kcp_available && destination_allows_kcp {
            Socks5TcpRoute::Kcp
        } else {
            Socks5TcpRoute::Smoltcp
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn virtual_destination(kcp_available: bool) -> Socks5TcpConnectPlan {
        Socks5TcpConnectPlan::new("10.1.1.2:443".parse().unwrap(), None, true, kcp_available)
    }

    #[test]
    fn kernel_route_covers_non_virtual_destinations() {
        assert_eq!(
            Socks5TcpConnectPlan::new("10.1.1.2:443".parse().unwrap(), None, false, false)
                .route(false, false),
            Socks5TcpRoute::Kernel
        );
        assert_eq!(
            virtual_destination(false).route(false, false),
            Socks5TcpRoute::Kernel
        );
    }

    #[test]
    fn kernel_route_covers_loopback_destination() {
        let plan = Socks5TcpConnectPlan::new("127.0.0.1:443".parse().unwrap(), None, true, true);

        assert!(!plan.needs_virtual_network_lookup());
        assert_eq!(plan.route(true, true), Socks5TcpRoute::Kernel);
    }

    #[test]
    fn virtual_route_uses_smoltcp_without_allowed_kcp() {
        assert_eq!(
            virtual_destination(false).route(true, false),
            Socks5TcpRoute::Smoltcp
        );
        assert_eq!(
            virtual_destination(true).route(true, false),
            Socks5TcpRoute::Smoltcp
        );
    }

    #[test]
    fn virtual_route_uses_kcp_only_when_available_and_allowed() {
        assert_eq!(
            virtual_destination(true).route(true, true),
            Socks5TcpRoute::Kcp
        );
    }

    #[test]
    fn local_virtual_destination_is_normalized_before_route_lookup() {
        let plan = Socks5TcpConnectPlan::new(
            "10.1.1.1:443".parse().unwrap(),
            Some("10.1.1.1".parse().unwrap()),
            true,
            true,
        );

        assert_eq!(plan.destination(), "127.0.0.1:443".parse().unwrap());
        assert!(!plan.needs_virtual_network_lookup());
        assert_eq!(plan.route(true, true), Socks5TcpRoute::Kernel);
    }
}
