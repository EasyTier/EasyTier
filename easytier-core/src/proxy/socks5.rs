use std::net::SocketAddr;

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
#[repr(u8)]
pub enum Socks5EntryKind {
    Udp = 1,
    Tcp = 2,
    TcpListen = 3,
}

#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub struct Socks5Entry {
    pub src: SocketAddr,
    pub dst: SocketAddr,
    pub kind: Socks5EntryKind,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Socks5TcpRoute {
    Kernel,
    Smoltcp,
    Kcp,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Socks5TcpRouteContext {
    pub has_smoltcp_net: bool,
    pub destination_in_virtual_network: bool,
    pub destination_is_loopback: bool,
    pub kcp_available: bool,
    pub destination_allows_kcp: bool,
}

impl Socks5TcpRouteContext {
    pub fn routes_over_virtual_network(self) -> bool {
        self.has_smoltcp_net && self.destination_in_virtual_network && !self.destination_is_loopback
    }

    pub fn route(self) -> Socks5TcpRoute {
        if !self.routes_over_virtual_network() {
            Socks5TcpRoute::Kernel
        } else if self.kcp_available && self.destination_allows_kcp {
            Socks5TcpRoute::Kcp
        } else {
            Socks5TcpRoute::Smoltcp
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{Socks5EntryKind, Socks5TcpRoute, Socks5TcpRouteContext};

    #[test]
    fn entry_kind_values_preserve_native_table_identity() {
        assert_eq!(Socks5EntryKind::Udp as u8, 1);
        assert_eq!(Socks5EntryKind::Tcp as u8, 2);
        assert_eq!(Socks5EntryKind::TcpListen as u8, 3);
    }

    fn virtual_destination() -> Socks5TcpRouteContext {
        Socks5TcpRouteContext {
            has_smoltcp_net: true,
            destination_in_virtual_network: true,
            ..Default::default()
        }
    }

    #[test]
    fn kernel_route_covers_non_virtual_destinations() {
        assert_eq!(
            Socks5TcpRouteContext::default().route(),
            Socks5TcpRoute::Kernel
        );
        assert_eq!(
            Socks5TcpRouteContext {
                has_smoltcp_net: true,
                ..Default::default()
            }
            .route(),
            Socks5TcpRoute::Kernel
        );
        assert_eq!(
            Socks5TcpRouteContext {
                destination_is_loopback: true,
                ..virtual_destination()
            }
            .route(),
            Socks5TcpRoute::Kernel
        );
    }

    #[test]
    fn virtual_route_uses_smoltcp_without_allowed_kcp() {
        assert_eq!(virtual_destination().route(), Socks5TcpRoute::Smoltcp);
        assert_eq!(
            Socks5TcpRouteContext {
                kcp_available: true,
                ..virtual_destination()
            }
            .route(),
            Socks5TcpRoute::Smoltcp
        );
        assert_eq!(
            Socks5TcpRouteContext {
                destination_allows_kcp: true,
                ..virtual_destination()
            }
            .route(),
            Socks5TcpRoute::Smoltcp
        );
    }

    #[test]
    fn virtual_route_uses_kcp_only_when_available_and_allowed() {
        assert_eq!(
            Socks5TcpRouteContext {
                kcp_available: true,
                destination_allows_kcp: true,
                ..virtual_destination()
            }
            .route(),
            Socks5TcpRoute::Kcp
        );
    }
}
