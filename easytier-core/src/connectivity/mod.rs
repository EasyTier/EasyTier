//! Portable connection orchestration.

use std::{
    fmt::Debug,
    net::{IpAddr, SocketAddr},
};

use url::Url;

use crate::socket::IpVersion;

pub mod composite;
pub mod direct;
pub mod hole_punch;
// Kept public: the host-driven adapter chain is WASI-only production code
// (cfg(target_os = "wasi")), so crate-private visibility would surface
// dead-code warnings on host builds for code that is live on WASI.
pub mod connector_host;
pub mod manual;
pub mod protocol;
pub mod stun;
pub mod transport;

/// Converts the optional underlay source IP into a bind address for one
/// address family. An address from the other family is deliberately ignored;
/// callers may then retain their existing automatic-selection behavior.
pub(crate) fn configured_bind_addr(
    bind_address: Option<IpAddr>,
    ip_version: IpVersion,
    port: u16,
) -> Option<SocketAddr> {
    let bind_address = bind_address?;
    match (bind_address, ip_version) {
        (IpAddr::V4(ip), IpVersion::V4 | IpVersion::Both) => {
            Some(SocketAddr::new(IpAddr::V4(ip), port))
        }
        (IpAddr::V6(ip), IpVersion::V6 | IpVersion::Both) => {
            Some(SocketAddr::new(IpAddr::V6(ip), port))
        }
        _ => None,
    }
}

/// Supplies the URLs of the instance's currently running listeners.
///
/// The listener layer's running-listener registry implements this seam.
/// Connectors use it to avoid dialing addresses that would hairpin back
/// into one of their own listeners, so connectivity depends on this narrow
/// query rather than on the listener module's concrete registry type.
pub trait LocalListenerUrls: Debug + Send + Sync + 'static {
    fn local_listener_urls(&self) -> Vec<Url>;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn configured_bind_addr_preserves_family_and_port() {
        let ipv4 = Some("192.0.2.10".parse().unwrap());
        assert_eq!(
            configured_bind_addr(ipv4, IpVersion::V4, 11010),
            Some("192.0.2.10:11010".parse().unwrap())
        );
        assert_eq!(configured_bind_addr(ipv4, IpVersion::V6, 11010), None);

        let ipv6 = Some("2001:db8::10".parse().unwrap());
        assert_eq!(
            configured_bind_addr(ipv6, IpVersion::V6, 21020),
            Some("[2001:db8::10]:21020".parse().unwrap())
        );
        assert_eq!(configured_bind_addr(None, IpVersion::Both, 0), None);
    }
}

/// Empty [`LocalListenerUrls`] for connectors that track no listeners.
#[derive(Debug, Default)]
pub struct NoLocalListeners;

impl LocalListenerUrls for NoLocalListeners {
    fn local_listener_urls(&self) -> Vec<Url> {
        Vec::new()
    }
}
