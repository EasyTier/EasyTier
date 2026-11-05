use std::net::SocketAddr;

use educe::Educe;
use serde::{Deserialize, Serialize};

use super::IpVersion;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Educe)]
#[educe(Default)]
pub struct SocketContext {
    /// A socket that does not name a family lets the local address decide,
    /// which is what `Both` expresses.
    #[educe(Default = IpVersion::Both)]
    pub ip_version: IpVersion,
    pub socket_mark: Option<u32>,
}

/// Shared socket configuration for TCP and UDP, passed unchanged to the host.
///
/// Every field is public; construct it with struct update syntax. VPN bypass is
/// the default: a caller that omits `need_protect` still requests protection,
/// so forgetting the field never silently weakens the host contract. No OS
/// socket is created until a host executes the configuration.
///
/// ```
/// use easytier_core::socket::BindConfig;
///
/// let socket = BindConfig {
///     local_addr: Some("127.0.0.1:0".parse().unwrap()),
///     bind_device: Some(String::new()),
///     ..BindConfig::default()
/// };
/// assert!(socket.need_protect);
/// assert_eq!(socket.reuse_addr, None);
/// ```
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Educe)]
#[educe(Default)]
#[serde(default)]
pub struct BindConfig {
    pub context: SocketContext,
    /// Request VPN bypass before bind/connect/listen. Local/TUN-facing callers
    /// opt out explicitly. Accepted TCP children inherit this requirement.
    #[educe(Default = true)]
    pub need_protect: bool,
    pub local_addr: Option<SocketAddr>,
    /// None discovers the local address's device; an empty string disables
    /// device binding; a nonempty string selects that device explicitly.
    pub bind_device: Option<String>,
    /// None selects the host's default. Explicit true and false always win.
    pub reuse_addr: Option<bool>,
    pub reuse_port: bool,
    pub only_v6: bool,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_requests_protection_and_serde_keeps_tri_state_reuse() {
        assert!(BindConfig::default().need_protect);
        assert_eq!(BindConfig::default().context, SocketContext::default());
        for reuse in [None, Some(false), Some(true)] {
            let options = BindConfig {
                reuse_addr: reuse,
                bind_device: Some(String::new()),
                need_protect: false,
                ..BindConfig::default()
            };
            let restored: BindConfig =
                serde_json::from_str(&serde_json::to_string(&options).unwrap()).unwrap();
            assert_eq!(restored, options);
            assert_eq!(restored.reuse_addr, reuse);
        }
        let omitted: BindConfig = serde_json::from_str("{}").unwrap();
        assert_eq!(omitted, BindConfig::default());
        assert!(omitted.need_protect);
    }
}
