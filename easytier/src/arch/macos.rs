use std::net::Ipv4Addr;
use std::sync::Mutex;
use std::time::{Duration, Instant};

/// The IPv4 default route of the physical network, i.e. the route underlay
/// traffic should take to escape any TUN-based routing (easytier's own full
/// tunnel or third-party VPNs).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DefaultRouteV4 {
    pub gateway: Ipv4Addr,
    pub iface: String,
}

fn is_virtual_iface(name: &str) -> bool {
    name.starts_with("utun")
        || name.starts_with("tun")
        || name.starts_with("tap")
        || name.starts_with("feth")
        || name.starts_with("bridge")
        || name.starts_with("lo")
}

fn parse_default_route_v4(netstat_output: &str) -> Option<DefaultRouteV4> {
    for line in netstat_output.lines() {
        let fields: Vec<&str> = line.split_whitespace().collect();
        if fields.len() < 4 || fields[0] != "default" {
            continue;
        }
        let iface = fields[3];
        if is_virtual_iface(iface) {
            continue;
        }
        let Ok(gateway) = fields[1].parse::<Ipv4Addr>() else {
            continue;
        };
        if gateway.is_unspecified() || gateway.is_loopback() {
            continue;
        }
        return Some(DefaultRouteV4 {
            gateway,
            iface: iface.to_string(),
        });
    }
    None
}

const CACHE_TTL: Duration = Duration::from_secs(10);
// A failed lookup (e.g. a transient netstat hiccup while roaming) is retried
// much sooner: callers fall back to unbound sockets while this is cached, so
// staying in that state for the full TTL would reopen the routing loop the
// binding exists to prevent.
const CACHE_TTL_FAILURE: Duration = Duration::from_secs(1);

static DEFAULT_ROUTE_CACHE: Mutex<Option<(Instant, Option<DefaultRouteV4>)>> = Mutex::new(None);

/// Returns the physical (non-TUN) IPv4 default route, cached for a short TTL
/// so it is cheap enough to call on every socket creation.
pub fn get_default_route_v4() -> Option<DefaultRouteV4> {
    let mut cache = DEFAULT_ROUTE_CACHE.lock().unwrap();
    if let Some((refreshed_at, route)) = cache.as_ref() {
        let ttl = if route.is_some() {
            CACHE_TTL
        } else {
            CACHE_TTL_FAILURE
        };
        if refreshed_at.elapsed() < ttl {
            return route.clone();
        }
    }

    let route = std::process::Command::new("netstat")
        .args(["-rn", "-f", "inet"])
        .output()
        .ok()
        .filter(|output| output.status.success())
        .and_then(|output| parse_default_route_v4(&String::from_utf8_lossy(&output.stdout)));
    if route.is_none() {
        tracing::warn!("no physical ipv4 default route found");
    }
    *cache = Some((Instant::now(), route.clone()));
    route
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_picks_first_physical_default_route() {
        // Real netstat -rn output from a machine with dual physical uplinks
        // and a third-party VPN (utun5) owning split routes.
        let output = r#"Routing tables

Internet:
Destination        Gateway            Flags               Netif Expire
default            192.168.0.1        UGScg                 en0
default            192.168.0.1        UGScIg               en12
1                  198.18.0.1         UGSc                utun5
128.0/1            198.18.0.1         UGSc                utun5
127.0.0.1          127.0.0.1          UH                    lo0
"#;
        assert_eq!(
            parse_default_route_v4(output),
            Some(DefaultRouteV4 {
                gateway: "192.168.0.1".parse().unwrap(),
                iface: "en0".to_string(),
            })
        );
    }

    #[test]
    fn parse_skips_virtual_default_routes() {
        let output = r#"Destination        Gateway            Flags               Netif Expire
default            198.18.0.1         UGSc                utun5
default            10.8.0.1           UGSc                 tun0
default            192.168.1.1        UGScg                 en1
"#;
        assert_eq!(
            parse_default_route_v4(output),
            Some(DefaultRouteV4 {
                gateway: "192.168.1.1".parse().unwrap(),
                iface: "en1".to_string(),
            })
        );
    }

    #[test]
    fn parse_returns_none_without_physical_default_route() {
        let output = r#"Destination        Gateway            Flags               Netif Expire
default            198.18.0.1         UGSc                utun5
default            link#14            UCS                   en0
"#;
        assert_eq!(parse_default_route_v4(output), None);
    }
}
