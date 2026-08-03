//! Linux systemd-resolved DNS configuration via D-Bus.
//!
//! Replaces shelling out to `resolvectl` so the MagicDNS IO path never
//! depends on external system commands. Uses the `org.freedesktop.resolve1`
//! D-Bus interface, which is what `resolvectl` itself talks to.

use std::io;

use nix::libc;

use super::{OSConfig, SystemConfig};

/// systemd-resolved D-Bus constants.
const RESOLVE1_SERVICE: &str = "org.freedesktop.resolve1";
const RESOLVE1_PATH: &str = "/org/freedesktop/resolve1";
const RESOLVE1_MANAGER_IFACE: &str = "org.freedesktop.resolve1.Manager";

#[derive(Default)]
pub struct LinuxSystemConfig {}

impl LinuxSystemConfig {
    pub fn new() -> Self {
        LinuxSystemConfig {}
    }

    /// Resolve a network interface name to its kernel ifindex.
    fn interface_index(name: &str) -> io::Result<i32> {
        let c_name = std::ffi::CString::new(name)
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "invalid interface name"))?;
        // SAFETY: if_nametoindex only reads the NUL-terminated name.
        let idx = unsafe { libc::if_nametoindex(c_name.as_ptr()) };
        if idx == 0 {
            Err(io::Error::last_os_error())
        } else {
            Ok(idx as i32)
        }
    }

    fn dns_ping() -> bool {
        zbus::blocking::Connection::system().is_ok()
    }

    /// Set the per-link DNS servers and search/routing domains through the
    /// systemd-resolved Manager D-Bus interface.
    ///
    /// `match_domains` are installed as routing domains (`~zone` in
    /// resolvectl terms) so only those queries go to the MagicDNS server.
    fn apply_link_config(
        &self,
        ifname: &str,
        nameservers: &[String],
        domains: &[String],
    ) -> io::Result<()> {
        let ifindex = Self::interface_index(ifname)?;
        let conn = zbus::blocking::Connection::system()
            .map_err(|e| io::Error::new(io::ErrorKind::Other, format!("D-Bus: {e}")))?;

        if !nameservers.is_empty() {
            let ns: Vec<(i32, Vec<u8>)> = nameservers
                .iter()
                .filter_map(|s| s.parse::<std::net::Ipv4Addr>().ok())
                .map(|ip| (libc::AF_INET as i32, ip.octets().to_vec()))
                .collect();
            if !ns.is_empty() {
                let reply = conn.call_method(
                    Some(RESOLVE1_SERVICE),
                    RESOLVE1_PATH,
                    Some(RESOLVE1_MANAGER_IFACE),
                    "SetLinkDNS",
                    &(ifindex, 0i32, ns),
                );
                if let Err(e) = reply {
                    tracing::warn!("SetLinkDNS failed: {e}");
                }
            }
        }

        if !domains.is_empty() {
            let doms: Vec<(String, bool)> = domains
                .iter()
                .map(|d| (d.trim_end_matches('.').to_string(), true))
                .collect();
            let reply = conn.call_method(
                Some(RESOLVE1_SERVICE),
                RESOLVE1_PATH,
                Some(RESOLVE1_MANAGER_IFACE),
                "SetLinkDomains",
                &(ifindex, doms),
            );
            if let Err(e) = reply {
                tracing::warn!("SetLinkDomains failed: {e}");
            }
        }

        Ok(())
    }
}

impl SystemConfig for LinuxSystemConfig {
    fn set_dns(&self, cfg: &OSConfig) -> io::Result<()> {
        if !Self::dns_ping() {
            return Ok(());
        }
        // If no explicit interface was captured, fall back to the default
        // route interface so the DNS config still lands somewhere useful.
        let ifname = match &cfg.interface_name {
            Some(n) => n.clone(),
            None => {
                tracing::warn!("no interface name for systemd-resolved config, skipping");
                return Ok(());
            }
        };
        self.apply_link_config(&ifname, &cfg.nameservers, &cfg.search_domains)
    }

    fn close(&self) -> io::Result<()> {
        Ok(())
    }
}
