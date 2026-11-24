//! Temporary Windows IPv4 underlay routes for overlapping manual connectors.
use std::{
    collections::{BTreeMap, BTreeSet},
    io,
    net::Ipv4Addr,
    sync::{LazyLock, Mutex},
};

use cidr::Ipv4Cidr;
use uuid::Uuid;
use windows::Win32::{
    Foundation::{ERROR_OBJECT_ALREADY_EXISTS, NO_ERROR},
    NetworkManagement::{
        IpHelper::{
            CreateIpForwardEntry2, DeleteIpForwardEntry2, FreeMibTable, GetIpForwardEntry2,
            GetIpForwardTable2, GetIpInterfaceEntry, InitializeIpForwardEntry, MIB_IPFORWARD_ROW2,
            MIB_IPINTERFACE_ROW, SetIpForwardEntry2,
        },
        Ndis::NET_LUID_LH,
    },
    Networking::WinSock::{
        AF_INET, IN_ADDR, IN_ADDR_0, MIB_IPPROTO_NETMGMT, SOCKADDR_IN, SOCKADDR_INET,
    },
};

// The NIC updater renews these every 15 seconds. A killed process cannot leave a permanent bypass.
const LIFETIME: u32 = 60;
type Path = (u64, Ipv4Addr); // LUID, next hop (0.0.0.0 for on-link routes)

#[derive(Default)]
struct Claims {
    ifindex: u32,
    prefixes: BTreeSet<Ipv4Cidr>,
    endpoints: BTreeSet<Ipv4Addr>,
}

#[derive(Default)]
struct Leases {
    members: BTreeMap<Uuid, Claims>,
    owned: BTreeMap<Ipv4Addr, Path>,
}

static LEASES: LazyLock<Mutex<Leases>> = LazyLock::new(Default::default);

/// Each NIC updater owns one claim, even when several instances share the same NIC.
pub(crate) struct RelayRoutes(Uuid);

impl RelayRoutes {
    pub(crate) fn new(ifindex: u32) -> Self {
        let id = Uuid::new_v4();
        LEASES.lock().unwrap().members.insert(
            id,
            Claims {
                ifindex,
                ..Default::default()
            },
        );
        Self(id)
    }

    pub(crate) fn update(&self, prefixes: &BTreeSet<Ipv4Cidr>, endpoints: BTreeSet<Ipv4Addr>) {
        let mut leases = LEASES.lock().unwrap();
        let member = leases.members.get_mut(&self.0).unwrap();
        member.prefixes.clone_from(prefixes);
        member.endpoints = endpoints;
        leases.sync();
    }
}

impl Drop for RelayRoutes {
    fn drop(&mut self) {
        let mut leases = LEASES.lock().unwrap();
        leases.members.remove(&self.0);
        leases.sync();
    }
}

fn address(addr: Ipv4Addr) -> SOCKADDR_INET {
    SOCKADDR_INET {
        Ipv4: SOCKADDR_IN {
            sin_family: AF_INET,
            sin_addr: IN_ADDR {
                S_un: IN_ADDR_0 {
                    S_addr: u32::from_ne_bytes(addr.octets()),
                },
            },
            ..Default::default()
        },
    }
}

fn ipv4(addr: SOCKADDR_INET) -> Ipv4Addr {
    // The caller enumerates AF_INET only.
    Ipv4Addr::from(unsafe { addr.Ipv4.sin_addr.S_un.S_addr }.to_ne_bytes())
}

fn entry(ip: Ipv4Addr, (luid, gateway): Path) -> MIB_IPFORWARD_ROW2 {
    let mut row = MIB_IPFORWARD_ROW2::default();
    unsafe { InitializeIpForwardEntry(&mut row) };
    row.InterfaceLuid = NET_LUID_LH { Value: luid };
    row.DestinationPrefix.Prefix = address(ip);
    row.DestinationPrefix.PrefixLength = 32;
    row.NextHop = address(gateway);
    row.Metric = 0;
    row.Protocol = MIB_IPPROTO_NETMGMT;
    row.ValidLifetime = LIFETIME;
    row.PreferredLifetime = LIFETIME;
    row.Immortal = false;
    row
}

fn still_owned(ip: Ipv4Addr, path: Path) -> bool {
    let mut row = entry(ip, path);
    let protocol = row.Protocol;
    (unsafe { GetIpForwardEntry2(&mut row) == NO_ERROR })
        && row.Protocol == protocol
        && row.Metric == 0
        && row.ValidLifetime <= LIFETIME
        && !row.Immortal
}

fn routes() -> io::Result<Vec<MIB_IPFORWARD_ROW2>> {
    let mut table = std::ptr::null_mut();
    let result = unsafe { GetIpForwardTable2(AF_INET, &mut table) };
    if result != NO_ERROR {
        return Err(io::Error::from_raw_os_error(result.0 as i32));
    }
    // Table is owned by IP Helper and contains NumEntries contiguous rows.
    let rows = unsafe {
        let rows =
            std::slice::from_raw_parts((*table).Table.as_ptr(), (*table).NumEntries as usize)
                .to_vec();
        FreeMibTable(table.cast());
        rows
    };
    Ok(rows)
}

impl Leases {
    fn sync(&mut self) {
        let mut wanted = BTreeMap::new();
        for ip in self.members.values().flat_map(|m| &m.endpoints) {
            if ip.is_loopback() || ip.is_unspecified() || ip.is_multicast() || ip.is_broadcast() {
                continue;
            }
            if let Some(length) = self
                .members
                .values()
                .flat_map(|m| &m.prefixes)
                .filter(|p| p.contains(ip))
                .map(Ipv4Cidr::network_length)
                .max()
            {
                wanted.insert(*ip, length);
            }
        }
        if wanted.is_empty() && self.owned.is_empty() {
            return;
        }
        let rows = match routes() {
            Ok(rows) => rows,
            Err(error) => {
                tracing::warn!(%error, "cannot inspect relay routes");
                return;
            }
        };
        self.owned.retain(|ip, path| still_owned(*ip, *path));
        let mut metrics = BTreeMap::new();
        let mut desired = BTreeMap::new();
        for (ip, covering_len) in wanted {
            let best = rows
                .iter()
                .filter_map(|row| {
                    if self
                        .members
                        .values()
                        .any(|m| m.ifindex == row.InterfaceIndex)
                        || row.ValidLifetime == 0
                    {
                        return None;
                    }
                    let prefix = row.DestinationPrefix;
                    let len = prefix.PrefixLength;
                    if !Ipv4Cidr::new(ipv4(prefix.Prefix), len).ok()?.contains(&ip) {
                        return None;
                    }
                    let path = (unsafe { row.InterfaceLuid.Value }, ipv4(row.NextHop));
                    if len == 32 && self.owned.get(&ip) == Some(&path) {
                        return None;
                    }
                    let (metric, no_default) = (*metrics.entry(path.0).or_insert_with(|| {
                        let mut iface = MIB_IPINTERFACE_ROW {
                            Family: AF_INET,
                            InterfaceLuid: row.InterfaceLuid,
                            ..Default::default()
                        };
                        (unsafe { GetIpInterfaceEntry(&mut iface) } == NO_ERROR && iface.Connected)
                            .then_some((iface.Metric, iface.DisableDefaultRoutes))
                    }))?;
                    if len == 0 && no_default {
                        return None;
                    }
                    Some((32 - len, u64::from(metric) + u64::from(row.Metric), path))
                })
                .min();
            // Respect a user /32 and any existing route more specific than the advertisement.
            if let Some((inv_len, _, path)) = best
                && inv_len != 0
                && 32 - inv_len <= covering_len
            {
                desired.insert(ip, path);
            }
        }
        self.owned.retain(|ip, path| {
            if desired.get(ip) == Some(path) {
                return true;
            }
            let status = unsafe { DeleteIpForwardEntry2(&entry(*ip, *path)) };
            if status != NO_ERROR {
                tracing::warn!(%ip, ?status, "cannot remove temporary relay route");
                return true;
            }
            tracing::debug!(%ip, "removed temporary relay route");
            false
        });
        for (ip, path) in desired {
            let row = entry(ip, path);
            let renew = self.owned.get(&ip) == Some(&path);
            let status = unsafe {
                if renew {
                    SetIpForwardEntry2(&row)
                } else {
                    CreateIpForwardEntry2(&row)
                }
            };
            if status == NO_ERROR {
                self.owned.insert(ip, path);
                if !renew {
                    tracing::info!(%ip, luid = path.0, gateway = %path.1, "installed temporary relay /32");
                }
            } else if status != ERROR_OBJECT_ALREADY_EXISTS {
                tracing::warn!(%ip, ?status, "cannot protect relay route");
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use windows::Win32::NetworkManagement::IpHelper::GetBestRoute2;

    fn best_route(ip: Ipv4Addr) -> MIB_IPFORWARD_ROW2 {
        let mut row = MIB_IPFORWARD_ROW2::default();
        let mut source = SOCKADDR_INET::default();
        assert_eq!(
            unsafe { GetBestRoute2(None, 0, None, &address(ip), 0, &mut row, &mut source) },
            NO_ERROR
        );
        row
    }

    #[test]
    #[ignore = "requires isolated LabUnder /16 and LabAlt /24 Windows route fixture"]
    fn relay_host_route_lifecycle() {
        let under = crate::arch::windows::find_interface_index("LabUnder").unwrap();
        let tun = crate::arch::windows::find_interface_index("LabAlt").unwrap();
        let ip = Ipv4Addr::new(198, 18, 247, 42);
        let neighbor = Ipv4Addr::new(198, 18, 247, 43);
        let admin_ip = Ipv4Addr::new(198, 18, 247, 44); // fixture-owned /32
        let prefixes = BTreeSet::from(["198.18.247.0/24".parse().unwrap()]);
        let endpoints = BTreeSet::from([ip, admin_ip]);
        assert_eq!(best_route(ip).InterfaceIndex, tun);
        let admin = best_route(admin_ip);
        assert_eq!(
            (admin.InterfaceIndex, admin.DestinationPrefix.PrefixLength),
            (under, 32)
        );
        let first = RelayRoutes::new(tun);
        first.update(&prefixes, endpoints.clone());
        let protected = best_route(ip);
        assert_eq!(
            (
                protected.InterfaceIndex,
                protected.DestinationPrefix.PrefixLength
            ),
            (under, 32)
        );
        assert_eq!(best_route(neighbor).InterfaceIndex, tun);
        let second = RelayRoutes::new(tun);
        second.update(&prefixes, endpoints);
        drop(first);
        assert_eq!(best_route(ip).InterfaceIndex, under);
        second.update(&prefixes, BTreeSet::from([neighbor, admin_ip]));
        assert_eq!(best_route(ip).InterfaceIndex, tun);
        assert_eq!(best_route(neighbor).InterfaceIndex, under);
        drop(second);
        assert_eq!(best_route(neighbor).InterfaceIndex, tun);
        let after = best_route(admin_ip);
        assert_eq!(
            (after.InterfaceIndex, after.Metric, after.ValidLifetime),
            (admin.InterfaceIndex, admin.Metric, admin.ValidLifetime)
        );
    }
}
