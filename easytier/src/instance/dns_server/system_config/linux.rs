#[cfg(test)]
mod resolved_fixture;

use std::{
    fs, io,
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
    sync::Mutex,
    time::Duration,
};

use serde::Serialize;
use zbus::{
    blocking::{Connection, Proxy, connection::Builder, proxy::Builder as ProxyBuilder},
    names::OwnedUniqueName,
    proxy::{CacheProperties, MethodFlags},
    zvariant::{DynamicType, OwnedObjectPath},
};

use super::{OSConfig, SystemConfig};

const RESOLVED_SERVICE: &str = "org.freedesktop.resolve1";
const RESOLVED_MANAGER_PATH: &str = "/org/freedesktop/resolve1";
const RESOLVED_MANAGER_INTERFACE: &str = "org.freedesktop.resolve1.Manager";
const RESOLVED_LINK_INTERFACE: &str = "org.freedesktop.resolve1.Link";
const NETWORKD_SERVICE: &str = "org.freedesktop.network1";
const NETWORKD_MANAGER_PATH: &str = "/org/freedesktop/network1";
const NETWORKD_MANAGER_INTERFACE: &str = "org.freedesktop.network1.Manager";
const LINK_BUSY_ERROR: &str = "org.freedesktop.resolve1.LinkBusy";
const DBUS_METHOD_TIMEOUT: Duration = Duration::from_secs(30);

pub fn new_configurator(interface: &str) -> io::Result<Box<dyn SystemConfig>> {
    let resolv_conf = fs::read_to_string("/etc/resolv.conf")?;
    let nsswitch = fs::read_to_string("/etc/nsswitch.conf").unwrap_or_default();
    // A previous file takeover must recover before any adapter reads upstreams,
    // even if NSS was changed to resolved while the old process was stopped.
    if !super::resolv_conf::ResolvConfConfigurator::needs_recovery(&resolv_conf)
        && ResolvedConfigurator::uses_resolved(&resolv_conf, &nsswitch)
    {
        Ok(Box::new(ResolvedConfigurator::new(interface)))
    } else {
        let configer = super::resolv_conf::ResolvConfConfigurator::new("/etc/resolv.conf".into());
        configer.check_support()?;
        Ok(Box::new(configer))
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct LinkConfig {
    nameservers: Vec<IpAddr>,
    domains: Vec<String>,
    default_route: bool,
}

struct LinkState {
    config: LinkConfig,
    owner: OwnedUniqueName,
}

struct AppliedConfig {
    original: LinkConfig,
    current: LinkConfig,
    desired: LinkConfig,
    owner: OwnedUniqueName,
}

/// Only configures the EasyTier link. Other links retain their DNS settings.
pub struct ResolvedConfigurator {
    interface: String,
    connection: Mutex<Option<Connection>>,
    check_query_path: fn() -> io::Result<()>,
    applied: Mutex<Option<AppliedConfig>>,
}

impl ResolvedConfigurator {
    pub fn new(interface: &str) -> Self {
        Self {
            interface: interface.to_owned(),
            connection: Mutex::new(None),
            check_query_path: Self::ensure_resolved_in_query_path,
            applied: Mutex::new(None),
        }
    }

    #[cfg(test)]
    fn with_connection(
        interface: &str,
        connection: Connection,
        check_query_path: fn() -> io::Result<()>,
    ) -> Self {
        Self {
            interface: interface.to_owned(),
            connection: Mutex::new(Some(connection)),
            check_query_path,
            applied: Mutex::new(None),
        }
    }

    fn connection(&self) -> zbus::Result<Connection> {
        let mut connection = self.connection.lock().unwrap();
        if let Some(connection) = connection.as_ref() {
            return Ok(connection.clone());
        }
        let new = Builder::system()
            .and_then(|builder| builder.method_timeout(DBUS_METHOD_TIMEOUT).build())?;
        *connection = Some(new.clone());
        Ok(new)
    }

    fn dbus_error(context: &str, error: zbus::Error) -> io::Error {
        let kind = match &error {
            zbus::Error::InputOutput(error) | zbus::Error::Connection(error, _) => error.kind(),
            zbus::Error::FDO(error)
                if matches!(
                    error.as_ref(),
                    zbus::fdo::Error::AccessDenied(_)
                        | zbus::fdo::Error::InteractiveAuthorizationRequired(_)
                ) =>
            {
                io::ErrorKind::PermissionDenied
            }
            zbus::Error::MethodError(name, _, _)
                if matches!(
                    name.as_str(),
                    "org.freedesktop.DBus.Error.AccessDenied"
                        | "org.freedesktop.DBus.Error.InteractiveAuthorizationRequired"
                ) =>
            {
                io::ErrorKind::PermissionDenied
            }
            _ => io::ErrorKind::Other,
        };
        io::Error::new(
            kind,
            format!("Magic DNS D-Bus call failed while {context}: {error}"),
        )
    }

    fn ifindex(&self) -> io::Result<i32> {
        let ifindex = nix::net::if_::if_nametoindex(self.interface.as_str()).map_err(|error| {
            io::Error::new(
                io::ErrorKind::NotFound,
                format!(
                    "Cannot find Magic DNS interface {}: {error}",
                    self.interface
                ),
            )
        })?;
        i32::try_from(ifindex).map_err(|_| {
            io::Error::other(format!(
                "Magic DNS interface index {ifindex} exceeds the resolved API range"
            ))
        })
    }

    pub(super) fn uses_resolved(resolv_conf: &str, nsswitch: &str) -> bool {
        resolv_conf.lines().any(|line| {
            let mut words = line
                .split('#')
                .next()
                .unwrap_or_default()
                .split_whitespace();
            words.next() == Some("nameserver")
                && matches!(words.next(), Some("127.0.0.53" | "127.0.0.54"))
        }) || nsswitch.lines().any(|line| {
            let mut words = line
                .split('#')
                .next()
                .unwrap_or_default()
                .split_whitespace();
            words.next() == Some("hosts:") && words.any(|word| word == "resolve")
        })
    }

    fn decode_nameservers(addresses: Vec<(i32, Vec<u8>)>) -> io::Result<Vec<IpAddr>> {
        addresses
            .into_iter()
            .map(|(family, address)| match (family, address.len()) {
                (nix::libc::AF_INET, 4) => {
                    let mut bytes = [0; 4];
                    bytes.copy_from_slice(&address);
                    Ok(IpAddr::V4(Ipv4Addr::from(bytes)))
                }
                (nix::libc::AF_INET6, 16) => {
                    let mut bytes = [0; 16];
                    bytes.copy_from_slice(&address);
                    Ok(IpAddr::V6(Ipv6Addr::from(bytes)))
                }
                _ => Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!(
                        "resolved returned a DNS address with family {family} and {} bytes",
                        address.len()
                    ),
                )),
            })
            .collect()
    }

    fn read_state(&self) -> io::Result<LinkState> {
        let connection = self
            .connection()
            .map_err(|error| Self::dbus_error("connecting to the system bus", error))?;
        let bus = Proxy::new(
            &connection,
            "org.freedesktop.DBus",
            "/org/freedesktop/DBus",
            "org.freedesktop.DBus",
        )
        .map_err(|error| Self::dbus_error("creating the D-Bus proxy", error))?;
        let owner: OwnedUniqueName = bus
            .call("GetNameOwner", &(RESOLVED_SERVICE,))
            .map_err(|error| Self::dbus_error("getting the resolved service owner", error))?;
        let manager = Proxy::new_owned(
            connection.clone(),
            owner.as_str().to_owned(),
            RESOLVED_MANAGER_PATH,
            RESOLVED_MANAGER_INTERFACE,
        )
        .map_err(|error| Self::dbus_error("creating the resolved manager proxy", error))?;
        let link_path: OwnedObjectPath = manager
            .call("GetLink", &(self.ifindex()?,))
            .map_err(|error| Self::dbus_error("getting the resolved link", error))?;
        let link: Proxy<'_> = ProxyBuilder::new(&connection)
            .destination(owner.as_str().to_owned())
            .map_err(|error| Self::dbus_error("creating the resolved link proxy", error))?
            .path(link_path)
            .map_err(|error| Self::dbus_error("creating the resolved link proxy", error))?
            .interface(RESOLVED_LINK_INTERFACE)
            .map_err(|error| Self::dbus_error("creating the resolved link proxy", error))?
            .cache_properties(CacheProperties::No)
            .build()
            .map_err(|error| Self::dbus_error("creating the resolved link proxy", error))?;
        let nameservers = Self::decode_nameservers(
            link.get_property("DNS")
                .map_err(|error| Self::dbus_error("reading resolved DNS servers", error))?,
        )?;
        let domains = link
            .get_property::<Vec<(String, bool)>>("Domains")
            .map_err(|error| Self::dbus_error("reading resolved domains", error))?
            .into_iter()
            .map(|(domain, route_only)| {
                if route_only {
                    format!("~{domain}")
                } else {
                    domain
                }
            })
            .collect();
        let default_route = link
            .get_property("DefaultRoute")
            .map_err(|error| Self::dbus_error("reading resolved DefaultRoute", error))?;
        let current_owner: OwnedUniqueName = bus
            .call("GetNameOwner", &(RESOLVED_SERVICE,))
            .map_err(|error| Self::dbus_error("checking the resolved service owner", error))?;
        if current_owner != owner {
            return Err(io::Error::other(
                "systemd-resolved restarted while Magic DNS was reading link state",
            ));
        }
        Ok(LinkState {
            config: LinkConfig {
                nameservers,
                domains,
                default_route,
            },
            owner,
        })
    }

    fn desired_config(cfg: &OSConfig) -> io::Result<LinkConfig> {
        let mut domains = Vec::new();
        for domain in &cfg.search_domains {
            let domain = domain.trim_end_matches('.');
            if domain.is_empty() || domain.starts_with('~') {
                return Err(io::Error::other("Magic DNS requires non-root domains"));
            }
            if !domains.contains(&domain.to_owned()) {
                domains.push(domain.to_owned());
            }
        }
        for domain in &cfg.match_domains {
            let domain = domain.trim_end_matches('.');
            if domain.is_empty() || domain.starts_with('~') {
                return Err(io::Error::other("Magic DNS requires non-root domains"));
            }
            if !domains.iter().any(|search| search == domain) {
                domains.push(format!("~{domain}"));
            }
        }
        if cfg.nameservers.is_empty() || domains.is_empty() {
            return Err(io::Error::other(
                "Magic DNS requires nameservers and domains",
            ));
        }
        let nameservers = cfg
            .nameservers
            .iter()
            .map(|server| {
                server.parse().map_err(|error| {
                    io::Error::new(
                        io::ErrorKind::InvalidInput,
                        format!("Invalid Magic DNS nameserver {server}: {error}"),
                    )
                })
            })
            .collect::<io::Result<Vec<IpAddr>>>()?;
        Ok(LinkConfig {
            nameservers,
            domains,
            default_route: false,
        })
    }

    fn call_manager_on<B>(
        &self,
        service: &str,
        path: &str,
        interface: &str,
        method: &str,
        body: &B,
    ) -> zbus::Result<()>
    where
        B: Serialize + DynamicType,
    {
        let connection = self.connection()?;
        let proxy = Proxy::new(&connection, service, path, interface)?;
        // zbus's blocking call_with_flags bypasses the connection method timeout.
        // A timeout only stops waiting; the peer may still apply the call later.
        let _: Option<()> = zbus::block_on(async {
            tokio::time::timeout(
                connection.method_timeout().unwrap_or(DBUS_METHOD_TIMEOUT),
                proxy.inner().call_with_flags(
                    method,
                    MethodFlags::AllowInteractiveAuth.into(),
                    body,
                ),
            )
            .await
        })
        .map_err(|_| {
            zbus::Error::InputOutput(std::sync::Arc::new(io::Error::new(
                io::ErrorKind::TimedOut,
                format!("{service}.{method} did not reply in time"),
            )))
        })??;
        Ok(())
    }

    fn call_manager<B>(&self, resolved_owner: &str, method: &str, body: &B) -> io::Result<()>
    where
        B: Serialize + DynamicType,
    {
        match self.call_manager_on(
            resolved_owner,
            RESOLVED_MANAGER_PATH,
            RESOLVED_MANAGER_INTERFACE,
            method,
            body,
        ) {
            Err(zbus::Error::MethodError(name, _, _)) if name.as_str() == LINK_BUSY_ERROR => self
                .call_manager_on(
                    NETWORKD_SERVICE,
                    NETWORKD_MANAGER_PATH,
                    NETWORKD_MANAGER_INTERFACE,
                    method,
                    body,
                )
                .map_err(|error| Self::dbus_error(method, error)),
            result => result.map_err(|error| Self::dbus_error(method, error)),
        }
    }

    // Record each successful write so normal cleanup also handles partial setup.
    fn write_config(&self, applied: &mut AppliedConfig, cfg: &LinkConfig) -> io::Result<()> {
        let ifindex = self.ifindex()?;
        let owner = applied.owner.clone();
        self.call_manager(
            owner.as_str(),
            "SetLinkDefaultRoute",
            &(ifindex, cfg.default_route),
        )?;
        applied.current.default_route = cfg.default_route;
        let domains: Vec<(String, bool)> = cfg
            .domains
            .iter()
            .map(|domain| {
                if let Some(domain) = domain.strip_prefix('~') {
                    (domain.to_owned(), true)
                } else {
                    (domain.clone(), false)
                }
            })
            .collect();
        self.call_manager(owner.as_str(), "SetLinkDomains", &(ifindex, domains))?;
        applied.current.domains.clone_from(&cfg.domains);
        let nameservers: Vec<(i32, Vec<u8>)> = cfg
            .nameservers
            .iter()
            .map(|server| match server {
                IpAddr::V4(address) => (nix::libc::AF_INET, address.octets().to_vec()),
                IpAddr::V6(address) => (nix::libc::AF_INET6, address.octets().to_vec()),
            })
            .collect();
        self.call_manager(owner.as_str(), "SetLinkDNS", &(ifindex, nameservers))?;
        applied.current.nameservers.clone_from(&cfg.nameservers);
        Ok(())
    }

    fn ensure_resolved_in_query_path() -> io::Result<()> {
        if !Self::uses_resolved(
            &fs::read_to_string("/etc/resolv.conf")?,
            &fs::read_to_string("/etc/nsswitch.conf").unwrap_or_default(),
        ) {
            return Err(io::Error::other(
                "Magic DNS requires system DNS to use the systemd-resolved stub or nss-resolve",
            ));
        }
        Ok(())
    }

    fn apply_config_locked(
        &self,
        state: &mut Option<AppliedConfig>,
        desired: LinkConfig,
    ) -> io::Result<()> {
        if let Some(applied) = state.as_mut() {
            applied.desired = desired.clone();
        }
        let LinkState {
            config: current,
            owner,
        } = self.read_state()?;
        if let Some(applied) = state.as_mut() {
            if owner != applied.owner {
                if current != applied.current {
                    // A nonempty value may contain our own completed but
                    // unacknowledged writes, so only adopt an empty baseline.
                    if current.nameservers.is_empty() && current.domains.is_empty() {
                        applied.original = current.clone();
                    }
                    applied.current.clone_from(&current);
                }
                applied.owner = owner;
            }
        } else {
            if !current.nameservers.is_empty() || !current.domains.is_empty() {
                return Err(io::Error::other(format!(
                    "{} already has DNS settings; refusing to take ownership",
                    self.interface,
                )));
            }
            *state = Some(AppliedConfig {
                original: current.clone(),
                current: current.clone(),
                desired: desired.clone(),
                owner,
            });
        }
        let applied = state.as_mut().unwrap();
        if current == desired {
            applied.current = current;
            return Ok(());
        }
        // Once owned, maintain the latest desired state instead of treating a
        // late reply or external write as a permanent snapshot conflict.
        self.write_config(applied, &desired)
    }
}

impl SystemConfig for ResolvedConfigurator {
    fn set_dns(&self, cfg: &OSConfig) -> io::Result<()> {
        let desired = Self::desired_config(cfg)?;
        (self.check_query_path)()?;
        let mut state = self.applied.lock().unwrap();
        self.apply_config_locked(&mut state, desired)
    }

    fn refresh(&self) -> io::Result<()> {
        let mut state = self.applied.lock().unwrap();
        let Some(desired) = state.as_ref().map(|applied| applied.desired.clone()) else {
            return Ok(());
        };
        (self.check_query_path)()?;
        self.apply_config_locked(&mut state, desired)
    }

    fn close(&self) -> io::Result<()> {
        let mut state = self.applied.lock().unwrap();
        let Some(applied) = state.as_mut() else {
            return Ok(());
        };
        if applied.desired == applied.original && applied.current == applied.original {
            *state = None;
            return Ok(());
        }
        let observed = self.read_state()?;
        if observed.owner != applied.owner {
            if observed.config != applied.current {
                *state = None;
                return Ok(());
            }
            applied.owner = observed.owner;
        }
        let original = applied.original.clone();
        self.write_config(applied, &original)?;
        *state = None;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use super::*;
    use resolved_fixture::{AF_INET, FixtureConfig, FixtureFailure, ResolvedFixture};
    use zbus::blocking::connection::Builder;

    fn config() -> OSConfig {
        OSConfig {
            nameservers: vec!["100.100.100.101".to_owned()],
            search_domains: vec!["et.test.".to_owned()],
            match_domains: vec!["et.test.".to_owned(), "internal.test.".to_owned()],
        }
    }

    fn original_config() -> FixtureConfig {
        FixtureConfig {
            default_route: true,
            ..Default::default()
        }
    }

    fn desired_config() -> FixtureConfig {
        FixtureConfig {
            nameservers: vec![(AF_INET, vec![100, 100, 100, 101])],
            domains: vec![
                ("et.test".to_owned(), false),
                ("internal.test".to_owned(), true),
            ],
            default_route: false,
        }
    }

    fn updated_config() -> OSConfig {
        OSConfig {
            nameservers: vec!["100.100.100.102".to_owned()],
            search_domains: vec!["new.test.".to_owned()],
            match_domains: vec!["new.test.".to_owned()],
        }
    }

    fn updated_fixture_config() -> FixtureConfig {
        FixtureConfig {
            nameservers: vec![(AF_INET, vec![100, 100, 100, 102])],
            domains: vec![("new.test".to_owned(), false)],
            default_route: false,
        }
    }

    fn setup() -> (ResolvedFixture, ResolvedConfigurator) {
        setup_with_timeout(Duration::from_secs(2))
    }

    fn setup_with_timeout(timeout: Duration) -> (ResolvedFixture, ResolvedConfigurator) {
        let fixture = ResolvedFixture::start();
        fixture.set_config(original_config());
        let connection = Builder::address(fixture.address.as_str())
            .unwrap()
            .method_timeout(timeout)
            .build()
            .unwrap();
        let configurator = ResolvedConfigurator::with_connection("lo", connection, || Ok(()));
        (fixture, configurator)
    }

    #[test]
    fn search_domains_and_route_only_domains_are_distinct() {
        let cfg = ResolvedConfigurator::desired_config(&OSConfig {
            nameservers: vec!["100.100.100.101".to_owned()],
            search_domains: vec!["et.net.".to_owned()],
            match_domains: vec!["et.net.".to_owned(), "internal.test.".to_owned()],
        })
        .unwrap();
        assert_eq!(cfg.domains, ["et.net", "~internal.test"]);
        assert!(!cfg.default_route);
    }

    #[test]
    fn refuses_root_domain_routing() {
        assert!(
            ResolvedConfigurator::desired_config(&OSConfig {
                nameservers: vec!["100.100.100.101".to_owned()],
                match_domains: vec![".".to_owned()],
                ..Default::default()
            })
            .is_err()
        );
    }

    #[test]
    fn requires_resolved_in_the_system_query_path() {
        assert!(ResolvedConfigurator::uses_resolved(
            "nameserver 127.0.0.53\n",
            ""
        ));
        assert!(ResolvedConfigurator::uses_resolved(
            "nameserver 192.0.2.53\n",
            "hosts: files resolve [!UNAVAIL=return] dns"
        ));
        assert!(!ResolvedConfigurator::uses_resolved(
            "nameserver 192.0.2.53 # 127.0.0.53\n",
            "hosts: files dns # resolve"
        ));
    }

    #[test]
    fn applies_and_restores_link_config_over_dbus() {
        let (fixture, configurator) = setup();
        configurator.set_dns(&config()).unwrap();
        assert_eq!(fixture.config(), desired_config());
        assert!(fixture.interactive());
        assert_eq!(
            fixture.calls(),
            [
                "resolved.SetLinkDefaultRoute",
                "resolved.SetLinkDomains",
                "resolved.SetLinkDNS",
            ]
        );

        configurator.close().unwrap();
        assert_eq!(fixture.config(), original_config());
        configurator.close().unwrap();
    }

    #[test]
    fn cleans_up_partial_dbus_writes() {
        let (fixture, configurator) = setup();
        fixture.fail("resolved.SetLinkDomains", FixtureFailure::AccessDenied);
        assert!(configurator.set_dns(&config()).is_err());
        assert!(!fixture.config().default_route);

        fixture.clear_failures();
        configurator.close().unwrap();
        assert_eq!(fixture.config(), original_config());
    }

    #[test]
    fn maintains_and_closes_over_external_dbus_changes() {
        let (fixture, configurator) = setup();
        configurator.set_dns(&config()).unwrap();
        let mut changed = fixture.config();
        changed.nameservers = vec![(AF_INET, vec![192, 0, 2, 53])];
        fixture.set_config(changed);

        configurator.set_dns(&config()).unwrap();
        assert_eq!(fixture.config(), desired_config());
        configurator.close().unwrap();
        assert_eq!(fixture.config(), original_config());
    }

    #[test]
    fn refresh_maintains_the_latest_config_after_a_late_write() {
        let (fixture, configurator) = setup_with_timeout(Duration::from_millis(50));
        configurator.set_dns(&config()).unwrap();
        fixture.fail(
            "resolved.SetLinkDNS",
            FixtureFailure::Delay(Duration::from_millis(300)),
        );

        let error = configurator.set_dns(&updated_config()).unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::TimedOut);
        std::thread::sleep(Duration::from_millis(350));
        assert_eq!(fixture.config(), updated_fixture_config());

        configurator.refresh().unwrap();
        assert_eq!(fixture.config(), updated_fixture_config());
        configurator.set_dns(&config()).unwrap();
        assert_eq!(fixture.config(), desired_config());
        configurator.close().unwrap();
        assert_eq!(fixture.config(), original_config());
    }

    #[test]
    fn a_late_write_can_still_arrive_after_close() {
        let (fixture, configurator) = setup_with_timeout(Duration::from_millis(50));
        configurator.set_dns(&config()).unwrap();
        fixture.fail("resolved.SetLinkDNS", FixtureFailure::Wait);

        let error = configurator.set_dns(&updated_config()).unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::TimedOut);
        let (close_tx, close_rx) = std::sync::mpsc::channel();
        let closer = std::thread::spawn(move || {
            close_tx.send(configurator.close()).unwrap();
        });
        let closed = close_rx.recv_timeout(Duration::from_secs(2));
        if matches!(&closed, Ok(Ok(()))) {
            assert_eq!(fixture.config(), original_config());
        }
        fixture.release_wait();
        closer.join().unwrap();
        closed.unwrap().unwrap();

        let deadline = std::time::Instant::now() + Duration::from_secs(2);
        while fixture.config().nameservers != updated_fixture_config().nameservers {
            assert!(std::time::Instant::now() < deadline);
            std::thread::sleep(Duration::from_millis(10));
        }
        let mut late = original_config();
        late.nameservers = updated_fixture_config().nameservers;
        assert_eq!(fixture.config(), late);
    }

    #[test]
    fn retained_owner_after_late_write_keeps_original_baseline() {
        let (mut fixture, configurator) = setup_with_timeout(Duration::from_millis(50));
        configurator.set_dns(&config()).unwrap();
        let mut changed = config();
        changed.search_domains = vec!["new.test.".to_owned()];
        changed.match_domains = vec!["new.test.".to_owned()];
        fixture.fail(
            "resolved.SetLinkDomains",
            FixtureFailure::Delay(Duration::from_millis(300)),
        );

        let error = configurator.set_dns(&changed).unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::TimedOut);
        std::thread::sleep(Duration::from_millis(350));
        assert_eq!(fixture.config().domains, [("new.test".to_owned(), false)]);
        fixture.restart_resolved_preserving_config();

        configurator.refresh().unwrap();
        configurator.close().unwrap();
        assert_eq!(fixture.config(), original_config());
    }

    #[test]
    fn refresh_accepts_changes_from_a_new_resolved_owner() {
        let (mut fixture, configurator) = setup();
        configurator.set_dns(&config()).unwrap();
        fixture.restart_resolved();
        let external = FixtureConfig {
            nameservers: vec![(AF_INET, vec![192, 0, 2, 53])],
            domains: vec![("external.test".to_owned(), true)],
            default_route: true,
        };
        fixture.set_config(external);

        configurator.refresh().unwrap();
        assert_eq!(fixture.config(), desired_config());
        configurator.close().unwrap();
        assert_eq!(fixture.config(), original_config());
    }

    #[test]
    fn link_busy_falls_back_to_networkd() {
        let (fixture, configurator) = setup();
        for method in [
            "resolved.SetLinkDefaultRoute",
            "resolved.SetLinkDomains",
            "resolved.SetLinkDNS",
        ] {
            fixture.fail(method, FixtureFailure::LinkBusy);
        }

        configurator.set_dns(&config()).unwrap();
        assert_eq!(fixture.config(), desired_config());
        let calls = fixture.calls();
        for method in [
            "networkd.SetLinkDefaultRoute",
            "networkd.SetLinkDomains",
            "networkd.SetLinkDNS",
        ] {
            assert!(calls.contains(&method.to_owned()));
        }
    }

    #[test]
    fn permission_errors_do_not_fall_back_to_networkd() {
        let (fixture, configurator) = setup();
        fixture.fail("resolved.SetLinkDefaultRoute", FixtureFailure::AccessDenied);

        assert!(configurator.set_dns(&config()).is_err());
        assert!(
            !fixture
                .calls()
                .iter()
                .any(|call| call.starts_with("networkd."))
        );
    }

    #[test]
    fn missing_default_route_method_aborts_before_changes() {
        let (fixture, configurator) = setup();
        fixture.fail(
            "resolved.SetLinkDefaultRoute",
            FixtureFailure::UnknownMethod,
        );

        assert!(configurator.set_dns(&config()).is_err());
        assert_eq!(fixture.config(), original_config());
        fixture.clear_failures();
        configurator.close().unwrap();
    }

    #[test]
    fn dbus_calls_honor_the_connection_timeout() {
        let (fixture, configurator) = setup_with_timeout(Duration::from_millis(250));
        fixture.fail(
            "resolved.SetLinkDefaultRoute",
            FixtureFailure::Delay(Duration::from_millis(300)),
        );

        let error = configurator.set_dns(&config()).unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::TimedOut);
    }

    #[test]
    fn refresh_reapplies_config_after_resolved_restarts() {
        let (mut fixture, configurator) = setup();
        configurator.set_dns(&config()).unwrap();
        fixture.restart_resolved();
        assert_eq!(fixture.config(), original_config());

        configurator.refresh().unwrap();
        assert_eq!(fixture.config(), desired_config());
        configurator.close().unwrap();
    }

    #[test]
    fn persisted_config_remains_owned_after_resolved_restarts() {
        let (mut fixture, configurator) = setup();
        configurator.set_dns(&config()).unwrap();
        fixture.restart_resolved_preserving_config();

        configurator.refresh().unwrap();
        assert_eq!(fixture.config(), desired_config());
        configurator.close().unwrap();
        assert_eq!(fixture.config(), original_config());
    }

    #[test]
    fn close_does_not_write_to_a_new_resolved_owner() {
        let (mut fixture, configurator) = setup();
        configurator.set_dns(&config()).unwrap();
        fixture.restart_resolved();
        let calls = fixture.calls();

        configurator.close().unwrap();
        assert_eq!(fixture.config(), original_config());
        assert_eq!(fixture.calls(), calls);
    }

    #[test]
    fn writes_fail_when_the_validated_owner_disappears() {
        let (mut fixture, configurator) = setup();
        configurator.set_dns(&config()).unwrap();
        let desired = configurator
            .applied
            .lock()
            .unwrap()
            .as_ref()
            .unwrap()
            .current
            .clone();
        fixture.restart_resolved();

        let mut state = configurator.applied.lock().unwrap();
        configurator
            .write_config(state.as_mut().unwrap(), &desired)
            .unwrap_err();
        assert_eq!(fixture.config(), original_config());
    }

    #[tokio::test]
    async fn constructor_is_safe_in_a_tokio_context() {
        let _configurator = ResolvedConfigurator::new("lo");
    }
}
