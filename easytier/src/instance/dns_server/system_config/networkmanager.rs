//! Configure the resolver through NetworkManager's D-Bus API.
//!
//! On hosts where NetworkManager owns DNS (`dns=default` or `dns=dnsmasq`) it
//! builds the resolver configuration from the DNS properties of the active
//! connections, so registering there is the canonical way in; writing
//! `/etc/resolv.conf` directly would race with NetworkManager for the same
//! file.
//!
//! `Device.GetAppliedConnection` + `Device.Reapply` change the applied
//! configuration in memory: the profile on disk is untouched, and a
//! reactivation reverts to it, after which `refresh` puts the entry back.

#[cfg(test)]
mod fixture;

use std::{collections::HashMap, io, net::Ipv4Addr, sync::Mutex};

use zbus::{
    blocking::{Connection, Proxy},
    zvariant::{OwnedValue, Value},
};

use super::{OSConfig, SystemConfig};

const NM_SERVICE: &str = "org.freedesktop.NetworkManager";
const NM_MANAGER_PATH: &str = "/org/freedesktop/NetworkManager";
const NM_MANAGER_INTERFACE: &str = "org.freedesktop.NetworkManager";
const NM_DNS_MANAGER_PATH: &str = "/org/freedesktop/NetworkManager/DnsManager";
const NM_DNS_MANAGER_INTERFACE: &str = "org.freedesktop.NetworkManager.DnsManager";
const NM_DEVICE_INTERFACE: &str = "org.freedesktop.NetworkManager.Device";
/// Keep addresses and routes added to the device from outside NetworkManager.
const REAPPLY_PRESERVE_EXTERNAL_IP: u32 = 0x1;

/// The `a{sa{sv}}` shape NetworkManager uses for connection settings.
pub(super) type Settings = HashMap<String, HashMap<String, OwnedValue>>;

pub struct NetworkManagerConfigurator {
    connection: Connection,
    applied: Mutex<Option<Applied>>,
}

struct Applied {
    config: OSConfig,
    /// Applied settings before the first change, per device path.
    originals: HashMap<String, Settings>,
}

impl NetworkManagerConfigurator {
    /// `None` when NetworkManager is not on the bus, or manages DNS elsewhere
    /// (`dns=none`, `dns=systemd-resolved`): another backend has to take over.
    pub fn detect() -> Option<Self> {
        let connection = Connection::system().ok()?;
        if !manages_dns(&connection).unwrap_or(true) {
            return None;
        }
        Some(Self::with_connection(connection))
    }

    /// Construct on an existing bus connection; also used by the tests.
    pub(super) fn with_connection(connection: Connection) -> Self {
        Self {
            connection,
            applied: Mutex::new(None),
        }
    }

    fn manager(&self) -> io::Result<Proxy<'_>> {
        Proxy::new(
            &self.connection,
            NM_SERVICE,
            NM_MANAGER_PATH,
            NM_MANAGER_INTERFACE,
        )
        .map_err(error)
    }

    fn device(&self, path: &str) -> io::Result<Proxy<'_>> {
        Proxy::new(
            &self.connection,
            NM_SERVICE.to_owned(),
            path.to_owned(),
            NM_DEVICE_INTERFACE.to_owned(),
        )
        .map_err(error)
    }

    fn devices(&self) -> io::Result<Vec<String>> {
        let paths: Vec<zbus::zvariant::OwnedObjectPath> =
            self.manager()?.get_property("Devices").map_err(error)?;
        Ok(paths.into_iter().map(|path| path.to_string()).collect())
    }

    fn applied_settings(&self, device: &str) -> io::Result<(Settings, u64)> {
        self.device(device)?
            .call("GetAppliedConnection", &(0u32))
            .map_err(error)
    }

    fn reapply(&self, device: &str, settings: Settings, version: u64) -> io::Result<()> {
        self.device(device)?
            .call::<_, _, ()>(
                "Reapply",
                &(settings, version, REAPPLY_PRESERVE_EXTERNAL_IP),
            )
            .map_err(error)
    }
}

impl SystemConfig for NetworkManagerConfigurator {
    fn refresh(&self) -> io::Result<()> {
        let config = match self.applied.lock().unwrap().as_ref() {
            Some(applied) => applied.config.clone(),
            None => return Ok(()),
        };
        // A reactivation or a `nmcli connection up` reverts the device to its
        // profile; only pay for another round trip when that happened.
        for device in self.devices()? {
            if let Ok((current, _)) = self.applied_settings(&device) {
                if !has_dns(&current, &config) {
                    return self.set_dns(&config);
                }
            }
        }
        Ok(())
    }

    fn set_dns(&self, cfg: &OSConfig) -> io::Result<()> {
        let devices = self.devices()?;
        let mut applied = self.applied.lock().unwrap();
        let state = applied.get_or_insert_with(|| Applied {
            config: cfg.clone(),
            originals: HashMap::new(),
        });
        state.config = cfg.clone();

        for device in devices {
            // A device without an applied connection is not active.
            let Ok((current, version)) = self.applied_settings(&device) else {
                continue;
            };
            state
                .originals
                .entry(device.clone())
                .or_insert_with(|| current.clone());
            let desired = with_dns(&current, cfg);
            if let Err(error) = self.reapply(&device, desired, version) {
                tracing::warn!(
                    ?error,
                    device,
                    "NetworkManager refused the Magic DNS settings"
                );
            }
        }
        Ok(())
    }

    fn close(&self) -> io::Result<()> {
        let state = match self.applied.lock().unwrap().take() {
            Some(state) => state,
            None => return Ok(()),
        };
        for (device, original) in state.originals {
            // Restore against the current version: a reactivation in between
            // bumps it, and a stale version is rejected by design.
            match self.applied_settings(&device) {
                Ok((_, version)) => {
                    if let Err(error) = self.reapply(&device, original, version) {
                        tracing::warn!(
                            ?error,
                            device,
                            "NetworkManager could not restore the original DNS settings"
                        );
                    }
                }
                // The device is gone; nothing left to restore.
                Err(_) => continue,
            }
        }
        Ok(())
    }
}

/// Whether NetworkManager builds the host resolver configuration itself.
fn manages_dns(connection: &Connection) -> zbus::Result<bool> {
    let proxy = Proxy::new(
        connection,
        NM_SERVICE,
        NM_DNS_MANAGER_PATH,
        NM_DNS_MANAGER_INTERFACE,
    )?;
    // Older NetworkManager has no DnsManager object; it manages DNS by default.
    let mode: String = proxy
        .get_property("Mode")
        .unwrap_or_else(|_| "default".to_owned());
    Ok(!matches!(mode.as_str(), "none" | "systemd-resolved"))
}

/// Add the Magic DNS nameservers and zones to an applied connection, leaving
/// everything else untouched.
pub(super) fn with_dns(settings: &Settings, cfg: &OSConfig) -> Settings {
    let mut settings = settings.clone();
    let ipv4 = settings.entry("ipv4".to_owned()).or_default();

    let mut addresses = read::<Vec<u32>>(ipv4.get("dns")).unwrap_or_default();
    for nameserver in &cfg.nameservers {
        if let Ok(address) = nameserver.parse::<Ipv4Addr>() {
            // ipv4.dns holds network-byte-order integers.
            let address = u32::from_be_bytes(address.octets());
            if !addresses.contains(&address) {
                addresses.insert(0, address);
            }
        }
    }
    ipv4.insert("dns".to_owned(), owned(addresses));

    let mut search = read::<Vec<String>>(ipv4.get("dns-search")).unwrap_or_default();
    for zone in zones(cfg) {
        if !search.contains(&zone) {
            search.push(zone);
        }
    }
    ipv4.insert("dns-search".to_owned(), owned(search));

    settings
}

pub(super) fn has_dns(settings: &Settings, cfg: &OSConfig) -> bool {
    let Some(ipv4) = settings.get("ipv4") else {
        return false;
    };
    let addresses: Vec<u32> = read(ipv4.get("dns")).unwrap_or_default();
    cfg.nameservers
        .iter()
        .filter_map(|nameserver| nameserver.parse::<Ipv4Addr>().ok())
        .all(|address| addresses.contains(&u32::from_be_bytes(address.octets())))
}

/// Served zones without their trailing dot, in order, without duplicates.
fn zones(cfg: &OSConfig) -> Vec<String> {
    let mut zones: Vec<String> = Vec::new();
    for zone in cfg.search_domains.iter().chain(cfg.match_domains.iter()) {
        let zone = zone.trim_end_matches('.').to_owned();
        if !zone.is_empty() && !zones.contains(&zone) {
            zones.push(zone);
        }
    }
    zones
}

fn read<T>(value: Option<&OwnedValue>) -> Option<T>
where
    T: TryFrom<OwnedValue>,
{
    let value = value?.try_clone().ok()?;
    T::try_from(value).ok()
}

fn owned<T>(value: T) -> OwnedValue
where
    Value<'static>: From<T>,
{
    OwnedValue::try_from(Value::from(value)).expect("settings value is owned")
}

fn error(error: zbus::Error) -> io::Error {
    io::Error::other(error)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn config() -> OSConfig {
        OSConfig {
            nameservers: vec!["100.100.100.101".to_owned()],
            search_domains: vec!["example.com.".to_owned()],
            match_domains: vec!["other.example.".to_owned()],
        }
    }

    fn settings() -> Settings {
        let mut ipv4 = HashMap::new();
        ipv4.insert("dns".to_owned(), owned(vec![0x0808_0808u32]));
        ipv4.insert("dns-search".to_owned(), owned(vec!["lan".to_owned()]));
        ipv4.insert("method".to_owned(), owned("auto".to_owned()));
        let mut settings = HashMap::new();
        settings.insert("ipv4".to_owned(), ipv4);
        settings
    }

    #[test]
    fn dns_is_prepended_and_existing_entries_survive() {
        let updated = with_dns(&settings(), &config());
        let nameservers: Vec<u32> = read(updated["ipv4"].get("dns")).unwrap();
        assert_eq!(nameservers, vec![0x6464_6465, 0x0808_0808]);
        let search: Vec<String> = read(updated["ipv4"].get("dns-search")).unwrap();
        assert_eq!(
            search,
            vec![
                "lan".to_owned(),
                "example.com".to_owned(),
                "other.example".to_owned()
            ]
        );
        // Unrelated settings are preserved verbatim.
        let method: String = read(updated["ipv4"].get("method")).unwrap();
        assert_eq!(method, "auto");
    }

    #[test]
    fn applying_twice_does_not_duplicate_entries() {
        let once = with_dns(&settings(), &config());
        let twice = with_dns(&once, &config());
        let nameservers: Vec<u32> = read(twice["ipv4"].get("dns")).unwrap();
        assert_eq!(nameservers.len(), 2);
        let search: Vec<String> = read(twice["ipv4"].get("dns-search")).unwrap();
        assert_eq!(search.len(), 3);
    }

    #[test]
    fn has_dns_reports_whether_the_entry_survived() {
        let updated = with_dns(&settings(), &config());
        assert!(has_dns(&updated, &config()));
        assert!(!has_dns(&settings(), &config()));
    }

    use super::fixture::NetworkManagerFixture;

    fn dns(settings: &Settings) -> Vec<u32> {
        read(settings["ipv4"].get("dns")).unwrap()
    }

    fn search(settings: &Settings) -> Vec<String> {
        read(settings["ipv4"].get("dns-search")).unwrap()
    }

    #[test]
    fn applies_dns_to_the_active_device() {
        let fixture = NetworkManagerFixture::start("default", settings());
        let configurator = fixture.configurator();

        configurator.set_dns(&config()).unwrap();

        let applied = fixture.settings();
        assert_eq!(dns(&applied), vec![0x6464_6465, 0x0808_0808]);
        assert_eq!(
            search(&applied),
            vec![
                "lan".to_owned(),
                "example.com".to_owned(),
                "other.example".to_owned()
            ]
        );
        assert_eq!(fixture.reapply_count(), 1);
    }

    #[test]
    fn close_restores_the_original_settings() {
        let original = settings();
        let fixture = NetworkManagerFixture::start("default", original.clone());
        let configurator = fixture.configurator();

        configurator.set_dns(&config()).unwrap();
        configurator.close().unwrap();

        assert_eq!(dns(&fixture.settings()), dns(&original));
        assert_eq!(search(&fixture.settings()), search(&original));
    }

    #[test]
    fn refresh_reapplies_after_a_reactivation() {
        let original = settings();
        let fixture = NetworkManagerFixture::start("default", original.clone());
        let configurator = fixture.configurator();
        configurator.set_dns(&config()).unwrap();

        // The device is reactivated and falls back to its profile.
        fixture.revert_to(original);
        assert!(!has_dns(&fixture.settings(), &config()));

        configurator.refresh().unwrap();
        assert!(has_dns(&fixture.settings(), &config()));
        assert_eq!(fixture.reapply_count(), 2);
    }

    #[test]
    fn close_restores_against_a_moved_version() {
        let original = settings();
        let fixture = NetworkManagerFixture::start("default", original.clone());
        let configurator = fixture.configurator();
        configurator.set_dns(&config()).unwrap();

        fixture.revert_to(original.clone());
        // The stored version is stale now; close has to read the current one.
        configurator.close().unwrap();

        assert_eq!(dns(&fixture.settings()), dns(&original));
    }

    #[test]
    fn does_not_claim_dns_when_network_manager_leaves_it_alone() {
        let fixture = NetworkManagerFixture::start("none", settings());
        assert!(!fixture.manages_dns());

        let fixture = NetworkManagerFixture::start("dnsmasq", settings());
        assert!(fixture.manages_dns());
    }
}
