use std::{collections::BTreeMap, io, net::IpAddr, process::Command, sync::Mutex};

use winreg::{
    RegKey, RegValue,
    enums::{HKEY_LOCAL_MACHINE, KEY_READ, KEY_WRITE},
    types::ToRegValue,
};

use crate::common::ifcfg::RegistryManager;

use super::{OSConfig, SystemConfig};

const RECOVERY_KEY: &str = r"SOFTWARE\EasyTier\MagicDNS";
const NRPT_KEY: &str = r"SYSTEM\CurrentControlSet\Services\Dnscache\Parameters\DnsPolicyConfig";
const RULE_IDS: &str = "NRPTRuleIDs";

fn powershell(script: &str) -> io::Result<()> {
    // Pass the script directly to PowerShell, without invoking cmd.exe. All
    // configurable values are escaped as PowerShell single-quoted strings.
    let script = format!("$ErrorActionPreference = 'Stop'; {script}");
    let output = Command::new("powershell.exe")
        .args(["-NoProfile", "-NonInteractive", "-Command"])
        .arg(script)
        .output()?;
    if !output.status.success() {
        return Err(io::Error::other(format!(
            "Windows DNS configuration failed: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        )));
    }
    Ok(())
}

fn quoted(value: &str) -> String {
    format!("'{}'", value.replace('\'', "''"))
}

struct NrptRule {
    id: String,
    domain: String,
}

impl NrptRule {
    fn namespaces(&self) -> String {
        format!(
            "@({}, {})",
            quoted(&self.domain),
            quoted(&format!(".{}", self.domain))
        )
    }

    fn set(&self, nameservers: &str) -> io::Result<()> {
        powershell(&format!(
            "$rule = Get-DnsClientNrptRule | Where-Object {{ $_.Name -eq {} }}; \
             if (-not $rule) {{ \
                 $namespaces = {}; \
                 $conflicts = @(Get-DnsClientNrptPolicy -Effective | Where-Object {{ \
                     @($_.Namespace | Where-Object {{ $namespaces -contains $_ }}).Count -gt 0 \
                 }}); \
                 if ($conflicts.Count -gt 0) {{ throw 'An existing NRPT policy already owns this domain' }}; \
             }}",
            quoted(&self.id),
            self.namespaces(),
        ))?;
        // Create a known ID only after its durable ownership list was saved.
        // Add-DnsClientNrptRule chooses an ID itself, leaving a crash window
        // between creating that rule and recording which ID belongs to us.
        let (key, _) =
            RegKey::predef(HKEY_LOCAL_MACHINE).create_subkey(format!(r"{NRPT_KEY}\{}", self.id))?;
        key.set_value("Version", &1_u32)?;
        key.set_value("ConfigOptions", &8_u32)?;
        key.set_value(
            "Name",
            &vec![self.domain.clone(), format!(".{}", self.domain)],
        )?;
        key.set_value("GenericDNSServers", &nameservers)?;
        key.set_value("Comment", &"EasyTier Magic DNS")?;
        powershell(&format!(
            "\
             $effective = @(Get-DnsClientNrptPolicy -Effective); \
             foreach ($namespace in {}) {{ \
                 if (@($effective | Where-Object {{ \
                     $_.Namespace -contains $namespace -and $_.NameServers -eq {} \
                 }}).Count -eq 0) {{ throw 'EasyTier NRPT rule is not effective (check Group Policy)' }} \
             }}",
            self.namespaces(),
            quoted(nameservers),
        ))
    }
}

fn remove_rule(id: &str) -> io::Result<()> {
    uuid::Uuid::parse_str(id).map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))?;
    match RegKey::predef(HKEY_LOCAL_MACHINE).delete_subkey(format!(r"{NRPT_KEY}\{id}")) {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error),
    }
}

// The private registry values are ownership records, not fingerprints. Like
// Tailscale's rule IDs, they authorize cleanup even after an external edit.
struct WindowsDNSRecovery {
    path: String,
}

impl WindowsDNSRecovery {
    fn open(&self) -> io::Result<RegKey> {
        RegKey::predef(HKEY_LOCAL_MACHINE)
            .create_subkey_with_flags(&self.path, KEY_READ | KEY_WRITE)
            .map(|(key, _)| key)
    }

    fn save_rules(&self, rules: &BTreeMap<String, NrptRule>) -> io::Result<()> {
        let key = self.open()?;
        let ids: Vec<_> = rules.values().map(|rule| rule.id.as_str()).collect();
        key.set_value(RULE_IDS, &ids)
    }

    fn save_search_list(
        &self,
        guid: &str,
        protocol: &str,
        original: &Option<RegValue<'_>>,
    ) -> io::Result<()> {
        let key = self.open()?;
        let (saved, _) = key.create_subkey(format!(r"SearchLists\{guid}\{protocol}"))?;
        match saved.get_value::<u32, _>("Ready") {
            Ok(1) => return Ok(()),
            Ok(_) => {}
            Err(error) if error.kind() == io::ErrorKind::NotFound => {}
            Err(error) => return Err(error),
        }
        if let Some(value) = original {
            saved.set_raw_value("OriginalSearchList", value)?;
        } else {
            match saved.delete_value("OriginalSearchList") {
                Ok(()) => {}
                Err(error) if error.kind() == io::ErrorKind::NotFound => {}
                Err(error) => return Err(error),
            }
        }
        // Until Ready is saved, no interface value may be changed. A crash
        // before this point therefore needs no interface restoration.
        saved.set_value("Ready", &1_u32)
    }

    fn clean(&self) -> io::Result<()> {
        let key = self.open()?;
        let ids: Vec<String> = match key.get_value(RULE_IDS) {
            Ok(ids) => ids,
            Err(error) if error.kind() == io::ErrorKind::NotFound => Vec::new(),
            Err(error) => return Err(error),
        };
        for id in &ids {
            uuid::Uuid::parse_str(id)
                .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))?;
        }
        for id in &ids {
            remove_rule(id)?;
        }
        let searches = match key.open_subkey_with_flags("SearchLists", KEY_READ | KEY_WRITE) {
            Ok(searches) => Some(searches),
            Err(error) if error.kind() == io::ErrorKind::NotFound => None,
            Err(error) => return Err(error),
        };
        if let Some(searches) = searches {
            for guid in searches.enum_keys().collect::<io::Result<Vec<_>>>()? {
                uuid::Uuid::parse_str(&guid)
                    .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))?;
                let interface = searches.open_subkey_with_flags(&guid, KEY_READ | KEY_WRITE)?;
                for (protocol, prefix) in [
                    ("IPv4", RegistryManager::IPV4_TCPIP_INTERFACE_PREFIX),
                    ("IPv6", RegistryManager::IPV6_TCPIP_INTERFACE_PREFIX),
                ] {
                    let saved = match interface.open_subkey(protocol) {
                        Ok(saved) => saved,
                        Err(error) if error.kind() == io::ErrorKind::NotFound => continue,
                        Err(error) => return Err(error),
                    };
                    let ready: u32 = match saved.get_value("Ready") {
                        Ok(ready) => ready,
                        Err(error) if error.kind() == io::ErrorKind::NotFound => 0,
                        Err(error) => return Err(error),
                    };
                    if ready == 1 {
                        match RegistryManager::open_interface_key(&guid, prefix) {
                            Ok(target) => match saved.get_raw_value("OriginalSearchList") {
                                Ok(original) => target.set_raw_value("SearchList", &original)?,
                                Err(error) if error.kind() == io::ErrorKind::NotFound => {
                                    match target.delete_value("SearchList") {
                                        Ok(()) => {}
                                        Err(error) if error.kind() == io::ErrorKind::NotFound => {}
                                        Err(error) => return Err(error),
                                    }
                                }
                                Err(error) => return Err(error),
                            },
                            // A disposable TUN adapter may have vanished with
                            // its process. There is no remaining value to fix.
                            Err(error) if error.kind() == io::ErrorKind::NotFound => {}
                            Err(error) => return Err(error),
                        }
                    }
                    drop(saved);
                    interface.delete_subkey(protocol)?;
                }
                drop(interface);
                searches.delete_subkey(&guid)?;
            }
            drop(searches);
            key.delete_subkey("SearchLists")?;
        }
        match key.delete_value(RULE_IDS) {
            Ok(()) => {}
            Err(error) if error.kind() == io::ErrorKind::NotFound => {}
            Err(error) => return Err(error),
        }
        Ok(())
    }
}

struct SearchList {
    prefix: &'static str,
    applied: RegValue<'static>,
}

fn search_list(key: &RegKey) -> io::Result<Option<RegValue<'static>>> {
    match key.get_raw_value("SearchList") {
        Ok(value) => Ok(Some(value)),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(None),
        Err(error) => Err(error),
    }
}

#[derive(Default)]
struct WindowsDNSState {
    prepared: bool,
    rules: BTreeMap<String, NrptRule>,
    search_lists: Vec<SearchList>,
}

pub struct WindowsDNSManager {
    interface_guid: String,
    recovery: WindowsDNSRecovery,
    state: Mutex<WindowsDNSState>,
}

impl WindowsDNSManager {
    pub fn new(tun_dev_name: &str) -> io::Result<Self> {
        Ok(Self {
            interface_guid: RegistryManager::find_interface_guid(tun_dev_name)?,
            recovery: WindowsDNSRecovery {
                path: RECOVERY_KEY.to_owned(),
            },
            state: Mutex::new(WindowsDNSState::default()),
        })
    }

    fn flush_dns() -> io::Result<()> {
        let output = Command::new("ipconfig").arg("/flushdns").output()?;
        if !output.status.success() {
            return Err(io::Error::other(format!(
                "Failed to flush Windows DNS cache: {}",
                String::from_utf8_lossy(&output.stderr).trim(),
            )));
        }
        Ok(())
    }

    fn check_search_lists(&self, state: &WindowsDNSState) -> io::Result<()> {
        // Check access and external edits before publishing any new NRPT rules.
        for prefix in [
            RegistryManager::IPV4_TCPIP_INTERFACE_PREFIX,
            RegistryManager::IPV6_TCPIP_INTERFACE_PREFIX,
        ] {
            let key = RegistryManager::open_interface_key(&self.interface_guid, prefix)?;
            let current = search_list(&key)?;
            if let Some(saved) = state.search_lists.iter().find(|s| s.prefix == prefix)
                && current.as_ref() != Some(&saved.applied)
            {
                return Err(io::Error::other(
                    "EasyTier adapter search list was changed externally; leaving it unchanged",
                ));
            }
        }
        Ok(())
    }

    fn set_search_list(&self, state: &mut WindowsDNSState, domains: &[String]) -> io::Result<()> {
        // Search suffixes expand short names. NRPT's namespaces select the DNS
        // server; they must never be used as the adapter's search list.
        let text = domains.join(",");
        let value = text.to_reg_value();
        for (protocol, prefix) in [
            ("IPv4", RegistryManager::IPV4_TCPIP_INTERFACE_PREFIX),
            ("IPv6", RegistryManager::IPV6_TCPIP_INTERFACE_PREFIX),
        ] {
            let key = RegistryManager::open_interface_key(&self.interface_guid, prefix)?;
            let current = search_list(&key)?;
            if let Some(saved) = state.search_lists.iter_mut().find(|s| s.prefix == prefix) {
                if current.as_ref() != Some(&saved.applied) {
                    return Err(io::Error::other(
                        "EasyTier adapter search list was changed externally; leaving it unchanged",
                    ));
                }
                key.set_raw_value("SearchList", &value)?;
                saved.applied = RegValue {
                    bytes: value.bytes.to_vec().into(),
                    vtype: value.vtype.clone(),
                };
            } else {
                self.recovery
                    .save_search_list(&self.interface_guid, protocol, &current)?;
                key.set_raw_value("SearchList", &value)?;
                state.search_lists.push(SearchList {
                    prefix,
                    applied: RegValue {
                        bytes: value.bytes.to_vec().into(),
                        vtype: value.vtype.clone(),
                    },
                });
            }
        }
        Ok(())
    }
}

impl SystemConfig for WindowsDNSManager {
    fn prepare(&self) -> io::Result<()> {
        let mut state = self.state.lock().unwrap();
        if !state.prepared {
            self.recovery.clean()?;
            Self::flush_dns()?;
            state.prepared = true;
        }
        Ok(())
    }

    fn set_dns(&self, cfg: &OSConfig) -> io::Result<()> {
        self.prepare()?;
        let nameservers = cfg
            .nameservers
            .iter()
            .map(|s| {
                s.parse::<IpAddr>()
                    .map(|ip| ip.to_string())
                    .map_err(|error| io::Error::new(io::ErrorKind::InvalidInput, error))
            })
            .collect::<io::Result<Vec<_>>>()?
            .join(";");
        if nameservers.is_empty() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "No Magic DNS server",
            ));
        }
        let domains: Vec<_> = cfg
            .match_domains
            .iter()
            .map(|d| d.trim_end_matches('.').to_lowercase())
            .collect();
        let search: Vec<_> = cfg
            .search_domains
            .iter()
            .map(|d| d.trim_end_matches('.').to_owned())
            .collect();
        if domains
            .iter()
            .chain(&search)
            .any(|d| d.is_empty() || d.starts_with('.'))
        {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "Invalid DNS domain",
            ));
        }
        let mut state = self.state.lock().unwrap();
        self.check_search_lists(&state)?;
        for domain in &domains {
            state
                .rules
                .entry(domain.clone())
                .or_insert_with(|| NrptRule {
                    id: format!("{{{}}}", uuid::Uuid::new_v4()),
                    domain: domain.clone(),
                });
            self.recovery.save_rules(&state.rules)?;
            state.rules[domain].set(&nameservers)?;
        }
        let obsolete: Vec<_> = state
            .rules
            .keys()
            .filter(|d| !domains.contains(d))
            .cloned()
            .collect();
        for domain in obsolete {
            remove_rule(&state.rules[&domain].id)?;
            state.rules.remove(&domain);
            self.recovery.save_rules(&state.rules)?;
        }
        self.set_search_list(&mut state, &search)?;
        Self::flush_dns()
    }

    fn close(&self) -> io::Result<()> {
        let mut state = self.state.lock().unwrap();
        self.recovery.clean()?;
        Self::flush_dns()?;
        state.rules.clear();
        state.search_lists.clear();
        // This owner can still retry setup after a partial startup failure.
        state.prepared = true;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use winreg::enums::{HKEY_LOCAL_MACHINE, KEY_READ};

    // Supply an exclusively owned disposable adapter, never a user's interface.
    #[test]
    #[ignore = "requires administrator privileges and Windows DNS Client service"]
    fn manager_lifecycle() {
        let interface = std::env::var("EASYTIER_DNS_TEST_INTERFACE")
            .expect("set EASYTIER_DNS_TEST_INTERFACE to an owned disposable adapter");
        assert!(interface.starts_with("EasyTier-DNS-Test-"));
        let mut manager = WindowsDNSManager::new(&interface).unwrap();
        manager.recovery.path = format!(r"{RECOVERY_KEY}\Test-{}", uuid::Uuid::new_v4());
        let snapshots: Vec<_> = [
            RegistryManager::IPV4_TCPIP_INTERFACE_PREFIX,
            RegistryManager::IPV6_TCPIP_INTERFACE_PREFIX,
        ]
        .iter()
        .map(|prefix| {
            // Snapshot independently of the helper whose access mask we test.
            let key = RegKey::predef(HKEY_LOCAL_MACHINE)
                .open_subkey_with_flags(format!("{prefix}{}", manager.interface_guid), KEY_READ)
                .unwrap();
            let original = search_list(&key).unwrap();
            (key, original)
        })
        .collect();
        let domain = format!("{}.invalid", uuid::Uuid::new_v4().simple());
        let mut cfg = OSConfig {
            nameservers: vec!["192.0.2.53".to_owned()],
            search_domains: vec![format!("search.{domain}")],
            match_domains: vec![domain.clone()],
        };
        let first_text = cfg.search_domains.join(",");
        let second_text = format!("updated.{domain}");
        let first_expected = first_text.to_reg_value();
        let second_expected = second_text.to_reg_value();
        let result = (|| -> io::Result<_> {
            manager.set_dns(&cfg)?;
            let ids: Vec<String> = manager.recovery.open()?.get_value(RULE_IDS)?;
            assert_eq!(ids.len(), 1);
            assert_eq!(ids[0], manager.state.lock().unwrap().rules[&domain].id);
            let first = snapshots
                .iter()
                .map(|(key, _)| search_list(key))
                .collect::<io::Result<Vec<_>>>()?;
            cfg.search_domains = vec![second_text.clone()];
            manager.set_dns(&cfg)?;
            let second = snapshots
                .iter()
                .map(|(key, _)| search_list(key))
                .collect::<io::Result<Vec<_>>>()?;
            Ok((first, second))
        })();
        // Attempt cleanup even when configuration or observation fails.
        let cleanup = manager.close();
        let (first, second) = result.unwrap();
        cleanup.unwrap();
        for value in first {
            assert_eq!(value.as_ref(), Some(&first_expected));
        }
        for value in second {
            assert_eq!(value.as_ref(), Some(&second_expected));
        }
        for (key, original) in snapshots {
            assert_eq!(search_list(&key).unwrap(), original);
        }
        manager.close().unwrap();
        RegKey::predef(HKEY_LOCAL_MACHINE)
            .delete_subkey(&manager.recovery.path)
            .unwrap();
    }
}
