use std::{fs, io, process::Command, sync::Mutex};

use super::{OSConfig, SystemConfig};

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
    nameservers: Vec<String>,
    domains: Vec<String>,
    default_route: bool,
}

struct AppliedConfig {
    original: LinkConfig,
    current: LinkConfig,
}

/// Only configures the EasyTier link. Other links retain their DNS settings.
pub struct ResolvedConfigurator {
    interface: String,
    applied: Mutex<Option<AppliedConfig>>,
}

impl ResolvedConfigurator {
    pub fn new(interface: &str) -> Self {
        Self {
            interface: interface.to_owned(),
            applied: Mutex::new(None),
        }
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

    fn resolvectl(&self, verb: &str, values: &[String]) -> io::Result<String> {
        let output = Command::new("resolvectl")
            .env("LC_ALL", "C")
            .arg(verb)
            .arg("--")
            .arg(&self.interface)
            .args(values)
            .output()
            .map_err(|error| {
                io::Error::new(
                    error.kind(),
                    format!("Failed to invoke resolvectl for Magic DNS: {error}"),
                )
            })?;
        if !output.status.success() {
            return Err(io::Error::other(format!(
                "resolvectl {verb} {} failed: {}{}",
                self.interface,
                String::from_utf8_lossy(&output.stdout),
                String::from_utf8_lossy(&output.stderr),
            )));
        }
        Ok(String::from_utf8_lossy(&output.stdout).into_owned())
    }

    fn read_values(&self, verb: &str) -> io::Result<Vec<String>> {
        let output = self.resolvectl(verb, &[])?;
        let (_, values) = output
            .split_once(':')
            .ok_or_else(|| io::Error::other(format!("Unexpected resolvectl output: {output}")))?;
        Ok(values.split_whitespace().map(str::to_owned).collect())
    }

    fn read_config(&self) -> io::Result<LinkConfig> {
        let nameservers = self.read_values("dns")?;
        let domains = self.read_values("domain")?;
        let default_route = match self.read_values("default-route")?.as_slice() {
            [value] if value == "yes" => true,
            [value] if value == "no" => false,
            values => {
                return Err(io::Error::other(format!(
                    "Unexpected resolved DefaultRoute value: {values:?}"
                )));
            }
        };
        Ok(LinkConfig {
            nameservers,
            domains,
            default_route,
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
        Ok(LinkConfig {
            nameservers: cfg.nameservers.clone(),
            domains,
            default_route: false,
        })
    }

    // Record each successful write so normal cleanup also handles partial setup.
    fn write_config(&self, applied: &mut AppliedConfig, cfg: &LinkConfig) -> io::Result<()> {
        self.resolvectl(
            "default-route",
            &[if cfg.default_route { "yes" } else { "no" }.to_owned()],
        )?;
        applied.current.default_route = cfg.default_route;
        let empty = [String::new()];
        self.resolvectl(
            "domain",
            if cfg.domains.is_empty() {
                &empty
            } else {
                &cfg.domains
            },
        )?;
        applied.current.domains.clone_from(&cfg.domains);
        self.resolvectl(
            "dns",
            if cfg.nameservers.is_empty() {
                &empty
            } else {
                &cfg.nameservers
            },
        )?;
        applied.current.nameservers.clone_from(&cfg.nameservers);
        Ok(())
    }
}

impl SystemConfig for ResolvedConfigurator {
    fn set_dns(&self, cfg: &OSConfig) -> io::Result<()> {
        let desired = Self::desired_config(cfg)?;
        if !Self::uses_resolved(
            &fs::read_to_string("/etc/resolv.conf")?,
            &fs::read_to_string("/etc/nsswitch.conf").unwrap_or_default(),
        ) {
            return Err(io::Error::other(
                "Magic DNS requires system DNS to use the systemd-resolved stub or nss-resolve",
            ));
        }
        let mut state = self.applied.lock().unwrap();
        let current = self.read_config()?;
        if let Some(applied) = state.as_ref() {
            if current != applied.current {
                return Err(io::Error::other(format!(
                    "DNS settings on {} changed outside EasyTier; refusing to overwrite them",
                    self.interface,
                )));
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
                current,
            });
        }
        self.write_config(state.as_mut().unwrap(), &desired)
    }

    fn close(&self) -> io::Result<()> {
        let mut state = self.applied.lock().unwrap();
        let Some(applied) = state.as_mut() else {
            return Ok(());
        };
        if self.read_config()? != applied.current {
            return Err(io::Error::other(format!(
                "DNS settings on {} changed outside EasyTier; preserving them",
                self.interface,
            )));
        }
        let original = applied.original.clone();
        self.write_config(applied, &original)?;
        *state = None;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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
}
