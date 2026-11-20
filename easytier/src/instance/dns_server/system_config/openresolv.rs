//! Configure the system resolver through the `resolvconf` framework.
//!
//! openresolv and the Debian `resolvconf` package publish a per-interface API:
//! every client registers its own entry and the framework merges them into
//! `/etc/resolv.conf`, then pushes the result to its subscribers (dnsmasq,
//! unbound, ...). Registering keeps concurrent DNS managers — another overlay,
//! a VPN client, a DHCP client — independent of each other, whereas rewriting
//! the file would silently discard whichever of them wrote last.

use std::{
    io::{self, Write},
    path::{Path, PathBuf},
    process::{Command, Stdio},
    sync::Mutex,
};

use super::{OSConfig, SystemConfig};

/// Marker files of the two common implementations. The binary alone is not
/// enough: systemd ships a `resolvconf` compatibility shim that only forwards
/// to systemd-resolved, which is the case this backend deliberately does not
/// take over.
const OPENRESOLV_CONF: &str = "/etc/resolvconf.conf";
const DEBIAN_RESOLVCONF_DIR: &str = "/etc/resolvconf";

/// Priority of our entry. 0 is the highest: local names have to win the merge,
/// because every other resolver on the host has never heard of them.
const METRIC: &str = "0";

pub struct OpenResolvConfigurator {
    key: String,
    applied: Mutex<Option<OSConfig>>,
}

impl OpenResolvConfigurator {
    pub fn new(interface: &str) -> Self {
        Self {
            key: Self::key(interface),
            applied: Mutex::new(None),
        }
    }

    /// Name used with resolvconf(8). The `<iface>.<owner>` shape follows the
    /// convention DHCP clients use; registering the same name again replaces
    /// the previous entry, which makes updates idempotent.
    fn key(interface: &str) -> String {
        format!("{interface}.easytier")
    }

    pub fn available() -> bool {
        Self::markers(Path::new(OPENRESOLV_CONF), Path::new(DEBIAN_RESOLVCONF_DIR))
            && Self::binary().is_some()
    }

    fn markers(openresolv_conf: &Path, debian_dir: &Path) -> bool {
        openresolv_conf.is_file() || debian_dir.is_dir()
    }

    fn binary() -> Option<PathBuf> {
        // A system service does not always inherit /usr/sbin on PATH.
        [
            "/usr/sbin/resolvconf",
            "/sbin/resolvconf",
            "/usr/bin/resolvconf",
        ]
        .into_iter()
        .map(PathBuf::from)
        .find(|path| path.is_file())
    }

    fn render(cfg: &OSConfig) -> String {
        let mut content = String::new();
        for nameserver in &cfg.nameservers {
            content.push_str("nameserver ");
            content.push_str(nameserver);
            content.push('\n');
        }
        // resolv.conf has no routing-domain concept: the search list is the
        // only place a suffix can go, so every served zone is listed there.
        let mut domains: Vec<&str> = Vec::new();
        for domain in cfg.search_domains.iter().chain(cfg.match_domains.iter()) {
            let domain = domain.trim_end_matches('.');
            if !domain.is_empty() && !domains.contains(&domain) {
                domains.push(domain);
            }
        }
        if !domains.is_empty() {
            content.push_str("search ");
            content.push_str(&domains.join(" "));
            content.push('\n');
        }
        content
    }

    fn run(args: &[&str], body: Option<&str>) -> io::Result<()> {
        let binary = Self::binary()
            .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "resolvconf not found"))?;
        let mut command = Command::new(binary);
        command.args(args);
        if body.is_some() {
            command
                .stdin(Stdio::piped())
                .stdout(Stdio::null())
                .stderr(Stdio::piped());
        }
        let mut child = command.spawn()?;
        if let Some(body) = body {
            let mut stdin = child
                .stdin
                .take()
                .ok_or_else(|| io::Error::other("resolvconf stdin unavailable"))?;
            stdin.write_all(body.as_bytes())?;
        }
        let output = child.wait_with_output()?;
        if !output.status.success() {
            return Err(io::Error::other(format!(
                "resolvconf {} failed: {}",
                args.join(" "),
                String::from_utf8_lossy(&output.stderr).trim()
            )));
        }
        Ok(())
    }
}

impl SystemConfig for OpenResolvConfigurator {
    /// Drop an entry a previous run may have left behind. Registrations are
    /// stored on disk, so a crash before `close` would otherwise keep pointing
    /// the host at an address nothing answers on.
    fn prepare(&self) -> io::Result<()> {
        let _ = Self::run(&["-d", &self.key], None);
        Ok(())
    }

    fn refresh(&self) -> io::Result<()> {
        let applied = self.applied.lock().unwrap().clone();
        match applied {
            Some(cfg) => self.set_dns(&cfg),
            None => Ok(()),
        }
    }

    fn set_dns(&self, cfg: &OSConfig) -> io::Result<()> {
        let body = Self::render(cfg);
        // openresolv sorts entries by metric; the legacy Debian implementation
        // has no metric option at all, so fall back to plain registration there
        // rather than failing the whole update.
        if Self::run(&["-a", &self.key, "-m", METRIC], Some(&body)).is_err() {
            Self::run(&["-a", &self.key], Some(&body))?;
        }
        *self.applied.lock().unwrap() = Some(cfg.clone());
        Ok(())
    }

    fn close(&self) -> io::Result<()> {
        *self.applied.lock().unwrap() = None;
        Self::run(&["-d", &self.key], None)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn config() -> OSConfig {
        OSConfig {
            nameservers: vec!["100.100.100.101".to_string()],
            search_domains: vec!["example.com.".to_string(), "other.example.".to_string()],
            match_domains: vec![
                "example.com".to_string(),
                "third.example".to_string(),
                "other.example".to_string(),
            ],
        }
    }

    #[test]
    fn render_lists_nameservers_and_every_zone_once() {
        assert_eq!(
            OpenResolvConfigurator::render(&config()),
            "nameserver 100.100.100.101\nsearch example.com other.example third.example\n"
        );
    }

    #[test]
    fn key_is_per_interface_and_stable() {
        assert_eq!(
            OpenResolvConfigurator::key("easytier0"),
            "easytier0.easytier"
        );
        assert_eq!(
            OpenResolvConfigurator::key("easytier0"),
            OpenResolvConfigurator::key("easytier0")
        );
    }

    #[test]
    fn markers_detect_both_implementations() {
        let dir = std::env::temp_dir().join(format!("easytier-resolvconf-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let conf = dir.join("resolvconf.conf");
        let debian = dir.join("resolvconf");

        assert!(!OpenResolvConfigurator::markers(&conf, &debian));
        std::fs::write(&conf, "").unwrap();
        assert!(OpenResolvConfigurator::markers(&conf, &debian));
        std::fs::remove_file(&conf).unwrap();
        std::fs::create_dir_all(&debian).unwrap();
        assert!(OpenResolvConfigurator::markers(&conf, &debian));

        let _ = std::fs::remove_dir_all(&dir);
    }
}
