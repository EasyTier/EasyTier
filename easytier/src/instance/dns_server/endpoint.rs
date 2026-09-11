use std::{
    fs::{File, OpenOptions, TryLockError},
    io::{Seek, SeekFrom, Write},
    net::IpAddr,
    path::{Path, PathBuf},
};

use anyhow::Context;
#[cfg(unix)]
use std::os::unix::fs::OpenOptionsExt;

const MAGIC_DNS_ENDPOINT_FILE: &str = "easytier-magic-dns-v1.endpoint";
pub(super) const MAGIC_DNS_BIND_ADDR: &str = "127.0.0.1:0";

pub(super) struct MagicDnsServerLease {
    file: File,
}

impl MagicDnsServerLease {
    pub(super) fn try_acquire() -> anyhow::Result<Option<Self>> {
        Self::try_acquire_at(&endpoint_file_path())
    }

    fn try_acquire_at(path: &Path) -> anyhow::Result<Option<Self>> {
        let mut options = OpenOptions::new();
        options.create(true).truncate(false).read(true).write(true);
        #[cfg(unix)]
        options.mode(0o600).custom_flags(nix::libc::O_NOFOLLOW);

        let file = options.open(path).with_context(|| {
            format!(
                "failed to open Magic DNS endpoint registry {}",
                path.display()
            )
        })?;

        match file.try_lock() {
            Ok(()) => {
                file.set_len(0).with_context(|| {
                    format!(
                        "failed to reset Magic DNS endpoint registry {}",
                        path.display()
                    )
                })?;
                Ok(Some(Self { file }))
            }
            Err(TryLockError::WouldBlock) => Ok(None),
            Err(TryLockError::Error(error)) => Err(error).with_context(|| {
                format!(
                    "failed to lock Magic DNS endpoint registry {}",
                    path.display()
                )
            }),
        }
    }

    pub(super) fn publish(&mut self, endpoint: &url::Url) -> anyhow::Result<()> {
        validate_endpoint(endpoint)?;
        self.file.seek(SeekFrom::Start(0))?;
        self.file.set_len(0)?;
        self.file.write_all(endpoint.as_str().as_bytes())?;
        self.file.sync_data()?;
        Ok(())
    }
}

impl Drop for MagicDnsServerLease {
    fn drop(&mut self) {
        let _ = self.file.set_len(0);
        let _ = self.file.unlock();
    }
}

pub(super) fn discover_magic_dns_endpoint() -> anyhow::Result<url::Url> {
    discover_magic_dns_endpoint_at(&endpoint_file_path())
}

fn discover_magic_dns_endpoint_at(path: &Path) -> anyhow::Result<url::Url> {
    let endpoint = std::fs::read_to_string(path).with_context(|| {
        format!(
            "failed to read Magic DNS endpoint registry {}",
            path.display()
        )
    })?;
    let endpoint = endpoint
        .trim()
        .parse::<url::Url>()
        .context("Magic DNS endpoint registry does not contain a valid URL")?;
    validate_endpoint(&endpoint)?;
    Ok(endpoint)
}

fn validate_endpoint(endpoint: &url::Url) -> anyhow::Result<()> {
    let is_loopback = endpoint
        .host_str()
        .and_then(|host| host.parse::<IpAddr>().ok())
        .is_some_and(|ip| ip.is_loopback());
    if endpoint.scheme() != "tcp" || !is_loopback || endpoint.port().is_none_or(|port| port == 0) {
        anyhow::bail!(
            "Magic DNS endpoint must be a loopback TCP URL with a non-zero port, got {endpoint}"
        );
    }
    Ok(())
}

fn endpoint_file_path() -> PathBuf {
    std::env::temp_dir().join(MAGIC_DNS_ENDPOINT_FILE)
}

#[cfg(test)]
mod tests {
    use std::net::TcpListener;

    use super::*;

    #[test]
    fn lease_is_exclusive_and_clears_stale_endpoint() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("magic-dns.endpoint");
        std::fs::write(&path, "tcp://127.0.0.1:49813").unwrap();

        let mut first = MagicDnsServerLease::try_acquire_at(&path).unwrap().unwrap();
        assert!(std::fs::read_to_string(&path).unwrap().is_empty());
        assert!(
            MagicDnsServerLease::try_acquire_at(&path)
                .unwrap()
                .is_none()
        );

        let endpoint: url::Url = "tcp://127.0.0.1:54321".parse().unwrap();
        first.publish(&endpoint).unwrap();
        assert_eq!(discover_magic_dns_endpoint_at(&path).unwrap(), endpoint);

        drop(first);
        assert!(std::fs::read_to_string(&path).unwrap().is_empty());
        assert!(
            MagicDnsServerLease::try_acquire_at(&path)
                .unwrap()
                .is_some()
        );
    }

    #[test]
    fn discovery_rejects_non_loopback_endpoints() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("magic-dns.endpoint");

        for endpoint in [
            "tcp://192.0.2.1:54321",
            "tcp://localhost:54321",
            "udp://127.0.0.1:54321",
            "tcp://127.0.0.1:0",
            "not-a-url",
        ] {
            std::fs::write(&path, endpoint).unwrap();
            assert!(discover_magic_dns_endpoint_at(&path).is_err(), "{endpoint}");
        }
    }

    #[test]
    fn magic_dns_bind_address_uses_an_os_assigned_port() {
        let occupied = TcpListener::bind("127.0.0.1:0").unwrap();
        let occupied_port = occupied.local_addr().unwrap().port();

        let listener = TcpListener::bind(MAGIC_DNS_BIND_ADDR).unwrap();
        let assigned_port = listener.local_addr().unwrap().port();

        assert_ne!(assigned_port, 0);
        assert_ne!(assigned_port, occupied_port);
    }

    #[cfg(unix)]
    #[test]
    fn lease_does_not_follow_registry_symlinks() {
        use std::os::unix::fs::symlink;

        let directory = tempfile::tempdir().unwrap();
        let target = directory.path().join("target");
        let registry = directory.path().join("magic-dns.endpoint");
        std::fs::write(&target, "do not truncate").unwrap();
        symlink(&target, &registry).unwrap();

        assert!(MagicDnsServerLease::try_acquire_at(&registry).is_err());
        assert_eq!(std::fs::read_to_string(target).unwrap(), "do not truncate");
    }
}
