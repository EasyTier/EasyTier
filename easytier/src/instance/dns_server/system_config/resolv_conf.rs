use std::{
    fs::{self, File, OpenOptions},
    io::{self, Read, Write},
    net::IpAddr,
    os::fd::AsRawFd,
    os::unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt, PermissionsExt, chown},
    path::{Path, PathBuf},
    sync::Mutex,
};

use hickory_resolver::system_conf::parse_resolv_conf;
use serde::{Deserialize, Serialize};

use super::{OSConfig, SystemConfig};

const HEADER: &str =
    "# Configured by EasyTier Magic DNS; all queries use its upstream forwarder.\n";
const OWNER_PREFIX: &str = "# EasyTier DNS ownership: ";

#[derive(Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct ResolverFile {
    content: String,
    device: u64,
    inode: u64,
    mode: u32,
    uid: u32,
    gid: u32,
}

impl ResolverFile {
    fn read(path: &Path) -> io::Result<Self> {
        Self::read_file(path, false)
    }

    fn read_for_replacement(path: &Path) -> io::Result<Self> {
        Self::read_file(path, true)
    }

    fn read_file(path: &Path, replacing: bool) -> io::Result<Self> {
        if fs::symlink_metadata(path)?.file_type().is_symlink() {
            return Err(io::Error::other(format!(
                "{} is a managed symlink; automatic Magic DNS takeover is unsupported",
                path.display()
            )));
        }
        let mut file = OpenOptions::new()
            .read(true)
            .custom_flags(nix::libc::O_NOFOLLOW | nix::libc::O_NONBLOCK)
            .open(path)?;
        let metadata = file.metadata()?;
        if !metadata.is_file() || metadata.nlink() != 1 {
            return Err(io::Error::other(
                "Magic DNS requires a regular, unshared resolv.conf file",
            ));
        }
        if replacing {
            // Atomic replacement creates a new inode. Until attributes can be
            // preserved, refuse to discard SELinux labels, ACLs or other xattrs.
            // Ordinary upstream reads do not require changing this metadata.
            let size = unsafe { nix::libc::flistxattr(file.as_raw_fd(), std::ptr::null_mut(), 0) };
            if size > 0 {
                return Err(io::Error::other(format!(
                    "{} has extended attributes; preserving it instead of replacing system DNS",
                    path.display(),
                )));
            }
            if size < 0 {
                let error = io::Error::last_os_error();
                if error.raw_os_error() != Some(nix::libc::ENOTSUP) {
                    return Err(error);
                }
            }
        }
        let mut content = String::new();
        file.read_to_string(&mut content)?;
        Ok(Self {
            content,
            device: metadata.dev(),
            inode: metadata.ino(),
            mode: metadata.mode(),
            uid: metadata.uid(),
            gid: metadata.gid(),
        })
    }

    fn same_config(&self, other: &Self) -> bool {
        self.content == other.content
            && self.mode == other.mode
            && self.uid == other.uid
            && self.gid == other.gid
    }

    fn is_managed(&self) -> bool {
        ResolvConfConfigurator::needs_recovery(&self.content)
    }
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct RecoveryRecord {
    target: PathBuf,
    original: ResolverFile,
    previous: ResolverFile,
    pending: ResolverFile,
    temporary: String,
}

struct RecoveryStore {
    directory: PathBuf,
    directory_file: File,
    parent_file: File,
    _lock: File,
}

impl RecoveryStore {
    fn trusted(metadata: &fs::Metadata, mode: u32) -> io::Result<()> {
        // The process must already have permission to change the resolver file.
        // Its recovery metadata must not be writable or replaceable by others.
        let uid = unsafe { nix::libc::geteuid() };
        if metadata.uid() != uid || metadata.mode() & 0o777 != mode {
            return Err(io::Error::other(
                "Untrusted EasyTier DNS recovery ownership or permissions",
            ));
        }
        Ok(())
    }

    fn open(parent: &Path) -> io::Result<Self> {
        let parent_file = OpenOptions::new()
            .read(true)
            .custom_flags(nix::libc::O_DIRECTORY | nix::libc::O_NOFOLLOW)
            .open(parent)?;
        let metadata = parent_file.metadata()?;
        let uid = unsafe { nix::libc::geteuid() };
        if metadata.uid() != uid || metadata.mode() & 0o022 != 0 {
            return Err(io::Error::other(
                "resolv.conf parent must be owned by EasyTier's user and not writable by others",
            ));
        }
        let directory = parent.join(".easytier-dns");
        match fs::DirBuilder::new().mode(0o700).create(&directory) {
            Ok(()) => parent_file.sync_all()?,
            Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {}
            Err(error) => return Err(error),
        }
        let directory_file = OpenOptions::new()
            .read(true)
            .custom_flags(nix::libc::O_DIRECTORY | nix::libc::O_NOFOLLOW)
            .open(&directory)?;
        Self::trusted(&directory_file.metadata()?, 0o700)?;
        let lock_path = directory.join("lock");
        let lock = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .mode(0o600)
            .custom_flags(nix::libc::O_NOFOLLOW)
            .open(&lock_path)?;
        let metadata = lock.metadata()?;
        Self::trusted(&metadata, 0o600)?;
        if !metadata.is_file() || metadata.nlink() != 1 {
            return Err(io::Error::other("Invalid EasyTier DNS lock file"));
        }
        // Never delete this inode: all cooperating processes lock the same file,
        // including processes using different EasyTier instance/state dirs.
        if unsafe { nix::libc::flock(lock.as_raw_fd(), nix::libc::LOCK_EX | nix::libc::LOCK_NB) }
            != 0
        {
            return Err(io::Error::other(format!(
                "Another EasyTier process owns system DNS: {}",
                io::Error::last_os_error(),
            )));
        }
        let current = fs::symlink_metadata(&lock_path)?;
        if current.dev() != metadata.dev() || current.ino() != metadata.ino() {
            return Err(io::Error::other("EasyTier DNS lock was replaced"));
        }
        lock.sync_all()?;
        directory_file.sync_all()?;
        Ok(Self {
            directory,
            directory_file,
            parent_file,
            _lock: lock,
        })
    }

    fn read(&self, target: &Path) -> io::Result<Option<RecoveryRecord>> {
        let mut file = match OpenOptions::new()
            .read(true)
            .custom_flags(nix::libc::O_NOFOLLOW | nix::libc::O_NONBLOCK)
            .open(self.directory.join("recovery.json"))
        {
            Ok(file) => file,
            Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
            Err(error) => return Err(error),
        };
        let metadata = file.metadata()?;
        Self::trusted(&metadata, 0o600)?;
        if !metadata.is_file() || metadata.nlink() != 1 || metadata.len() > 1024 * 1024 {
            return Err(io::Error::other("Invalid EasyTier DNS recovery record"));
        }
        let mut content = String::new();
        file.read_to_string(&mut content)?;
        let record: RecoveryRecord = serde_json::from_str(&content).map_err(io::Error::other)?;
        if record.target != target
            || record
                .temporary
                .strip_prefix("resolver-")
                .is_none_or(|value| uuid::Uuid::parse_str(value).is_err())
            || [&record.original, &record.previous, &record.pending]
                .iter()
                .any(|file| file.mode & nix::libc::S_IFMT != nix::libc::S_IFREG)
            || (!record.previous.is_managed() && !record.previous.same_config(&record.original))
            || (!record.pending.is_managed() && !record.pending.same_config(&record.original))
        {
            return Err(io::Error::other(
                "Inconsistent EasyTier DNS recovery record",
            ));
        }
        ResolvConfConfigurator::validate_original(&record.original.content)?;
        Ok(Some(record))
    }

    fn write(&self, record: &RecoveryRecord) -> io::Result<()> {
        let content = serde_json::to_vec(record).map_err(io::Error::other)?;
        if content.len() > 1024 * 1024 {
            return Err(io::Error::other(
                "EasyTier DNS recovery record is too large",
            ));
        }
        let temporary = self
            .directory
            .join(format!("record-{}", uuid::Uuid::new_v4()));
        let result = (|| {
            let mut file = OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(0o600)
                .custom_flags(nix::libc::O_NOFOLLOW)
                .open(&temporary)?;
            file.write_all(&content)?;
            file.sync_all()?;
            fs::rename(&temporary, self.directory.join("recovery.json"))?;
            self.directory_file.sync_all()
        })();
        if result.is_err() {
            let _ = fs::remove_file(&temporary);
        }
        result
    }

    fn remove(&self, record: &RecoveryRecord) -> io::Result<()> {
        let temporary = self.directory.join(&record.temporary);
        match ResolverFile::read_for_replacement(&temporary) {
            Ok(current) if current == record.pending => fs::remove_file(&temporary)?,
            Ok(_) => {
                return Err(io::Error::other(
                    "EasyTier DNS recovery temporary file changed; preserving it",
                ));
            }
            Err(error) if error.kind() == io::ErrorKind::NotFound => {}
            Err(error) => return Err(error),
        }
        fs::remove_file(self.directory.join("recovery.json"))?;
        self.directory_file.sync_all()
    }
}

#[derive(Default)]
struct ResolverState {
    original: Option<ResolverFile>,
    applied: Option<ResolverFile>,
    recovery: Option<RecoveryStore>,
}

/// A plain resolv.conf cannot route domains. Route all DNS through the existing
/// Magic DNS endpoint, whose root forwarder retains the original nameservers.
/// Managed files and local stubs need their own verified integration.
pub struct ResolvConfConfigurator {
    path: PathBuf,
    state: Mutex<ResolverState>,
}

impl ResolvConfConfigurator {
    pub(super) fn needs_recovery(content: &str) -> bool {
        content.starts_with(HEADER)
            && content.lines().nth(1).is_some_and(|line| {
                line.strip_prefix(OWNER_PREFIX)
                    .is_some_and(|value| uuid::Uuid::parse_str(value).is_ok())
            })
    }

    pub fn new(path: PathBuf) -> Self {
        Self {
            path,
            state: Mutex::new(ResolverState::default()),
        }
    }

    pub fn check_support(&self) -> io::Result<()> {
        let current = ResolverFile::read(&self.path)?;
        if current.is_managed() {
            // Selection is read-only. Only the elected server may take the
            // host lock and inspect the durable recovery record.
            Ok(())
        } else {
            Self::validate_original(&current.content)
        }
    }

    fn validate_original(content: &str) -> io::Result<()> {
        for line in content
            .lines()
            .filter(|line| line.trim_start().starts_with('#'))
        {
            let comment = line.to_ascii_lowercase();
            if comment.contains("easytier magic dns")
                || comment.contains("networkmanager")
                || comment.contains("resolvconf")
                || comment.contains("systemd-resolved")
                || comment.contains("generated by")
                || comment.contains("managed by")
            {
                return Err(io::Error::other(format!(
                    "Managed resolv.conf is unsupported for direct Magic DNS takeover: {line}"
                )));
            }
        }
        let (config, _) = parse_resolv_conf(content).map_err(io::Error::other)?;
        let fake_ip: IpAddr = super::super::MAGIC_DNS_FAKE_IP
            .parse()
            .map_err(io::Error::other)?;
        if config.name_servers().iter().any(|server| {
            let ip = server.socket_addr.ip();
            ip == fake_ip || ip.is_loopback() || ip.is_unspecified() || ip.is_multicast()
        }) {
            return Err(io::Error::other(
                "Automatic resolv.conf takeover requires original DNS servers outside Magic DNS and local stubs",
            ));
        }
        Ok(())
    }

    fn desired_content(original: &str, cfg: &OSConfig) -> io::Result<String> {
        let (base, _) = parse_resolv_conf(original).map_err(io::Error::other)?;
        let nameservers = cfg
            .nameservers
            .iter()
            .map(|value| value.parse::<IpAddr>().map_err(io::Error::other))
            .collect::<io::Result<Vec<_>>>()?;
        if nameservers.is_empty()
            || base
                .name_servers()
                .iter()
                .any(|server| nameservers.contains(&server.socket_addr.ip()))
        {
            return Err(io::Error::other(
                "Magic DNS cannot forward to its own system DNS address",
            ));
        }
        let mut search = Vec::new();
        for domain in &cfg.search_domains {
            let domain = domain.trim_end_matches('.');
            if domain.is_empty()
                || domain.split('.').any(|label| {
                    label.is_empty()
                        || !label
                            .bytes()
                            .all(|ch| ch.is_ascii_alphanumeric() || matches!(ch, b'-' | b'_'))
                })
            {
                return Err(io::Error::other("Invalid Magic DNS search domain"));
            }
            if !search.contains(&domain.to_owned()) {
                search.push(domain.to_owned());
            }
        }
        for domain in base.search() {
            let domain = domain.to_utf8().trim_end_matches('.').to_owned();
            if !search.contains(&domain) {
                search.push(domain);
            }
        }
        // `domain` supplies the search path when no explicit search is present.
        if base.search().is_empty()
            && let Some(domain) = base.domain()
            && !domain.is_root()
        {
            let domain = domain.to_utf8().trim_end_matches('.').to_owned();
            if !search.contains(&domain) {
                search.push(domain);
            }
        }
        let mut content = String::from(HEADER);
        content.push_str(&format!("{OWNER_PREFIX}{}\n", uuid::Uuid::new_v4()));
        for nameserver in nameservers {
            content.push_str(&format!("nameserver {nameserver}\n"));
        }
        if !search.is_empty() {
            content.push_str(&format!("search {}\n", search.join(" ")));
        }
        // Preserve options and all unrelated original lines verbatim. Search
        // domains are merged above rather than overridden by a later directive.
        for line in original.split_inclusive('\n') {
            if !matches!(
                line.split_whitespace().next(),
                Some("nameserver" | "search" | "domain")
            ) {
                content.push_str(line);
            }
        }
        Ok(content)
    }

    fn replace(
        &self,
        recovery: &RecoveryStore,
        original: &ResolverFile,
        expected: &ResolverFile,
        content: String,
    ) -> io::Result<ResolverFile> {
        let name = format!("resolver-{}", uuid::Uuid::new_v4());
        let temporary = recovery.directory.join(&name);
        let result = (|| {
            let mut file = OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(expected.mode & 0o7777)
                .custom_flags(nix::libc::O_NOFOLLOW)
                .open(&temporary)?;
            let metadata = file.metadata()?;
            if metadata.uid() != expected.uid || metadata.gid() != expected.gid {
                chown(&temporary, Some(expected.uid), Some(expected.gid))?;
            }
            file.write_all(content.as_bytes())?;
            file.set_permissions(fs::Permissions::from_mode(expected.mode & 0o7777))?;
            file.sync_all()?;
            let replacement = ResolverFile::read_for_replacement(&temporary)?;
            if ResolverFile::read_for_replacement(&self.path)? != *expected {
                return Err(io::Error::other(
                    "resolv.conf changed outside EasyTier; preserving it",
                ));
            }
            recovery.write(&RecoveryRecord {
                target: self.path.clone(),
                original: original.clone(),
                previous: expected.clone(),
                pending: replacement.clone(),
                temporary: name,
            })?;
            // The durable recovery record covers both sides of this rename.
            if ResolverFile::read_for_replacement(&self.path)? != *expected {
                return Err(io::Error::other(
                    "resolv.conf changed outside EasyTier; preserving it",
                ));
            }
            fs::rename(&temporary, &self.path)?;
            recovery.parent_file.sync_all()?;
            recovery.directory_file.sync_all()?;
            Ok(replacement)
        })();
        if result.is_err() {
            let _ = fs::remove_file(&temporary);
            let _ = recovery.directory_file.sync_all();
        }
        result
    }

    fn recover(&self, recovery: &RecoveryStore) -> io::Result<()> {
        let Some(record) = recovery.read(&self.path)? else {
            return Ok(());
        };
        let current = ResolverFile::read(&self.path)?;
        if current.same_config(&record.original) {
            // This also covers a crash after restoration but before removing
            // the recovery record. Never overwrite an already restored file.
            return recovery.remove(&record);
        }
        if !current.is_managed() || (current != record.previous && current != record.pending) {
            return Err(io::Error::other(
                "resolv.conf no longer matches EasyTier's recovery record; preserving it",
            ));
        }
        self.replace(
            recovery,
            &record.original,
            &current,
            record.original.content.clone(),
        )?;
        // A pre-rename crash may have left the previous pending resolver file.
        // Only delete it if its full identity still matches the old record.
        let pending = recovery.directory.join(&record.temporary);
        match ResolverFile::read_for_replacement(&pending) {
            Ok(current) if current == record.pending => fs::remove_file(pending)?,
            Ok(_) => {
                return Err(io::Error::other(
                    "EasyTier DNS recovery temporary file changed; preserving it",
                ));
            }
            Err(error) if error.kind() == io::ErrorKind::NotFound => {}
            Err(error) => return Err(error),
        }
        let restored = recovery
            .read(&self.path)?
            .ok_or_else(|| io::Error::other("EasyTier DNS recovery record disappeared"))?;
        recovery.remove(&restored)
    }
}

impl SystemConfig for ResolvConfConfigurator {
    fn needs_resolv_conf_recovery(&self) -> bool {
        true
    }

    fn original_resolv_conf(&self) -> io::Result<Option<String>> {
        let mut state = self.state.lock().unwrap();
        if state.applied.is_none() && state.recovery.is_none() {
            let current = ResolverFile::read(&self.path)?;
            if !current.is_managed() {
                // Reading upstreams does not require permission to create recovery
                // state. set_dns repeats the identity check under the takeover lock.
                Self::validate_original(&current.content)?;
                state.original = Some(current);
                return Ok(state.original.as_ref().map(|file| file.content.clone()));
            }
        }
        if state.recovery.is_none() {
            let parent = self
                .path
                .parent()
                .ok_or_else(|| io::Error::other("resolv.conf has no parent directory"))?;
            state.recovery = Some(RecoveryStore::open(parent)?);
        }
        let current = ResolverFile::read(&self.path)?;
        if let Some(applied) = &state.applied {
            let record = state
                .recovery
                .as_ref()
                .unwrap()
                .read(&self.path)?
                .ok_or_else(|| io::Error::other("EasyTier DNS recovery record is missing"))?;
            if state.original.as_ref() != Some(&record.original) {
                return Err(io::Error::other(
                    "EasyTier DNS original recovery configuration changed; preserving resolv.conf",
                ));
            }
            if *applied != current {
                // A rename may have succeeded while a later directory fsync
                // failed. The durable record, rather than a guessed PID or
                // header alone, proves whether this is still our version.
                if !current.is_managed()
                    || (current != record.previous && current != record.pending)
                {
                    return Err(io::Error::other(
                        "resolv.conf changed outside EasyTier; system DNS is no longer owned by EasyTier",
                    ));
                }
                state.applied = Some(current);
            }
        } else {
            // A failed first set can leave a durable record even when no
            // successful application was recorded in memory.
            self.recover(state.recovery.as_ref().unwrap())?;
            let current = ResolverFile::read(&self.path)?;
            Self::validate_original(&current.content)?;
            state.original = Some(current);
        }
        Ok(state.original.as_ref().map(|file| file.content.clone()))
    }

    fn set_dns(&self, cfg: &OSConfig) -> io::Result<()> {
        let nsswitch = self.path.with_file_name("nsswitch.conf");
        if super::linux::ResolvedConfigurator::uses_resolved(
            "",
            &fs::read_to_string(nsswitch).unwrap_or_default(),
        ) {
            return Err(io::Error::other(
                "NSS now uses systemd-resolved; original resolv.conf was recovered, restart EasyTier to select resolved",
            ));
        }
        let mut state = self.state.lock().unwrap();
        if state.original.is_none() {
            return Err(io::Error::other(
                "Original DNS must be loaded before resolv.conf takeover",
            ));
        }
        if state.recovery.is_none() {
            let parent = self
                .path
                .parent()
                .ok_or_else(|| io::Error::other("resolv.conf has no parent directory"))?;
            state.recovery = Some(RecoveryStore::open(parent)?);
            self.recover(state.recovery.as_ref().unwrap())?;
            let current = ResolverFile::read(&self.path)?;
            if state.original.as_ref() != Some(&current) {
                return Err(io::Error::other(
                    "resolv.conf changed outside EasyTier; reload original DNS before takeover",
                ));
            }
        }
        let original = state.original.as_ref().unwrap();
        let recovery = state.recovery.as_ref().unwrap();
        let content = Self::desired_content(&original.content, cfg)?;
        let expected = state.applied.as_ref().unwrap_or(original);
        if state.applied.is_some() {
            let record = recovery
                .read(&self.path)?
                .ok_or_else(|| io::Error::other("EasyTier DNS recovery record is missing"))?;
            if record.original != *original {
                return Err(io::Error::other(
                    "EasyTier DNS original recovery configuration changed; preserving resolv.conf",
                ));
            }
        }
        let applied = self.replace(recovery, original, expected, content)?;
        let initial = state.applied.is_none();
        state.applied = Some(applied);
        if initial {
            crate::common::log::info!(
                category: "DNS",
                "System DNS now uses Magic DNS for all domains; ordinary domains use its existing upstream forwarder"
            );
        }
        Ok(())
    }

    fn close(&self) -> io::Result<()> {
        let mut state = self.state.lock().unwrap();
        if let Some(recovery) = &state.recovery {
            if state.applied.is_some() && recovery.read(&self.path)?.is_none() {
                return Err(io::Error::other(
                    "EasyTier DNS recovery record is missing; preserving current resolv.conf",
                ));
            }
            self.recover(recovery)?;
        }
        // Dropping the file releases flock; the shared lock inode is permanent.
        *state = ResolverState::default();
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn config() -> OSConfig {
        OSConfig {
            nameservers: vec!["100.100.100.101".to_owned()],
            search_domains: vec!["et.net.".to_owned()],
            match_domains: vec!["et.net.".to_owned()],
        }
    }

    #[test]
    fn configures_forwarding_search_options_and_restores_original() -> io::Result<()> {
        let directory = tempfile::tempdir()?;
        let path = directory.path().join("resolv.conf");
        let original = "# original\nnameserver 192.0.2.53\nsearch lan.test\noptions timeout:1 attempts:2 ndots:2\n";
        fs::write(&path, original)?;
        fs::set_permissions(&path, fs::Permissions::from_mode(0o640))?;
        let configurator = ResolvConfConfigurator::new(path.clone());
        assert_eq!(
            configurator.original_resolv_conf()?,
            Some(original.to_owned())
        );
        configurator.set_dns(&config())?;
        let applied = fs::read_to_string(&path)?;
        assert!(applied.contains("nameserver 100.100.100.101\n"));
        assert!(!applied.contains("nameserver 192.0.2.53\n"));
        assert!(applied.contains("search et.net lan.test\n"));
        assert!(applied.contains("options timeout:1 attempts:2 ndots:2\n"));
        assert_eq!(fs::metadata(&path)?.mode() & 0o777, 0o640);
        assert_eq!(
            configurator.original_resolv_conf()?,
            Some(original.to_owned())
        );
        let mut updated = config();
        updated.search_domains = vec!["new.test.".to_owned()];
        configurator.set_dns(&updated)?;
        assert!(fs::read_to_string(&path)?.contains("search new.test lan.test\n"));
        configurator.close()?;
        configurator.close()?;
        assert_eq!(fs::read_to_string(&path)?, original);
        assert_eq!(fs::metadata(&path)?.mode() & 0o777, 0o640);
        Ok(())
    }

    #[test]
    fn preserves_external_changes_before_during_and_after_takeover() -> io::Result<()> {
        let directory = tempfile::tempdir()?;
        let path = directory.path().join("resolv.conf");
        fs::write(&path, "nameserver 192.0.2.53\n")?;
        let configurator = ResolvConfConfigurator::new(path.clone());
        configurator.original_resolv_conf()?;
        fs::write(&path, "nameserver 192.0.2.54\n")?;
        assert!(configurator.set_dns(&config()).is_err());
        configurator.original_resolv_conf()?;
        configurator.set_dns(&config())?;
        let replacement = directory.path().join("replacement");
        let external = "nameserver 192.0.2.55\n";
        fs::write(&replacement, external)?;
        fs::rename(&replacement, &path)?;
        assert!(configurator.original_resolv_conf().is_err());
        assert!(configurator.set_dns(&config()).is_err());
        assert!(configurator.close().is_err());
        assert_eq!(fs::read_to_string(&path)?, external);
        assert_eq!(fs::read_dir(directory.path())?.count(), 2);
        Ok(())
    }

    #[test]
    fn preserves_extended_attributes_before_and_after_takeover() -> io::Result<()> {
        use std::ffi::CString;

        for phase in ["before_read", "before_set", "after_set"] {
            let directory = tempfile::tempdir()?;
            let path = directory.path().join("resolv.conf");
            let original = "nameserver 192.0.2.53\n";
            fs::write(&path, original)?;
            let configurator = ResolvConfConfigurator::new(path.clone());
            if phase != "before_read" {
                assert_eq!(
                    configurator.original_resolv_conf()?,
                    Some(original.to_owned())
                );
            }
            if phase == "after_set" {
                configurator.set_dns(&config())?;
            }
            let file = File::open(&path)?;
            let name = CString::new("user.easytier-test").unwrap();
            let value = b"preserve";
            let result = unsafe {
                nix::libc::fsetxattr(
                    file.as_raw_fd(),
                    name.as_ptr(),
                    value.as_ptr().cast(),
                    value.len(),
                    0,
                )
            };
            if result != 0 {
                return Err(io::Error::last_os_error());
            }
            let snapshot = ResolverFile::read(&path)?;
            // Refusing metadata replacement must not disable original upstream reads.
            assert_eq!(
                configurator.original_resolv_conf()?,
                Some(original.to_owned())
            );
            assert!(configurator.set_dns(&config()).is_err());
            if phase == "after_set" {
                assert!(configurator.close().is_err());
                assert!(
                    directory
                        .path()
                        .join(".easytier-dns/recovery.json")
                        .exists()
                );
                drop(configurator);
                let restarted = ResolvConfConfigurator::new(path.clone());
                assert!(restarted.original_resolv_conf().is_err());
                assert!(ResolverFile::read(&path)? == snapshot);
            } else {
                configurator.close()?;
            }
            assert!(ResolverFile::read(&path)? == snapshot);
            let mut actual = [0_u8; 8];
            let size = unsafe {
                nix::libc::fgetxattr(
                    File::open(&path)?.as_raw_fd(),
                    name.as_ptr(),
                    actual.as_mut_ptr().cast(),
                    actual.len(),
                )
            };
            assert_eq!(size, value.len() as isize);
            assert_eq!(&actual, value);
        }
        Ok(())
    }

    #[test]
    fn recovers_original_after_owner_dies_and_dynamic_updates() -> io::Result<()> {
        let directory = tempfile::tempdir()?;
        let path = directory.path().join("resolv.conf");
        let original = "nameserver 192.0.2.53\nsearch lan.test\noptions timeout:1\n";
        fs::write(&path, original)?;
        fs::set_permissions(&path, fs::Permissions::from_mode(0o640))?;
        let configurator = ResolvConfConfigurator::new(path.clone());
        configurator.original_resolv_conf()?;
        configurator.set_dns(&config())?;
        let lock = directory.path().join(".easytier-dns/lock");
        let lock_inode = fs::metadata(&lock)?.ino();
        let mut updated = config();
        updated.search_domains = vec!["new.test.".to_owned()];
        configurator.set_dns(&updated)?;
        let record: RecoveryRecord = serde_json::from_slice(&fs::read(
            directory.path().join(".easytier-dns/recovery.json"),
        )?)
        .map_err(io::Error::other)?;
        assert_eq!(record.original.content, original);
        // Dropping without close models the OS releasing a dead owner's lock;
        // the production file and durable recovery record remain in place.
        drop(configurator);
        let restarted = ResolvConfConfigurator::new(path.clone());
        restarted.check_support()?;
        assert_eq!(restarted.original_resolv_conf()?, Some(original.to_owned()));
        assert_eq!(fs::read_to_string(&path)?, original);
        assert_eq!(fs::metadata(&path)?.mode() & 0o777, 0o640);
        assert_eq!(fs::metadata(lock)?.ino(), lock_inode);
        assert!(
            !directory
                .path()
                .join(".easytier-dns/recovery.json")
                .exists()
        );
        restarted.close()?;
        Ok(())
    }

    #[test]
    fn clean_original_is_readable_without_recovery_storage() -> io::Result<()> {
        let directory = tempfile::tempdir()?;
        let path = directory.path().join("resolv.conf");
        let original = "nameserver 192.0.2.53\nsearch lan.test\n";
        fs::write(&path, original)?;
        fs::set_permissions(&path, fs::Permissions::from_mode(0o444))?;
        fs::write(directory.path().join(".easytier-dns"), "not a directory")?;
        let configurator = ResolvConfConfigurator::new(path.clone());
        assert_eq!(
            configurator.original_resolv_conf()?,
            Some(original.to_owned())
        );
        assert!(configurator.set_dns(&config()).is_err());
        assert_eq!(fs::read_to_string(path)?, original);
        Ok(())
    }

    #[test]
    fn managed_original_still_requires_recovery_storage() -> io::Result<()> {
        let directory = tempfile::tempdir()?;
        let path = directory.path().join("resolv.conf");
        let managed = format!(
            "{HEADER}{OWNER_PREFIX}{}\nnameserver 100.100.100.101\n",
            uuid::Uuid::new_v4()
        );
        fs::write(&path, &managed)?;
        fs::write(directory.path().join(".easytier-dns"), "not a directory")?;
        let configurator = ResolvConfConfigurator::new(path.clone());
        assert!(configurator.original_resolv_conf().is_err());
        assert_eq!(fs::read_to_string(path)?, managed);
        Ok(())
    }

    #[test]
    fn host_lock_excludes_another_owner_and_keeps_the_same_inode() -> io::Result<()> {
        let directory = tempfile::tempdir()?;
        let path = directory.path().join("resolv.conf");
        fs::write(&path, "nameserver 192.0.2.53\n")?;
        let first = ResolvConfConfigurator::new(path.clone());
        let second = ResolvConfConfigurator::new(path.clone());
        first.original_resolv_conf()?;
        second.original_resolv_conf()?;
        first.set_dns(&config())?;
        let lock = directory.path().join(".easytier-dns/lock");
        let inode = fs::metadata(&lock)?.ino();
        assert!(second.original_resolv_conf().is_err());
        assert!(second.set_dns(&config()).is_err());
        first.close()?;
        second.original_resolv_conf()?;
        second.set_dns(&config())?;
        second.close()?;
        assert_eq!(fs::metadata(lock)?.ino(), inode);
        assert_eq!(fs::read_to_string(path)?, "nameserver 192.0.2.53\n");
        Ok(())
    }

    #[test]
    fn recovers_file_but_refuses_takeover_after_nss_switches_to_resolved() -> io::Result<()> {
        let directory = tempfile::tempdir()?;
        let path = directory.path().join("resolv.conf");
        let original = "nameserver 192.0.2.53\n";
        fs::write(&path, original)?;
        let configurator = ResolvConfConfigurator::new(path.clone());
        configurator.original_resolv_conf()?;
        configurator.set_dns(&config())?;
        drop(configurator);
        fs::write(
            directory.path().join("nsswitch.conf"),
            "hosts: files resolve [!UNAVAIL=return] dns\n",
        )?;
        assert!(ResolvConfConfigurator::needs_recovery(&fs::read_to_string(
            &path
        )?));
        let restarted = ResolvConfConfigurator::new(path.clone());
        assert_eq!(restarted.original_resolv_conf()?, Some(original.to_owned()));
        assert!(restarted.set_dns(&config()).is_err());
        restarted.close()?;
        assert_eq!(fs::read_to_string(path)?, original);
        Ok(())
    }

    #[test]
    fn prepublication_recovery_keeps_original_file_unchanged() -> io::Result<()> {
        let directory = tempfile::tempdir()?;
        let path = directory.path().join("resolv.conf");
        let original = "nameserver 192.0.2.53\n";
        fs::write(&path, original)?;
        let configurator = ResolvConfConfigurator::new(path.clone());
        configurator.original_resolv_conf()?;
        let original_inode = fs::metadata(&path)?.ino();
        {
            let mut state = configurator.state.lock().unwrap();
            assert!(state.recovery.is_none());
            // Model the lock acquired at the start of set_dns before the crash.
            state.recovery = Some(RecoveryStore::open(directory.path())?);
            let recovery = state.recovery.as_ref().unwrap();
            let original = state.original.as_ref().unwrap();
            let temporary = format!("resolver-{}", uuid::Uuid::new_v4());
            let pending = recovery.directory.join(&temporary);
            fs::write(
                &pending,
                ResolvConfConfigurator::desired_content(&original.content, &config())?,
            )?;
            recovery.write(&RecoveryRecord {
                target: path.clone(),
                original: original.clone(),
                previous: original.clone(),
                pending: ResolverFile::read(&pending)?,
                temporary,
            })?;
        }
        drop(configurator);
        let restarted = ResolvConfConfigurator::new(path.clone());
        restarted.original_resolv_conf()?;
        assert_eq!(fs::read_to_string(&path)?, original);
        assert_eq!(
            fs::read_dir(directory.path().join(".easytier-dns"))?.count(),
            3,
        );
        let mut rejected = config();
        rejected.nameservers.push("192.0.2.53".to_owned());
        // The first set reconciles recovery before rejecting this self-loop,
        // so the pending record is cleaned without publishing the pending file.
        assert!(restarted.set_dns(&rejected).is_err());
        assert_eq!(fs::read_to_string(path)?, original);
        assert_eq!(
            fs::metadata(directory.path().join("resolv.conf"))?.ino(),
            original_inode
        );
        assert_eq!(
            fs::read_dir(directory.path().join(".easytier-dns"))?.count(),
            1,
        );
        restarted.close()?;
        Ok(())
    }

    #[test]
    fn missing_corrupt_or_untrusted_recovery_never_overwrites_resolver() -> io::Result<()> {
        for damage in ["missing", "corrupt", "permissions"] {
            let directory = tempfile::tempdir()?;
            let path = directory.path().join("resolv.conf");
            fs::write(&path, "nameserver 192.0.2.53\n")?;
            let configurator = ResolvConfConfigurator::new(path.clone());
            configurator.original_resolv_conf()?;
            configurator.set_dns(&config())?;
            let managed = fs::read_to_string(&path)?;
            drop(configurator);
            let record = directory.path().join(".easytier-dns/recovery.json");
            match damage {
                "missing" => fs::remove_file(&record)?,
                "corrupt" => fs::write(&record, "{broken")?,
                _ => fs::set_permissions(&record, fs::Permissions::from_mode(0o666))?,
            }
            let restarted = ResolvConfConfigurator::new(path.clone());
            assert!(restarted.original_resolv_conf().is_err());
            let _ = restarted.close();
            assert_eq!(fs::read_to_string(path)?, managed);
        }
        Ok(())
    }

    #[test]
    fn refuses_managers_symlinks_and_local_upstream_loops() -> io::Result<()> {
        let directory = tempfile::tempdir()?;
        let path = directory.path().join("resolv.conf");
        for content in [
            "# Generated by NetworkManager\nnameserver 192.0.2.53\n",
            "# Generated by resolvconf\nnameserver 192.0.2.53\n",
            "nameserver 127.0.0.1\n",
            "nameserver ::1\n",
            "nameserver 100.100.100.101\n",
            "options timeout:1\n",
        ] {
            fs::write(&path, content)?;
            let configurator = ResolvConfConfigurator::new(path.clone());
            assert!(configurator.original_resolv_conf().is_err());
            assert!(configurator.set_dns(&config()).is_err());
            configurator.close()?;
            assert_eq!(fs::read_to_string(&path)?, content);
        }
        fs::remove_file(&path)?;
        let target = directory.path().join("managed");
        fs::write(&target, "nameserver 192.0.2.53\n")?;
        std::os::unix::fs::symlink(&target, &path)?;
        let configurator = ResolvConfConfigurator::new(path.clone());
        assert!(configurator.original_resolv_conf().is_err());
        configurator.close()?;
        assert!(fs::symlink_metadata(&path)?.file_type().is_symlink());
        assert_eq!(fs::read_to_string(&target)?, "nameserver 192.0.2.53\n");
        Ok(())
    }
}
