use std::{
    collections::BTreeMap,
    fs::{self, File, OpenOptions},
    io::{self, Read, Seek, Write},
    os::unix::fs::{OpenOptionsExt, PermissionsExt},
    path::{Path, PathBuf},
    sync::Mutex,
};

use super::{OSConfig, SystemConfig};

const MAC_RESOLVER_FILE_HEADER: &str = "# Added by easytier\n";
const ETC_RESOLVER: &str = "/etc/resolver";

pub struct DarwinConfigurator {
    resolver_dir: PathBuf,
    prepared: Mutex<bool>,
}

impl Default for DarwinConfigurator {
    fn default() -> Self {
        Self::new()
    }
}

impl DarwinConfigurator {
    pub fn new() -> Self {
        Self::with_resolver_dir(PathBuf::from(ETC_RESOLVER))
    }

    fn with_resolver_dir(resolver_dir: PathBuf) -> Self {
        Self {
            resolver_dir,
            prepared: Mutex::new(false),
        }
    }

    fn resolver_name(domain: &str) -> io::Result<&str> {
        let name = domain.trim_end_matches('.');
        if name.is_empty()
            || name.split('.').any(|label| {
                label.is_empty()
                    || !label
                        .bytes()
                        .all(|c| c.is_ascii_alphanumeric() || c == b'-' || c == b'_')
            })
        {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("Invalid resolver domain: {domain:?}"),
            ));
        }
        Ok(name)
    }

    fn desired_files(cfg: &OSConfig) -> io::Result<BTreeMap<String, String>> {
        let mut desired = BTreeMap::new();
        let mut ns_content = String::from(MAC_RESOLVER_FILE_HEADER);
        for ns in &cfg.nameservers {
            let address = ns
                .parse::<std::net::IpAddr>()
                .map_err(|error| io::Error::new(io::ErrorKind::InvalidInput, error))?;
            ns_content.push_str(&format!("nameserver {address}\n"));
        }
        for domain in &cfg.match_domains {
            let name = Self::resolver_name(domain)?;
            desired.insert(name.to_owned(), ns_content.clone());
        }

        // 写 search.easytier 文件。Search expansion is separate from domain routing.
        if !cfg.search_domains.is_empty() {
            let mut content = String::from(MAC_RESOLVER_FILE_HEADER);
            content.push_str("search");
            for domain in &cfg.search_domains {
                content.push(' ');
                content.push_str(Self::resolver_name(domain)?);
            }
            content.push('\n');
            if desired
                .insert("search.easytier".to_owned(), content)
                .is_some()
            {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "The search.easytier resolver filename is reserved for search domains",
                ));
            }
        }
        Ok(desired)
    }

    fn open_marked(path: &Path, write: bool) -> io::Result<Option<File>> {
        let mut file = OpenOptions::new()
            .read(true)
            .write(write)
            .custom_flags(nix::libc::O_NOFOLLOW | nix::libc::O_NONBLOCK)
            .open(path)?;
        if !file.metadata()?.is_file() {
            return Ok(None);
        }
        let mut header = vec![0; MAC_RESOLVER_FILE_HEADER.len()];
        match file.read_exact(&mut header) {
            Ok(()) if header == MAC_RESOLVER_FILE_HEADER.as_bytes() => Ok(Some(file)),
            Ok(()) => Ok(None),
            Err(error) if error.kind() == io::ErrorKind::UnexpectedEof => Ok(None),
            Err(error) => Err(error),
        }
    }

    fn remove_resolver_files(&self, keep: &BTreeMap<String, String>) -> io::Result<()> {
        let entries = match fs::read_dir(&self.resolver_dir) {
            Ok(entries) => entries,
            Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(()),
            Err(error) => return Err(error),
        };
        for entry in entries {
            let entry = entry?;
            if !entry.file_type()?.is_file()
                || entry
                    .file_name()
                    .to_str()
                    .is_some_and(|name| keep.contains_key(name))
            {
                continue;
            }
            match Self::open_marked(&entry.path(), false) {
                // The marker is the ownership policy, including after restart
                // or an external edit that retains it. No old process is needed.
                Ok(Some(_)) => fs::remove_file(entry.path())?,
                Ok(None) => {}
                Err(error) if error.kind() == io::ErrorKind::NotFound => {}
                Err(error) => return Err(error),
            }
        }
        Ok(())
    }

    pub fn do_close(&self) -> io::Result<()> {
        let _guard = self.prepared.lock().unwrap();
        self.remove_resolver_files(&BTreeMap::new())
    }

    pub fn do_set_dns(&self, cfg: &OSConfig) -> io::Result<()> {
        let desired = Self::desired_files(cfg)?;
        self.prepare()?;
        let _guard = self.prepared.lock().unwrap();
        fs::create_dir_all(&self.resolver_dir)?;

        // Keep the existing refusal to replace unrelated files, even though
        // tailscaled's writer can replace an unmarked same-domain file.
        for name in desired.keys() {
            let path = self.resolver_dir.join(name);
            match fs::symlink_metadata(&path) {
                Ok(metadata) if metadata.is_file() => {
                    if Self::open_marked(&path, false)?.is_none() {
                        return Err(io::Error::other(format!(
                            "Resolver file {} is not owned by EasyTier; preserving it",
                            path.display(),
                        )));
                    }
                }
                Ok(_) => {
                    return Err(io::Error::other(format!(
                        "Resolver file {} is not a regular owned file; preserving it",
                        path.display(),
                    )));
                }
                Err(error) if error.kind() == io::ErrorKind::NotFound => {}
                Err(error) => return Err(error),
            }
        }

        // 写 match_domains 文件 and the independent search-domain file.
        for (name, content) in &desired {
            let path = self.resolver_dir.join(name);
            let mut file = match OpenOptions::new()
                .create_new(true)
                .read(true)
                .write(true)
                .mode(0o644)
                .open(&path)
            {
                Ok(file) => file,
                Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {
                    Self::open_marked(&path, true)?.ok_or_else(|| {
                        io::Error::other(format!(
                            "Resolver file {} is no longer owned by EasyTier; preserving it",
                            path.display(),
                        ))
                    })?
                }
                Err(error) => return Err(error),
            };
            file.rewind()?;
            file.set_len(0)?;
            file.set_permissions(fs::Permissions::from_mode(0o644))?;
            file.write_all(content.as_bytes())?;
        }

        // 删除未保留的 resolver 文件, restricted to the application marker.
        self.remove_resolver_files(&desired)
    }
}

impl SystemConfig for DarwinConfigurator {
    fn prepare(&self) -> io::Result<()> {
        let mut prepared = self.prepared.lock().unwrap();
        if !*prepared {
            self.remove_resolver_files(&BTreeMap::new())?;
            *prepared = true;
        }
        Ok(())
    }

    fn set_dns(&self, cfg: &OSConfig) -> io::Result<()> {
        self.do_set_dns(cfg)
    }

    fn close(&self) -> io::Result<()> {
        self.do_close()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::symlink;

    fn config(domains: &[&str]) -> OSConfig {
        OSConfig {
            nameservers: vec!["100.100.100.101".to_owned()],
            search_domains: vec!["et.test.".to_owned()],
            match_domains: domains.iter().map(|domain| (*domain).to_owned()).collect(),
        }
    }

    #[test]
    fn updates_domains_and_cleans_only_owned_files() -> io::Result<()> {
        let dir = tempfile::tempdir()?;
        fs::write(dir.path().join("user.test"), "nameserver 192.0.2.53\n")?;
        let configurator = DarwinConfigurator::with_resolver_dir(dir.path().to_owned());
        configurator.set_dns(&config(&["et.test.", "old.test"]))?;
        assert_eq!(
            fs::read_to_string(dir.path().join("et.test"))?,
            "# Added by easytier\nnameserver 100.100.100.101\n"
        );
        assert_eq!(
            fs::read_to_string(dir.path().join("search.easytier"))?,
            "# Added by easytier\nsearch et.test\n"
        );
        configurator.set_dns(&config(&["et.test.", "new.test"]))?;
        assert!(!dir.path().join("old.test").exists());
        assert!(dir.path().join("new.test").exists());
        configurator.close()?;
        configurator.close()?;
        assert_eq!(fs::read_dir(dir.path())?.count(), 1);
        assert_eq!(
            fs::read_to_string(dir.path().join("user.test"))?,
            "nameserver 192.0.2.53\n"
        );
        Ok(())
    }

    #[test]
    fn refuses_preexisting_files_and_symlinks_before_writing() -> io::Result<()> {
        let dir = tempfile::tempdir()?;
        let preexisting = dir.path().join("existing.test");
        let content = "nameserver 192.0.2.53\n";
        fs::write(&preexisting, content)?;
        let configurator = DarwinConfigurator::with_resolver_dir(dir.path().to_owned());
        assert!(
            configurator
                .set_dns(&config(&["another.test", "existing.test"]))
                .is_err()
        );
        assert!(!dir.path().join("another.test").exists());
        configurator.close()?;
        assert_eq!(fs::read_to_string(&preexisting)?, content);
        symlink(&preexisting, dir.path().join("linked.test"))?;
        assert!(configurator.set_dns(&config(&["linked.test"])).is_err());
        assert_eq!(fs::read_to_string(&preexisting)?, content);
        Ok(())
    }

    #[test]
    fn startup_cleans_marked_files_and_preserves_unmarked_edits() -> io::Result<()> {
        let dir = tempfile::tempdir()?;
        let configurator = DarwinConfigurator::with_resolver_dir(dir.path().to_owned());
        configurator.set_dns(&config(&["edited.test", "replaced.test"]))?;
        let edited = dir.path().join("edited.test");
        let replaced = dir.path().join("replaced.test");
        // Keeping the application marker keeps the file inside its ownership.
        fs::write(&edited, "# Added by easytier\nnameserver 192.0.2.54\n")?;
        let replacement = dir.path().join("replacement");
        fs::write(&replacement, "nameserver 192.0.2.55\n")?;
        fs::rename(&replacement, &replaced)?;
        // No close: model a process that cannot run its normal cleanup.
        drop(configurator);
        let restarted = DarwinConfigurator::with_resolver_dir(dir.path().to_owned());
        assert!(edited.exists());
        assert!(dir.path().join("search.easytier").exists());
        restarted.prepare()?;
        assert!(!edited.exists());
        assert!(!dir.path().join("search.easytier").exists());
        assert_eq!(fs::read_to_string(&replaced)?, "nameserver 192.0.2.55\n");
        restarted.set_dns(&config(&["edited.test"]))?;
        restarted.close()?;
        assert!(!edited.exists());
        assert!(replaced.exists());
        Ok(())
    }

    #[test]
    fn rejects_domain_path_and_content_injection() -> io::Result<()> {
        let dir = tempfile::tempdir()?;
        let configurator = DarwinConfigurator::with_resolver_dir(dir.path().to_owned());
        for domain in ["../outside", "", ".", "test\nnameserver 192.0.2.53"] {
            assert!(configurator.set_dns(&config(&[domain])).is_err());
        }
        assert_eq!(fs::read_dir(dir.path())?.count(), 0);
        Ok(())
    }
}
