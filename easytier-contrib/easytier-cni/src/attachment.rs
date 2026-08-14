use std::{
    env, fs,
    fs::{File, OpenOptions},
    io,
    net::Ipv4Addr,
    path::{Path, PathBuf},
};

use anyhow::{Context, Result, ensure};
use easytier::common::config::{ConfigLoader as _, load_toml_config_from_path};
use sha2::{Digest, Sha256};
use uuid::Uuid;

use crate::cni::PluginConfig;

fn config_dir() -> PathBuf {
    env::var_os("EASYTIER_CNI_TEST_CONFIG_DIR")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("/var/lib/easytier-cni/configs"))
}

pub(crate) fn attachment_id(network: &str, container_id: &str, ifname: &str) -> Uuid {
    let digest = Sha256::digest(format!("{network}\0{container_id}\0{ifname}"));
    let mut bytes = [0u8; 16];
    bytes.copy_from_slice(&digest[..16]);
    bytes[6] = (bytes[6] & 0x0f) | 0x50;
    bytes[8] = (bytes[8] & 0x3f) | 0x80;
    Uuid::from_bytes(bytes)
}

pub(crate) struct AttachmentLock {
    _file: File,
}

impl AttachmentLock {
    pub(crate) fn acquire(id: Uuid) -> Result<Self> {
        #[cfg(unix)]
        {
            use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};

            let config_dir = config_dir();
            let metadata = fs::symlink_metadata(&config_dir).with_context(|| {
                format!(
                    "failed to inspect config directory {}",
                    config_dir.display()
                )
            })?;
            ensure!(metadata.is_dir(), "configDir must be a directory");
            ensure!(metadata.uid() == 0, "configDir must be owned by root");
            ensure!(
                metadata.permissions().mode() & 0o022 == 0,
                "configDir must not be writable by group or other users"
            );

            let lock_dir = config_dir.join(".locks");
            fs::create_dir_all(&lock_dir)?;
            fs::set_permissions(&lock_dir, fs::Permissions::from_mode(0o700))?;
            let file = OpenOptions::new()
                .read(true)
                .write(true)
                .create(true)
                .truncate(false)
                .mode(0o600)
                .open(lock_dir.join(id.to_string()))?;
            file.lock()?;
            Ok(Self { _file: file })
        }
        #[cfg(not(unix))]
        anyhow::bail!("EasyTier CNI is unsupported on this platform")
    }
}

pub(crate) fn ensure_attachment_persisted(
    id: Uuid,
    address: Ipv4Addr,
    prefix: u8,
    netns: &str,
    ifname: &str,
    config: &PluginConfig,
    secret: &str,
) -> Result<()> {
    let path = config_dir().join(format!("{id}.toml"));
    let persisted = load_toml_config_from_path(&path)
        .with_context(|| format!("persisted attachment config {} is invalid", path.display()))?;
    ensure!(persisted.get_id() == id, "persisted attachment ID differs");
    ensure!(
        persisted.get_ipv4().is_some_and(|value| {
            value.address() == address && value.network_length() == prefix
        }),
        "persisted attachment address differs"
    );
    ensure!(
        persisted.get_netns().as_deref() == Some(netns),
        "persisted attachment network namespace differs"
    );
    let identity = persisted.get_network_identity();
    ensure!(
        identity.network_name == config.network_name
            && identity.network_secret.as_deref() == Some(secret),
        "persisted attachment network identity differs"
    );
    let expected_peers = config
        .peers
        .iter()
        .map(|peer| peer.parse::<url::Url>())
        .collect::<std::result::Result<Vec<_>, _>>()?;
    ensure!(
        persisted
            .get_peers()
            .into_iter()
            .map(|peer| peer.uri)
            .eq(expected_peers),
        "persisted attachment peers differ"
    );
    let flags = persisted.get_flags();
    ensure!(
        flags.dev_name == ifname
            && flags.mtu == u32::from(config.mtu)
            && !flags.no_tun
            && !flags.enable_ipv6
            && !flags.multi_thread,
        "persisted attachment interface settings differ"
    );
    Ok(())
}

pub(crate) fn take_persisted_attachment(id: Uuid) -> Result<Option<Vec<u8>>> {
    let path = config_dir().join(format!("{id}.toml"));
    if !path.exists() {
        return Ok(None);
    }
    let persisted = load_toml_config_from_path(&path)
        .with_context(|| format!("orphaned attachment config {} is invalid", path.display()))?;
    ensure!(persisted.get_id() == id, "orphaned attachment ID differs");
    let contents = fs::read(&path)?;
    fs::remove_file(&path)
        .with_context(|| format!("failed to remove attachment config {}", path.display()))?;
    Ok(Some(contents))
}

pub(crate) fn restore_persisted_attachment(id: Uuid, contents: Option<&[u8]>) -> Result<()> {
    let Some(contents) = contents else {
        return Ok(());
    };
    #[cfg(unix)]
    use std::os::unix::fs::OpenOptionsExt;

    let path = config_dir().join(format!("{id}.toml"));
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(&path)
        .with_context(|| format!("failed to restore attachment config {}", path.display()))?;
    io::Write::write_all(&mut file, contents)?;
    file.sync_all()?;
    Ok(())
}

pub(crate) fn read_network_secret(path: &Path) -> Result<String> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::{MetadataExt, PermissionsExt};

        let parent = path.parent().context("networkSecretFile has no parent")?;
        let parent_metadata = fs::symlink_metadata(parent).with_context(|| {
            format!(
                "failed to inspect networkSecretFile directory {}",
                parent.display()
            )
        })?;
        ensure!(
            parent_metadata.is_dir()
                && parent_metadata.uid() == 0
                && parent_metadata.permissions().mode() & 0o022 == 0,
            "networkSecretFile directory must be root-owned and not group/world-writable"
        );
        let metadata = fs::symlink_metadata(path)
            .with_context(|| format!("failed to inspect networkSecretFile {}", path.display()))?;
        ensure!(
            metadata.is_file(),
            "networkSecretFile must be a regular file"
        );
        ensure!(
            metadata.uid() == 0,
            "networkSecretFile must be owned by root"
        );
        ensure!(
            metadata.permissions().mode() & 0o077 == 0,
            "networkSecretFile must not be accessible by group or other users"
        );
        ensure!(metadata.len() <= 4096, "networkSecretFile is too large");
    }

    let secret = fs::read_to_string(path)
        .with_context(|| format!("failed to read networkSecretFile {}", path.display()))?
        .trim()
        .to_string();
    ensure!(!secret.is_empty(), "networkSecretFile is empty");
    Ok(secret)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn attachment_ids_are_stable_and_distinct() {
        let first = attachment_id("overlay", "container-a", "net1");
        assert_eq!(first, attachment_id("overlay", "container-a", "net1"));
        assert_ne!(first, attachment_id("overlay", "container-b", "net1"));
        assert_ne!(first, attachment_id("overlay", "container-a", "net2"));
    }
}
