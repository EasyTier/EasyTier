use std::{
    env,
    ffi::OsString,
    io::Write as _,
    path::{Path, PathBuf},
    time::{Duration, Instant},
};

use anyhow::Context as _;
#[cfg(unix)]
use nix::{
    errno::Errno,
    fcntl::{Flock, FlockArg},
};

#[derive(Debug, Clone, Default)]
pub struct MachineIdOptions {
    pub explicit_machine_id: Option<String>,
    pub state_dir: Option<PathBuf>,
}

pub fn resolve_machine_id(opts: &MachineIdOptions) -> anyhow::Result<uuid::Uuid> {
    if let Some(explicit_machine_id) = opts.explicit_machine_id.as_deref() {
        return Ok(parse_or_hash_machine_id(explicit_machine_id));
    }

    let state_file = resolve_machine_id_state_file(opts.state_dir.as_deref())?;
    let allow_legacy_machine_uid_migration =
        should_attempt_legacy_machine_uid_migration(&state_file);
    if let Some(machine_id) = read_state_machine_id(&state_file)? {
        return Ok(machine_id);
    }

    if let Some(machine_id) = read_legacy_machine_id_file() {
        return persist_machine_id(&state_file, machine_id);
    }

    if allow_legacy_machine_uid_migration
        && let Some(machine_id) = resolve_legacy_machine_uid_hash()
    {
        return persist_machine_id(&state_file, machine_id);
    }

    let machine_id = resolve_new_machine_id().unwrap_or_else(uuid::Uuid::new_v4);
    persist_machine_id(&state_file, machine_id)
}

fn parse_or_hash_machine_id(raw: &str) -> uuid::Uuid {
    if let Ok(mid) = uuid::Uuid::parse_str(raw.trim()) {
        return mid;
    }
    digest_uuid_from_str(raw)
}

fn digest_uuid_from_str(raw: &str) -> uuid::Uuid {
    let mut b = [0u8; 16];
    crate::tunnel::generate_digest_from_str("", raw, &mut b);
    uuid::Uuid::from_bytes(b)
}

fn resolve_machine_id_state_file(state_dir: Option<&Path>) -> anyhow::Result<PathBuf> {
    let state_dir = match state_dir {
        Some(dir) => dir.to_path_buf(),
        None => default_machine_id_state_dir()?,
    };
    Ok(state_dir.join("machine_id"))
}

fn non_empty_os_string(value: Option<OsString>) -> Option<OsString> {
    value.filter(|value| !value.is_empty())
}

#[cfg(target_os = "linux")]
fn default_linux_machine_id_state_dir(
    xdg_data_home: Option<OsString>,
    home: Option<OsString>,
) -> PathBuf {
    if let Some(path) = non_empty_os_string(xdg_data_home) {
        return PathBuf::from(path).join("easytier");
    }

    if let Some(home) = non_empty_os_string(home) {
        return PathBuf::from(home)
            .join(".local")
            .join("share")
            .join("easytier");
    }

    PathBuf::from("/var/lib/easytier")
}

fn default_machine_id_state_dir() -> anyhow::Result<PathBuf> {
    cfg_select! {
        target_os = "linux" => Ok(default_linux_machine_id_state_dir(
            env::var_os("XDG_DATA_HOME"),
            env::var_os("HOME"),
        )),
        all(target_os = "macos", not(feature = "macos-ne")) => {
            let home = non_empty_os_string(env::var_os("HOME"))
                .ok_or_else(|| anyhow::anyhow!("HOME is not set, cannot resolve machine id state directory"))?;
            Ok(PathBuf::from(home)
                .join("Library")
                .join("Application Support")
                .join("com.easytier"))
        },
        target_os = "windows" => {
            let local_app_data = non_empty_os_string(env::var_os("LOCALAPPDATA")).ok_or_else(|| {
                anyhow::anyhow!("LOCALAPPDATA is not set, cannot resolve machine id state directory")
            })?;
            Ok(PathBuf::from(local_app_data).join("easytier"))
        },
        target_os = "freebsd" => {
            let home = non_empty_os_string(env::var_os("HOME"))
                .ok_or_else(|| anyhow::anyhow!("HOME is not set, cannot resolve machine id state directory"))?;
            Ok(PathBuf::from(home).join(".local").join("share").join("easytier"))
        },
        target_os = "android" => {
            anyhow::bail!("machine id state directory must be provided explicitly on Android");
        },
        _ => anyhow::bail!("machine id state directory is unsupported on this platform"),
    }
}

fn read_state_machine_id(path: &Path) -> anyhow::Result<Option<uuid::Uuid>> {
    let Some(contents) = read_optional_file(path)? else {
        return Ok(None);
    };

    let machine_id = uuid::Uuid::parse_str(contents.trim())
        .with_context(|| format!("invalid machine id in state file {}", path.display()))?;
    Ok(Some(machine_id))
}

fn read_legacy_machine_id_file() -> Option<uuid::Uuid> {
    let path = legacy_machine_id_file_path()?;
    read_legacy_machine_id_file_at(&path)
}

fn read_legacy_machine_id_file_at(path: &Path) -> Option<uuid::Uuid> {
    let contents = match std::fs::read_to_string(path) {
        Ok(contents) => contents,
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => return None,
        Err(err) => {
            tracing::warn!(
                path = %path.display(),
                %err,
                "ignoring unreadable legacy machine id file"
            );
            return None;
        }
    };

    match uuid::Uuid::parse_str(contents.trim()) {
        Ok(machine_id) => Some(machine_id),
        Err(err) => {
            tracing::warn!(
                path = %path.display(),
                %err,
                "ignoring invalid legacy machine id file"
            );
            None
        }
    }
}

fn legacy_machine_id_file_path() -> Option<PathBuf> {
    std::env::current_exe()
        .ok()
        .map(|path| path.with_file_name("et_machine_id"))
}

fn read_optional_file(path: &Path) -> anyhow::Result<Option<String>> {
    match std::fs::read_to_string(path) {
        Ok(contents) => Ok(Some(contents)),
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(err) => Err(err).with_context(|| format!("failed to read {}", path.display())),
    }
}

fn should_attempt_legacy_machine_uid_migration(state_file: &Path) -> bool {
    let Some(state_dir) = state_file.parent() else {
        return false;
    };

    let Ok(mut entries) = std::fs::read_dir(state_dir) else {
        return false;
    };
    entries.any(|entry| entry.is_ok())
}

fn resolve_legacy_machine_uid_hash() -> Option<uuid::Uuid> {
    machine_uid_seed().map(|seed| digest_uuid_from_str(seed.as_str()))
}

fn resolve_new_machine_id() -> Option<uuid::Uuid> {
    let seed = machine_uid_seed()?;

    #[cfg(target_os = "linux")]
    {
        let seed = linux_machine_id_seed(&seed);
        Some(digest_uuid_from_str(&seed))
    }

    #[cfg(not(target_os = "linux"))]
    {
        Some(digest_uuid_from_str(&seed))
    }
}

#[cfg(any(
    target_os = "linux",
    all(target_os = "macos", not(feature = "macos-ne")),
    target_os = "windows",
    target_os = "freebsd"
))]
fn machine_uid_seed() -> Option<String> {
    machine_uid::get()
        .ok()
        .filter(|value| !value.trim().is_empty())
}

#[cfg(not(any(
    target_os = "linux",
    all(target_os = "macos", not(feature = "macos-ne")),
    target_os = "windows",
    target_os = "freebsd"
)))]
fn machine_uid_seed() -> Option<String> {
    None
}

#[cfg(target_os = "linux")]
fn linux_machine_id_seed(machine_uid: &str) -> String {
    let mut seed = format!("machine_uid={machine_uid}");

    let hostname = gethostname::gethostname()
        .to_string_lossy()
        .trim()
        .to_string();
    if !hostname.is_empty() {
        seed.push_str("\nhostname=");
        seed.push_str(&hostname);
    }

    let mac_addresses = collect_linux_mac_addresses();
    if !mac_addresses.is_empty() {
        seed.push_str("\nmacs=");
        seed.push_str(&mac_addresses.join(","));
    }

    seed
}

#[cfg(target_os = "linux")]
fn collect_linux_mac_addresses() -> Vec<String> {
    let mut macs = Vec::new();
    let Ok(entries) = std::fs::read_dir("/sys/class/net") else {
        return macs;
    };

    for entry in entries.flatten() {
        let Ok(name) = entry.file_name().into_string() else {
            continue;
        };
        if name == "lo" {
            continue;
        }

        let address_path = entry.path().join("address");
        let Ok(address) = std::fs::read_to_string(address_path) else {
            continue;
        };
        let address = address.trim().to_ascii_lowercase();
        if address.is_empty() || address == "00:00:00:00:00:00" {
            continue;
        }
        macs.push(address);
    }

    macs.sort();
    macs.dedup();
    macs.truncate(3);
    macs
}

fn persist_machine_id(path: &Path, machine_id: uuid::Uuid) -> anyhow::Result<uuid::Uuid> {
    if let Some(existing) = read_state_machine_id(path)? {
        return Ok(existing);
    }

    let _lock = MachineIdWriteLock::acquire(path)?;

    if let Some(existing) = read_state_machine_id(path)? {
        return Ok(existing);
    }

    write_uuid_file_atomically(path, machine_id)?;
    Ok(machine_id)
}

fn write_uuid_file_atomically(path: &Path, machine_id: uuid::Uuid) -> anyhow::Result<()> {
    let parent = path.parent().ok_or_else(|| {
        anyhow::anyhow!(
            "machine id state file {} has no parent directory",
            path.display()
        )
    })?;
    std::fs::create_dir_all(parent).with_context(|| {
        format!(
            "failed to create machine id state directory {}",
            parent.display()
        )
    })?;

    let tmp_path = parent.join(format!(
        ".machine_id.tmp-{}-{}",
        std::process::id(),
        uuid::Uuid::new_v4()
    ));
    {
        let mut file = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&tmp_path)
            .with_context(|| format!("failed to create {}", tmp_path.display()))?;
        file.write_all(machine_id.to_string().as_bytes())
            .with_context(|| format!("failed to write {}", tmp_path.display()))?;
        file.sync_all()
            .with_context(|| format!("failed to flush {}", tmp_path.display()))?;
    }

    if let Err(err) = std::fs::rename(&tmp_path, path) {
        let _ = std::fs::remove_file(&tmp_path);
        return Err(err).with_context(|| {
            format!(
                "failed to move machine id state file into place at {}",
                path.display()
            )
        });
    }

    Ok(())
}

struct MachineIdWriteLock {
    #[cfg(unix)]
    _lock: Flock<std::fs::File>,
    #[cfg(not(unix))]
    path: PathBuf,
}

impl MachineIdWriteLock {
    fn acquire(path: &Path) -> anyhow::Result<Self> {
        let parent = path.parent().ok_or_else(|| {
            anyhow::anyhow!(
                "machine id state file {} has no parent directory",
                path.display()
            )
        })?;
        std::fs::create_dir_all(parent).with_context(|| {
            format!(
                "failed to create machine id state directory {}",
                parent.display()
            )
        })?;

        #[cfg(unix)]
        {
            Self::acquire_unix(path)
        }

        #[cfg(not(unix))]
        {
            Self::acquire_fallback(path)
        }
    }

    #[cfg(unix)]
    fn acquire_unix(path: &Path) -> anyhow::Result<Self> {
        let lock_path = path.with_extension("lock");
        let deadline = Instant::now() + Duration::from_secs(5);
        let mut lock_file = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .open(&lock_path)
            .with_context(|| format!("failed to open machine id lock {}", lock_path.display()))?;

        loop {
            match Flock::lock(lock_file, FlockArg::LockExclusiveNonblock) {
                Ok(lock) => return Ok(Self { _lock: lock }),
                Err((file, Errno::EAGAIN)) => {
                    if Instant::now() >= deadline {
                        anyhow::bail!(
                            "timed out waiting for machine id lock {}",
                            lock_path.display()
                        );
                    }
                    lock_file = file;
                    std::thread::sleep(Duration::from_millis(50));
                }
                Err((_file, err)) => {
                    anyhow::bail!(
                        "failed to acquire machine id lock {}: {}",
                        lock_path.display(),
                        err
                    );
                }
            }
        }
    }

    #[cfg(not(unix))]
    fn acquire_fallback(path: &Path) -> anyhow::Result<Self> {
        let lock_path = path.with_extension("lock");
        let deadline = Instant::now() + Duration::from_secs(5);

        loop {
            match std::fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(&lock_path)
            {
                Ok(mut file) => {
                    writeln!(file, "pid={}", std::process::id()).ok();
                    return Ok(Self { path: lock_path });
                }
                Err(err) if err.kind() == std::io::ErrorKind::AlreadyExists => {
                    if should_reap_stale_lock_file(&lock_path) {
                        let _ = std::fs::remove_file(&lock_path);
                        continue;
                    }
                    if Instant::now() >= deadline {
                        anyhow::bail!(
                            "timed out waiting for machine id lock {}",
                            lock_path.display()
                        );
                    }
                    std::thread::sleep(Duration::from_millis(50));
                }
                Err(err) => {
                    return Err(err).with_context(|| {
                        format!("failed to acquire machine id lock {}", lock_path.display())
                    });
                }
            }
        }
    }
}

#[cfg(not(unix))]
fn should_reap_stale_lock_file(lock_path: &Path) -> bool {
    const STALE_LOCK_AGE: Duration = Duration::from_secs(30);

    let Ok(metadata) = std::fs::metadata(lock_path) else {
        return false;
    };
    let Ok(modified) = metadata.modified() else {
        return false;
    };
    modified
        .elapsed()
        .is_ok_and(|elapsed| elapsed >= STALE_LOCK_AGE)
}

impl Drop for MachineIdWriteLock {
    fn drop(&mut self) {
        #[cfg(not(unix))]
        let _ = std::fs::remove_file(&self.path);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_resolve_machine_id_uses_uuid_seed_verbatim() {
        let raw = "33333333-3333-3333-3333-333333333333".to_string();
        let opts = MachineIdOptions {
            explicit_machine_id: Some(raw.clone()),
            state_dir: None,
        };
        assert_eq!(
            resolve_machine_id(&opts).unwrap(),
            uuid::Uuid::parse_str(&raw).unwrap()
        );
    }

    #[test]
    fn test_resolve_machine_id_reads_state_file() {
        let temp_dir = tempfile::tempdir().unwrap();
        let expected = uuid::Uuid::new_v4();
        std::fs::write(temp_dir.path().join("machine_id"), expected.to_string()).unwrap();

        let opts = MachineIdOptions {
            explicit_machine_id: None,
            state_dir: Some(temp_dir.path().to_path_buf()),
        };

        assert_eq!(resolve_machine_id(&opts).unwrap(), expected);
    }

    #[test]
    fn test_read_legacy_machine_id_file_ignores_read_errors() {
        let temp_dir = tempfile::tempdir().unwrap();

        assert_eq!(read_legacy_machine_id_file_at(temp_dir.path()), None);
    }

    #[test]
    fn test_write_uuid_file_atomically_writes_expected_contents() {
        let temp_dir = tempfile::tempdir().unwrap();
        let machine_id = uuid::Uuid::new_v4();
        let state_file = temp_dir.path().join("machine_id");

        write_uuid_file_atomically(&state_file, machine_id).unwrap();

        assert_eq!(
            std::fs::read_to_string(state_file).unwrap(),
            machine_id.to_string()
        );
    }

    #[test]
    fn test_non_empty_os_string_filters_empty_values() {
        assert_eq!(non_empty_os_string(Some(OsString::new())), None);
        assert_eq!(
            non_empty_os_string(Some(OsString::from("foo"))),
            Some(OsString::from("foo"))
        );
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn test_default_linux_machine_id_state_dir_falls_back_in_order() {
        assert_eq!(
            default_linux_machine_id_state_dir(
                Some(OsString::from("/tmp/xdg")),
                Some(OsString::from("/tmp/home"))
            ),
            PathBuf::from("/tmp/xdg").join("easytier")
        );
        assert_eq!(
            default_linux_machine_id_state_dir(
                Some(OsString::new()),
                Some(OsString::from("/tmp/home"))
            ),
            PathBuf::from("/tmp/home")
                .join(".local")
                .join("share")
                .join("easytier")
        );
        assert_eq!(
            default_linux_machine_id_state_dir(Some(OsString::new()), Some(OsString::new())),
            PathBuf::from("/var/lib/easytier")
        );
    }

    #[test]
    fn test_persist_machine_id_creates_missing_state_dir() {
        let temp_dir = tempfile::tempdir().unwrap();
        let state_file = temp_dir.path().join("nested").join("machine_id");
        let machine_id = uuid::Uuid::new_v4();

        assert_eq!(
            persist_machine_id(&state_file, machine_id).unwrap(),
            machine_id
        );
        assert_eq!(
            std::fs::read_to_string(state_file).unwrap(),
            machine_id.to_string()
        );
    }

    #[test]
    fn test_legacy_machine_uid_migration_requires_existing_state_dir_content() {
        let temp_dir = tempfile::tempdir().unwrap();
        let missing_state_file = temp_dir.path().join("missing").join("machine_id");
        assert!(!should_attempt_legacy_machine_uid_migration(
            &missing_state_file
        ));

        let empty_dir = temp_dir.path().join("empty");
        std::fs::create_dir_all(&empty_dir).unwrap();
        assert!(!should_attempt_legacy_machine_uid_migration(
            &empty_dir.join("machine_id")
        ));

        std::fs::write(empty_dir.join("config.toml"), "x=1").unwrap();
        assert!(should_attempt_legacy_machine_uid_migration(
            &empty_dir.join("machine_id")
        ));
    }
}
