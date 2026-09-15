use std::{io::Write, path::PathBuf, sync::Arc};

use atomic_write_file::{AtomicWriteFile, OpenOptions};
use easytier_core::peers::credential_manager::CredentialStorage;

struct FileCredentialStorage {
    path: PathBuf,
}

impl CredentialStorage for FileCredentialStorage {
    fn load(&self) -> anyhow::Result<Option<String>> {
        let serialized = match std::fs::read_to_string(&self.path) {
            Ok(serialized) => serialized,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(error) => return Err(error.into()),
        };
        tracing::info!(path = %self.path.display(), "loaded credentials");
        Ok(Some(serialized))
    }

    fn store(&self, serialized_credentials: &str) -> anyhow::Result<()> {
        let mut file = restricted_atomic_file(&self.path)?;
        file.write_all(serialized_credentials.as_bytes())?;
        file.commit()?;
        Ok(())
    }
}

fn restricted_atomic_file(path: &std::path::Path) -> std::io::Result<AtomicWriteFile> {
    let mut options = OpenOptions::new();
    #[cfg(unix)]
    {
        atomic_write_file::unix::OpenOptionsExt::preserve_mode(&mut options, false);
        std::os::unix::fs::OpenOptionsExt::mode(&mut options, 0o600);
    }
    options.open(path)
}

pub(crate) fn runtime_credential_storage(
    path: Option<PathBuf>,
) -> Option<Arc<dyn CredentialStorage>> {
    path.map(|path| Arc::new(FileCredentialStorage { path }) as Arc<dyn CredentialStorage>)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn file_storage_round_trips_serialized_credentials() {
        let directory = tempfile::tempdir().unwrap();
        let storage = FileCredentialStorage {
            path: directory.path().join("credentials.json"),
        };

        assert_eq!(storage.load().unwrap(), None);
        storage.store("{\"credential\":true}").unwrap();
        storage.store("{\"credential\":false}").unwrap();
        assert_eq!(
            storage.load().unwrap().as_deref(),
            Some("{\"credential\":false}")
        );
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;

            assert_eq!(
                std::fs::metadata(&storage.path)
                    .unwrap()
                    .permissions()
                    .mode()
                    & 0o777,
                0o600
            );
        }
    }

    #[test]
    fn file_storage_reports_read_errors() {
        let directory = tempfile::tempdir().unwrap();
        let storage = FileCredentialStorage {
            path: directory.path().to_path_buf(),
        };

        assert!(storage.load().is_err());
    }
}
