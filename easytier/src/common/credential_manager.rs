use std::{path::PathBuf, sync::Arc};

use easytier_core::peers::credential_manager::CredentialStorage;

struct FileCredentialStorage {
    path: PathBuf,
}

impl CredentialStorage for FileCredentialStorage {
    fn load(&self) -> anyhow::Result<Option<String>> {
        let Ok(serialized) = std::fs::read_to_string(&self.path) else {
            return Ok(None);
        };
        tracing::info!(path = %self.path.display(), "loaded credentials");
        Ok(Some(serialized))
    }

    fn store(&self, serialized_credentials: &str) -> anyhow::Result<()> {
        std::fs::write(&self.path, serialized_credentials)?;
        Ok(())
    }
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
        assert_eq!(
            storage.load().unwrap().as_deref(),
            Some("{\"credential\":true}")
        );
    }
}
