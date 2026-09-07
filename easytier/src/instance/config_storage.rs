use std::{io::Write as _, path::Path};

use atomic_write_file::{AtomicWriteFile, OpenOptions};

use easytier_core::management::{ConfigFileControl, ConfigFilePermission, ConfigFileStorage};

#[derive(Default)]
pub(crate) struct NativeConfigFileStorage;

#[async_trait::async_trait]
impl ConfigFileStorage for NativeConfigFileStorage {
    async fn inspect(&self, path: &Path) -> ConfigFileControl {
        let read_only = tokio::fs::metadata(path)
            .await
            .map(|metadata| metadata.permissions().readonly())
            .unwrap_or(true);
        ConfigFileControl::new(
            Some(path.to_owned()),
            if read_only {
                ConfigFilePermission::from(ConfigFilePermission::READ_ONLY)
            } else {
                ConfigFilePermission::default()
            },
        )
    }

    async fn read(&self, path: &Path) -> anyhow::Result<Option<Vec<u8>>> {
        match tokio::fs::read(path).await {
            Ok(contents) => Ok(Some(contents)),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(error) => Err(error.into()),
        }
    }

    async fn write(&self, path: &Path, contents: &[u8]) -> anyhow::Result<()> {
        let path = path.to_owned();
        let contents = contents.to_owned();
        tokio::task::spawn_blocking(move || {
            let mut options = OpenOptions::new();
            #[cfg(unix)]
            {
                atomic_write_file::unix::OpenOptionsExt::preserve_mode(&mut options, false);
                std::os::unix::fs::OpenOptionsExt::mode(&mut options, 0o600);
            }
            let mut file: AtomicWriteFile = options.open(path)?;
            file.write_all(&contents)?;
            file.commit()
        })
        .await??;
        Ok(())
    }

    async fn remove(&self, path: &Path) -> anyhow::Result<()> {
        tokio::fs::remove_file(path).await?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn config_write_is_atomic_and_private() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("instance.toml");
        let storage = NativeConfigFileStorage;

        storage.write(&path, b"first").await.unwrap();
        storage.write(&path, b"second").await.unwrap();
        assert_eq!(std::fs::read_to_string(&path).unwrap(), "second");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;

            assert_eq!(
                std::fs::metadata(path).unwrap().permissions().mode() & 0o777,
                0o600
            );
        }
    }
}
