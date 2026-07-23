use std::path::Path;

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
        tokio::fs::write(path, contents).await?;
        Ok(())
    }

    async fn remove(&self, path: &Path) -> anyhow::Result<()> {
        tokio::fs::remove_file(path).await?;
        Ok(())
    }
}
