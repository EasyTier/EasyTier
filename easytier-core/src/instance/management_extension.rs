use super::{CoreInstance, CoreInstanceHost, CoreInstanceHostConfig};
use crate::config::runtime::InstanceConfigStore;

impl<H> CoreInstance<H>
where
    H: CoreInstanceHost,
{
    pub(crate) fn host_config(&self) -> &CoreInstanceHostConfig {
        &self.host_config
    }

    pub fn config_store(&self) -> &InstanceConfigStore {
        &self.runtime_config
    }
}
