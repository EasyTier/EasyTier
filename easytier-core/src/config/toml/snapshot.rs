use super::{Arc, Mutex, TomlConfig};

impl TomlConfig {
    /// Copies the underlying configuration into an independent mutable model.
    pub fn detached_snapshot(&self) -> Self {
        let config = self.config.lock().unwrap().clone();
        Self {
            config: Arc::new(Mutex::new(config)),
        }
    }

    pub(crate) fn replace_from_snapshot(&self, snapshot: &Self) {
        let config = snapshot.config.lock().unwrap().clone();
        *self.config.lock().unwrap() = config;
    }
}
