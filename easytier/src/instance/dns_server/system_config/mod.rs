#[cfg(target_os = "windows")]
pub mod windows;

#[cfg(any(
    all(target_os = "macos", not(feature = "macos-ne")),
    all(test, target_os = "linux")
))]
pub mod darwin;

#[cfg(target_os = "linux")]
pub mod linux;

#[cfg(target_os = "linux")]
pub mod resolv_conf;

#[derive(Default, Debug)]
pub struct OSConfig {
    pub nameservers: Vec<String>,
    pub search_domains: Vec<String>,
    pub match_domains: Vec<String>,
}

pub trait SystemConfig: Send + Sync {
    /// Clean up this application's previous settings after DNS server election.
    fn prepare(&self) -> std::io::Result<()> {
        Ok(())
    }

    /// Recover a persistent file takeover before loading its original upstreams.
    fn needs_resolv_conf_recovery(&self) -> bool {
        false
    }

    /// The original resolver file, when the OS cannot route DNS by domain.
    /// Read this before redirecting system queries to the existing DNS server.
    fn original_resolv_conf(&self) -> std::io::Result<Option<String>> {
        Ok(None)
    }

    fn set_dns(&self, cfg: &OSConfig) -> std::io::Result<()>;
    fn close(&self) -> std::io::Result<()>;
}
