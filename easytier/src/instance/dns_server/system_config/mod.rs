#[cfg(target_os = "windows")]
pub mod windows;

#[cfg(any(
    all(target_os = "macos", not(feature = "macos-ne")),
    all(test, target_os = "linux")
))]
pub mod darwin;

#[cfg(target_os = "linux")]
pub mod linux;

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

    /// Reapply owned settings if the platform resolver lost them.
    fn refresh(&self) -> std::io::Result<()> {
        Ok(())
    }

    fn set_dns(&self, cfg: &OSConfig) -> std::io::Result<()>;
    fn close(&self) -> std::io::Result<()>;
}
