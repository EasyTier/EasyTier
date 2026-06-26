#[cfg(target_os = "linux")]
pub mod linux;

#[cfg(target_os = "windows")]
pub mod windows;

#[cfg(all(target_os = "macos", not(feature = "macos-ne")))]
pub mod darwin;

#[derive(Default, Debug)]
pub struct OSConfig {
    pub nameservers: Vec<String>,
    pub search_domains: Vec<String>,
    pub match_domains: Vec<String>,
}

pub trait SystemConfig: Send + Sync {
    fn set_dns(&self, cfg: &OSConfig) -> std::io::Result<()>;
    fn close(&self) -> std::io::Result<()>;
}
