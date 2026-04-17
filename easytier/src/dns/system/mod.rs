#[allow(unused_imports)]
use crate::utils::BoxExt;

#[cfg(target_os = "linux")]
pub mod linux;

#[cfg(target_os = "windows")]
pub mod windows;

#[cfg(all(target_os = "macos", not(feature = "macos-ne")))]
pub mod macos;

#[derive(Default, Debug)]
pub struct SystemConfig {
    pub nameservers: Vec<String>,
    pub search_domains: Vec<String>,
    pub match_domains: Vec<String>,
}

pub trait SystemConfigurator: Send + Sync {
    fn set_dns(&self, cfg: &SystemConfig) -> std::io::Result<()>;
    fn clean(&self) -> std::io::Result<()>;
}

// TODO: move this to nic mod
pub fn get(
    #[allow(unused_variables)] interface: &str,
) -> Result<Option<Box<dyn SystemConfigurator>>, anyhow::Error> {
    cfg_select! {
        target_os = "windows" => {
            use crate::dns::system::windows::WindowsDNSManager;
            Ok(Some(WindowsDNSManager::new(interface)?.boxed()))
        }

        all(target_os = "macos", not(feature = "macos-ne")) => {
            use crate::dns::system::macos::DarwinConfigurator;
            Ok(Some(DarwinConfigurator::new().boxed()))
        }

        _ => Ok(None)
    }
}
