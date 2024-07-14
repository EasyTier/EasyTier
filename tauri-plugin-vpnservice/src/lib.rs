use tauri::{
    plugin::{Builder, TauriPlugin},
    Runtime,
};

#[cfg(mobile)]
use tauri::Manager;

#[cfg(mobile)]
mod mobile;

#[cfg(mobile)]
use mobile::Vpnservice;

mod error;
mod models;

pub use error::{Error, Result};

/// Extensions to [`tauri::App`], [`tauri::AppHandle`] and [`tauri::Window`] to access the vpnservice APIs.
#[cfg(mobile)]
pub trait VpnserviceExt<R: Runtime> {
    fn vpnservice(&self) -> &Vpnservice<R>;
}

#[cfg(mobile)]
impl<R: Runtime, T: Manager<R>> crate::VpnserviceExt<R> for T {
    fn vpnservice(&self) -> &Vpnservice<R> {
        self.state::<Vpnservice<R>>().inner()
    }
}

/// Initializes the plugin.
pub fn init<R: Runtime>() -> TauriPlugin<R> {
    Builder::new("vpnservice")
        .setup(|_app, _api| {
            #[cfg(mobile)]
            {
                let vpnservice = mobile::init(_app, _api)?;
                _app.manage(vpnservice);
            }
            Ok(())
        })
        .build()
}
