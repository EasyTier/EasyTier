use tauri::{
    plugin::{Builder, TauriPlugin},
    Manager, Runtime,
};

pub use models::*;

#[cfg(desktop)]
mod desktop;
#[cfg(mobile)]
mod mobile;

mod commands;
mod error;
mod models;

pub use error::{Error, Result};

#[cfg(desktop)]
use desktop::Vpnservice;
#[cfg(mobile)]
use mobile::Vpnservice;

/// Extensions to [`tauri::App`], [`tauri::AppHandle`] and [`tauri::Window`] to access the vpnservice APIs.
pub trait VpnserviceExt<R: Runtime> {
    fn vpnservice(&self) -> &Vpnservice<R>;
}

impl<R: Runtime, T: Manager<R>> crate::VpnserviceExt<R> for T {
    fn vpnservice(&self) -> &Vpnservice<R> {
        self.state::<Vpnservice<R>>().inner()
    }
}

/// Initializes the plugin.
pub fn init<R: Runtime>() -> TauriPlugin<R> {
    Builder::new("vpnservice")
        .invoke_handler(tauri::generate_handler![commands::ping])
        .setup(|app, api| {
            #[cfg(mobile)]
            let vpnservice = mobile::init(app, api)?;
            #[cfg(desktop)]
            let vpnservice = desktop::init(app, api)?;
            app.manage(vpnservice);
            Ok(())
        })
        .build()
}
