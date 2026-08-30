use tauri::{
    Runtime,
    plugin::{Builder, TauriPlugin},
};

#[cfg(mobile)]
use tauri::AppHandle;

#[cfg(mobile)]
use tauri::Manager;

#[cfg(mobile)]
mod mobile;

#[cfg(mobile)]
use mobile::Vpnservice;

#[cfg(mobile)]
use models::{
    InstanceRequest, PingRequest, PingResponse, SaveHeadlessProfileRequest, StartVpnRequest,
    Status, VoidRequest, VpnStatus,
};

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

#[cfg(mobile)]
#[tauri::command]
async fn ping<R: Runtime>(app: AppHandle<R>, payload: PingRequest) -> Result<PingResponse> {
    app.vpnservice().ping(payload)
}

#[cfg(mobile)]
#[tauri::command]
async fn prepare_vpn<R: Runtime>(app: AppHandle<R>) -> Result<Status> {
    app.vpnservice().prepare_vpn(VoidRequest {})
}

#[cfg(mobile)]
#[tauri::command]
async fn start_vpn<R: Runtime>(app: AppHandle<R>, payload: StartVpnRequest) -> Result<Status> {
    app.vpnservice().start_vpn(payload)
}

#[cfg(mobile)]
#[tauri::command]
async fn stop_vpn<R: Runtime>(app: AppHandle<R>) -> Result<Status> {
    app.vpnservice().stop_vpn(VoidRequest {})
}

#[cfg(target_os = "android")]
pub fn detach_vpn_instance<R: Runtime>(
    app: &AppHandle<R>,
    instance_id: impl Into<String>,
) -> Result<()> {
    app.vpnservice().detach_vpn_instance(InstanceRequest {
        instance_id: instance_id.into(),
    })?;
    Ok(())
}

#[cfg(mobile)]
#[tauri::command]
async fn get_vpn_status<R: Runtime>(app: AppHandle<R>) -> Result<VpnStatus> {
    app.vpnservice().get_vpn_status(VoidRequest {})
}

#[cfg(mobile)]
#[tauri::command]
async fn save_headless_profile<R: Runtime>(
    app: AppHandle<R>,
    payload: SaveHeadlessProfileRequest,
) -> Result<Status> {
    app.vpnservice().save_headless_profile(payload)
}

/// Initializes the plugin.
pub fn init<R: Runtime>() -> TauriPlugin<R> {
    let builder = Builder::new("vpnservice");
    #[cfg(mobile)]
    let builder = builder.invoke_handler(tauri::generate_handler![
        ping,
        prepare_vpn,
        start_vpn,
        stop_vpn,
        get_vpn_status,
        save_headless_profile,
    ]);

    builder
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
