//! Portable connection orchestration.

use std::fmt::Debug;

use url::Url;

pub mod composite;
pub mod direct;
pub mod hole_punch;
// Kept public: the host-driven adapter chain is WASI-only production code
// (cfg(target_os = "wasi")), so crate-private visibility would surface
// dead-code warnings on host builds for code that is live on WASI.
pub mod connector_host;
pub mod manual;
pub mod protocol;
pub mod stun;
pub mod transport;

/// Supplies the URLs of the instance's currently running listeners.
///
/// The listener layer's running-listener registry implements this seam.
/// Connectors use it to avoid dialing addresses that would hairpin back
/// into one of their own listeners, so connectivity depends on this narrow
/// query rather than on the listener module's concrete registry type.
pub trait LocalListenerUrls: Debug + Send + Sync + 'static {
    fn local_listener_urls(&self) -> Vec<Url>;
}

/// Empty [`LocalListenerUrls`] for connectors that track no listeners.
#[derive(Debug, Default)]
pub struct NoLocalListeners;

impl LocalListenerUrls for NoLocalListeners {
    fn local_listener_urls(&self) -> Vec<Url> {
        Vec::new()
    }
}
