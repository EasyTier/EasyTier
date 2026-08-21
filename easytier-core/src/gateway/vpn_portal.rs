//! Protocol-neutral portal runtime and host adapter seam.

mod ipv4_translator;
mod runtime;

pub use runtime::{
    DEFAULT_PORTAL_CLIENT_ADDRESS, MAX_VPN_PORTAL_CLIENTS, PortalClientConfig,
    PortalClientConfigPlan, PortalClientInfoSnapshot, PortalClientState, PortalHost,
    PortalInfoSnapshot, PortalListener, PortalModule, PortalRuntimeConfig, PortalSession,
};
