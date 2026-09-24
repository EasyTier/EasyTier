//! Protocol-neutral portal runtime and host adapter seam.

mod runtime;

pub use runtime::{
    MAX_VPN_PORTAL_CLIENTS, PortalClientConfig, PortalClientConfigPlan, PortalClientInfoSnapshot,
    PortalClientState, PortalHost, PortalInfoSnapshot, PortalListener, PortalModule,
    PortalRuntimeConfig, PortalSession,
};
