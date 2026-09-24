use std::sync::Arc;

use easytier_core::connectivity::protocol::{ClientProtocolUpgrader, ServerProtocolUpgrader};

use crate::{common::global_ctx::ArcGlobalCtx, socket::tcp::RuntimeTcpSocket};

#[cfg(feature = "quic")]
mod quic;
#[cfg(feature = "websocket")]
mod websocket;
#[cfg(feature = "wireguard")]
mod wireguard;

pub(super) type ClientAdapter = Arc<dyn ClientProtocolUpgrader<RuntimeTcpSocket>>;
pub(super) type ServerAdapter = Arc<dyn ServerProtocolUpgrader<RuntimeTcpSocket>>;

pub(super) fn client_adapters(global_ctx: &ArcGlobalCtx) -> Vec<ClientAdapter> {
    let _ = global_ctx;
    [
        #[cfg(feature = "websocket")]
        websocket::client_adapter(global_ctx),
        #[cfg(feature = "wireguard")]
        wireguard::client_adapter(global_ctx),
        #[cfg(feature = "quic")]
        quic::client_adapter(global_ctx),
    ]
    .into_iter()
    .collect()
}

pub(super) fn server_adapters(global_ctx: &ArcGlobalCtx) -> Vec<ServerAdapter> {
    let _ = global_ctx;
    [
        #[cfg(feature = "websocket")]
        websocket::server_adapter(global_ctx),
        #[cfg(feature = "wireguard")]
        wireguard::server_adapter(global_ctx),
        #[cfg(feature = "quic")]
        quic::server_adapter(global_ctx),
    ]
    .into_iter()
    .collect()
}
