use std::sync::Arc;

use easytier_core::connectivity::protocol::{ClientProtocolUpgrader, ServerProtocolUpgrader};

use crate::{common::global_ctx::ArcGlobalCtx, socket::tcp::RuntimeTcpSocket};

mod quic;
mod websocket;
mod wireguard;

pub(super) type ClientAdapter = Arc<dyn ClientProtocolUpgrader<RuntimeTcpSocket>>;
pub(super) type ServerAdapter = Arc<dyn ServerProtocolUpgrader<RuntimeTcpSocket>>;

pub(super) fn client_adapters(global_ctx: &ArcGlobalCtx) -> Vec<ClientAdapter> {
    [
        websocket::client_adapter(global_ctx),
        wireguard::client_adapter(global_ctx),
        quic::client_adapter(global_ctx),
    ]
    .into_iter()
    .flatten()
    .collect()
}

pub(super) fn server_adapters(global_ctx: &ArcGlobalCtx) -> Vec<ServerAdapter> {
    [
        websocket::server_adapter(global_ctx),
        wireguard::server_adapter(global_ctx),
        quic::server_adapter(global_ctx),
    ]
    .into_iter()
    .flatten()
    .collect()
}
