#[cfg(not(feature = "websocket"))]
#[path = "websocket_disabled.rs"]
mod selected;
#[cfg(feature = "websocket")]
#[path = "websocket_enabled.rs"]
mod selected;

use crate::common::global_ctx::ArcGlobalCtx;

use super::{ClientAdapter, ServerAdapter};

pub(super) fn client_adapter(global_ctx: &ArcGlobalCtx) -> Option<ClientAdapter> {
    selected::client_adapter(global_ctx)
}

pub(super) fn server_adapter(global_ctx: &ArcGlobalCtx) -> Option<ServerAdapter> {
    selected::server_adapter(global_ctx)
}
