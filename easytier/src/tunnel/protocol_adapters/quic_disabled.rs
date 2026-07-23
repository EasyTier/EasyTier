use crate::common::global_ctx::ArcGlobalCtx;

use super::super::{ClientAdapter, ServerAdapter};

pub(super) fn client_adapter(_global_ctx: &ArcGlobalCtx) -> Option<ClientAdapter> {
    None
}

pub(super) fn server_adapter(_global_ctx: &ArcGlobalCtx) -> Option<ServerAdapter> {
    None
}
