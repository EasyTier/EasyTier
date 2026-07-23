use tokio_util::sync::CancellationToken;

use crate::common::global_ctx::ArcGlobalCtx;

pub(super) struct EventJournal;

impl EventJournal {
    pub(super) fn new(_global_ctx: &ArcGlobalCtx) -> Self {
        Self
    }

    pub(super) async fn start(&self, _cancel: CancellationToken) {}

    pub(super) async fn stop(&self) {}

    pub(super) fn events(&self) -> Vec<String> {
        Vec::new()
    }
}
