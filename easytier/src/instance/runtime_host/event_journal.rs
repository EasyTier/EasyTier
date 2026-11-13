#[cfg(feature = "management")]
use std::{
    collections::VecDeque,
    sync::{Arc, RwLock},
};

#[cfg(feature = "management")]
use tokio::sync::Mutex;
use tokio_util::sync::CancellationToken;
#[cfg(feature = "management")]
use tokio_util::task::AbortOnDropHandle;

use crate::common::global_ctx::ArcGlobalCtx;
#[cfg(feature = "management")]
use crate::common::global_ctx::{EventBusSubscriber, GlobalCtxEvent};

#[cfg(feature = "management")]
#[derive(serde::Serialize)]
struct ManagementEvent {
    time: chrono::DateTime<chrono::Local>,
    event: GlobalCtxEvent,
}

#[cfg(feature = "management")]
pub(super) struct EventJournal {
    global_ctx: ArcGlobalCtx,
    events: Arc<RwLock<VecDeque<String>>>,
    receiver: Mutex<Option<EventBusSubscriber>>,
    task: Mutex<Option<AbortOnDropHandle<()>>>,
}

#[cfg(not(feature = "management"))]
pub(super) struct EventJournal;

#[cfg(feature = "management")]
impl EventJournal {
    pub(super) fn new(global_ctx: &ArcGlobalCtx) -> Self {
        Self {
            global_ctx: global_ctx.clone(),
            events: Arc::new(RwLock::new(VecDeque::new())),
            receiver: Mutex::new(Some(global_ctx.subscribe())),
            task: Mutex::new(None),
        }
    }

    pub(super) async fn start(&self, cancel: CancellationToken) {
        let Some(mut receiver) = self.receiver.lock().await.take() else {
            return;
        };
        let events = self.events.clone();
        let task = tokio::spawn(async move {
            loop {
                let event = tokio::select! {
                    _ = cancel.cancelled() => return,
                    event = receiver.recv() => match event {
                        Ok(event) => event,
                        Err(tokio::sync::broadcast::error::RecvError::Closed) => return,
                        Err(tokio::sync::broadcast::error::RecvError::Lagged(_)) => continue,
                    },
                };
                let event = ManagementEvent {
                    time: chrono::Local::now(),
                    event,
                };
                let Ok(event) = serde_json::to_string(&event) else {
                    continue;
                };
                let mut events = events.write().unwrap();
                events.push_front(event);
                if events.len() > 20 {
                    events.pop_back();
                }
            }
        });
        self.task.lock().await.replace(AbortOnDropHandle::new(task));
    }

    pub(super) async fn stop(&self) {
        if let Some(task) = self.task.lock().await.take() {
            let _ = task.await;
        }
    }

    pub(super) fn events(&self) -> Vec<String> {
        self.events.read().unwrap().iter().cloned().collect()
    }

    pub(super) fn publish_config_patch(
        &self,
        patch: crate::proto::api::config::InstanceConfigPatch,
    ) {
        self.global_ctx
            .issue_event(GlobalCtxEvent::ConfigPatched(patch));
    }
}

#[cfg(not(feature = "management"))]
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
