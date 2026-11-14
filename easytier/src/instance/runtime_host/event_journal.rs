#[cfg(feature = "management")]
use std::{
    collections::VecDeque,
    sync::{Arc, RwLock},
};

#[cfg(feature = "management")]
use tokio::{sync::Mutex, task::JoinSet};
use tokio_util::sync::CancellationToken;
#[cfg(feature = "management")]
use tokio_util::task::AbortOnDropHandle;

use crate::common::global_ctx::ArcGlobalCtx;
#[cfg(feature = "management")]
use crate::common::global_ctx::{EventBusSubscriber, GlobalCtxEvent};
#[cfg(feature = "management")]
use crate::common::log;

#[cfg(feature = "management")]
const EVENT_HISTORY_LEN: usize = 20;

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
            events: Arc::new(RwLock::new(VecDeque::with_capacity(EVENT_HISTORY_LEN + 1))),
            receiver: Mutex::new(Some(global_ctx.subscribe())),
            task: Mutex::new(None),
        }
    }

    pub(super) async fn start(&self, cancel: CancellationToken) {
        let Some(mut receiver) = self.receiver.lock().await.take() else {
            return;
        };
        let events = self.events.clone();
        let global_ctx = self.global_ctx.clone();
        let task = tokio::spawn(async move {
            let mut tasks = JoinSet::new();
            let mut handles = VecDeque::with_capacity(EVENT_HISTORY_LEN + 1);

            let handler = |event: GlobalCtxEvent,
                           tasks: &mut JoinSet<_>,
                           handles: &mut VecDeque<_>| {
                let event = ManagementEvent {
                    time: chrono::Local::now(),
                    event,
                };

                let Ok(event) = serde_json::to_string(&event).inspect_err(|error| {
                    log::error!(category: "INSTANCE::HOOK", ?error, "failed to serialize event")
                }) else {
                    return;
                };

                if let Some(hook) = global_ctx.config.get_hook() {
                    let config = global_ctx.config.dump();
                    let event_payload = event.clone();
                    handles.push_front(tasks.spawn(async move {
                        crate::utils::execute(
                            hook,
                            [
                                ("EASYTIER_EVENT", event_payload),
                                ("EASYTIER_CONFIG", config),
                            ],
                        )
                        .await
                    }));
                    if handles.len() > EVENT_HISTORY_LEN
                        && let Some(handle) = handles.pop_back()
                    {
                        handle.abort();
                        log::warn!(category: "INSTANCE::HOOK", "too many events, aborting the oldest hook task");
                    }
                }

                let mut events = events.write().unwrap();
                events.push_front(event);
                if events.len() > EVENT_HISTORY_LEN {
                    events.pop_back();
                }
            };

            loop {
                tokio::select! {
                    _ = cancel.cancelled() => return,
                    event = receiver.recv() => match event {
                        Ok(event) => handler(event, &mut tasks, &mut handles),
                        Err(tokio::sync::broadcast::error::RecvError::Closed) => return,
                        Err(tokio::sync::broadcast::error::RecvError::Lagged(_)) => continue,
                    },
                    Some(result) = tasks.join_next_with_id(), if !tasks.is_empty() => {
                        let output = || -> anyhow::Result<_> {
                            let id = match &result {
                                Ok((id, _)) => *id,
                                Err(e) => e.id(),
                            };
                            if let Some(idx) = handles.iter().rposition(|h| h.id() == id) {
                                handles.remove(idx);
                            }
                            Ok(result.map(|(_, r)| r)??)
                        }();
                        match output {
                            Ok(output) => {
                                let stdout = String::from_utf8_lossy(&output.stdout);
                                let stdout = stdout.trim();
                                let stderr = String::from_utf8_lossy(&output.stderr);
                                let stderr = stderr.trim();
                                let status = output.status;
                                if output.status.success() {
                                    log::debug!(
                                        category: "INSTANCE::HOOK",
                                        ?stdout,
                                        ?stderr,
                                        "event hook executed successfully"
                                    );
                                } else {
                                    log::error!(
                                        category: "INSTANCE::HOOK",
                                        status = status.code(),
                                        ?stdout,
                                        ?stderr,
                                        "event hook exited with non-zero status"
                                    );
                                }
                            }
                            Err(error) => {
                                log::error!(category: "INSTANCE::HOOK", ?error, "failed to run event hook");
                            }
                        }
                    }
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
