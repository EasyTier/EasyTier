use std::{
    result::Result,
    sync::{atomic::Ordering, Arc, Mutex},
};

use atomic_shim::AtomicU64;

use async_trait::async_trait;
use dashmap::DashMap;
use tokio::select;
use tokio::sync::Notify;
use tokio::task::JoinHandle;

use crate::common::scoped_task::ScopedTask;
use anyhow::Error;

use super::peer_manager::PeerManager;

pub struct ExternalTaskSignal {
    version: AtomicU64,
    notify: Notify,
}

impl Default for ExternalTaskSignal {
    fn default() -> Self {
        Self::new()
    }
}

impl ExternalTaskSignal {
    pub fn new() -> Self {
        Self {
            version: AtomicU64::new(0),
            notify: Notify::new(),
        }
    }

    pub fn notify(&self) {
        self.version.fetch_add(1, Ordering::Relaxed);
        self.notify.notify_waiters();
    }

    pub fn version(&self) -> u64 {
        self.version.load(Ordering::Relaxed)
    }

    pub fn notified(&self) -> impl std::future::Future<Output = ()> + '_ {
        self.notify.notified()
    }
}

#[async_trait]
pub trait PeerTaskLauncher: Send + Sync + Clone + 'static {
    type Data;
    type CollectPeerItem;
    type TaskRet;

    fn new_data(&self, peer_mgr: Arc<PeerManager>) -> Self::Data;
    async fn collect_peers_need_task(&self, data: &Self::Data) -> Vec<Self::CollectPeerItem>;
    async fn launch_task(
        &self,
        data: &Self::Data,
        item: Self::CollectPeerItem,
    ) -> JoinHandle<Result<Self::TaskRet, Error>>;

    async fn all_task_done(&self, _data: &Self::Data) {}

    fn loop_interval_ms(&self) -> u64 {
        5000
    }
}

pub struct PeerTaskManager<Launcher: PeerTaskLauncher> {
    launcher: Launcher,
    main_loop_task: Mutex<Option<ScopedTask<()>>>,
    run_signal: Arc<Notify>,
    external_signal: Option<Arc<ExternalTaskSignal>>,
    data: Launcher::Data,
}

impl<D, C, T, L> PeerTaskManager<L>
where
    D: Send + Sync + Clone + 'static,
    C: std::fmt::Debug + Send + Sync + Clone + core::hash::Hash + Eq + 'static,
    T: Send + 'static,
    L: PeerTaskLauncher<Data = D, CollectPeerItem = C, TaskRet = T> + 'static,
{
    pub fn new(launcher: L, peer_mgr: Arc<PeerManager>) -> Self {
        Self::new_with_external_signal(launcher, peer_mgr, None)
    }

    pub fn new_with_external_signal(
        launcher: L,
        peer_mgr: Arc<PeerManager>,
        external_signal: Option<Arc<ExternalTaskSignal>>,
    ) -> Self {
        let data = launcher.new_data(peer_mgr.clone());
        Self {
            launcher,
            main_loop_task: Mutex::new(None),
            run_signal: Arc::new(Notify::new()),
            external_signal,
            data,
        }
    }

    pub fn start(&self) {
        let task = tokio::spawn(Self::main_loop(
            self.launcher.clone(),
            self.data.clone(),
            self.run_signal.clone(),
            self.external_signal.clone(),
        ))
        .into();
        self.main_loop_task.lock().unwrap().replace(task);
    }

    async fn main_loop(
        launcher: L,
        data: D,
        signal: Arc<Notify>,
        external_signal: Option<Arc<ExternalTaskSignal>>,
    ) {
        let peer_task_map = Arc::new(DashMap::<C, ScopedTask<Result<T, Error>>>::new());
        let mut external_signal_version = external_signal.as_ref().map(|signal| signal.version());

        loop {
            let peers_to_connect = launcher.collect_peers_need_task(&data).await;

            // remove task not in peers_to_connect
            let mut to_remove = vec![];
            for item in peer_task_map.iter() {
                if !peers_to_connect.contains(item.key()) || item.value().is_finished() {
                    to_remove.push(item.key().clone());
                }
            }

            for key in to_remove {
                if let Some((_, task)) = peer_task_map.remove(&key) {
                    task.abort();
                    match task.await {
                        Ok(Ok(_)) => {}
                        Ok(Err(task_ret)) => {
                            tracing::error!(?task_ret, "hole punching task failed");
                        }
                        Err(e) => {
                            tracing::error!(?e, "hole punching task aborted");
                        }
                    }
                }
                peer_task_map.shrink_to_fit();
            }

            if !peers_to_connect.is_empty() {
                for item in peers_to_connect {
                    if peer_task_map.contains_key(&item) {
                        continue;
                    }

                    tracing::debug!(?item, "launch hole punching task");
                    peer_task_map
                        .insert(item.clone(), launcher.launch_task(&data, item).await.into());
                }
            } else if peer_task_map.is_empty() {
                launcher.all_task_done(&data).await;
            }

            if let Some(external_signal) = external_signal.as_ref() {
                let notified = external_signal.notified();
                tokio::pin!(notified);
                let cur_version = external_signal.version();
                if external_signal_version != Some(cur_version) {
                    external_signal_version = Some(cur_version);
                    continue;
                }

                select! {
                    _ = tokio::time::sleep(std::time::Duration::from_millis(
                        launcher.loop_interval_ms(),
                    )) => {},
                    _ = signal.notified() => {},
                    _ = &mut notified => {
                        external_signal_version = Some(external_signal.version());
                    }
                }
            } else {
                select! {
                    _ = tokio::time::sleep(std::time::Duration::from_millis(
                        launcher.loop_interval_ms(),
                    )) => {},
                    _ = signal.notified() => {}
                }
            }
        }
    }

    pub async fn run_immediately(&self) {
        self.run_signal.notify_one();
    }

    pub fn data(&self) -> D {
        self.data.clone()
    }
}
