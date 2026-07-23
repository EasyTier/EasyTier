use std::{
    result::Result,
    sync::{Arc, Mutex, atomic::Ordering},
    time::Duration,
};

use anyhow::Error;
use async_trait::async_trait;
use atomic_shim::AtomicU64;
use dashmap::DashMap;
use tokio::{
    select,
    sync::Notify,
    task::{JoinHandle, JoinSet},
};
use tokio_util::task::AbortOnDropHandle;

pub(crate) async fn reap_joinset_background<T>(tasks: Arc<Mutex<JoinSet<T>>>, origin: &'static str)
where
    T: Send + 'static,
{
    let tasks = Arc::downgrade(&tasks);
    loop {
        crate::foundation::time::sleep(Duration::from_secs(1)).await;
        let Some(tasks) = tasks.upgrade() else {
            break;
        };
        while tasks.lock().unwrap().try_join_next().is_some() {}
    }
    tracing::debug!(origin, "joinset task reaper exited");
}

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
    type PeerManager: Send + Sync + 'static;
    type Data;
    type CollectPeerItem;
    type TaskRet;

    fn new_data(&self, peer_mgr: Arc<Self::PeerManager>) -> Self::Data;
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

type PeerTaskMap<Launcher> = DashMap<
    <Launcher as PeerTaskLauncher>::CollectPeerItem,
    AbortOnDropHandle<Result<<Launcher as PeerTaskLauncher>::TaskRet, Error>>,
>;

pub struct PeerTaskManager<Launcher: PeerTaskLauncher> {
    launcher: Launcher,
    main_loop_task: Mutex<Option<AbortOnDropHandle<()>>>,
    peer_tasks: Arc<PeerTaskMap<Launcher>>,
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
    pub fn new_with_external_signal(
        launcher: L,
        peer_mgr: Arc<L::PeerManager>,
        external_signal: Option<Arc<ExternalTaskSignal>>,
    ) -> Self {
        let data = launcher.new_data(peer_mgr.clone());
        Self {
            launcher,
            main_loop_task: Mutex::new(None),
            peer_tasks: Arc::new(DashMap::new()),
            run_signal: Arc::new(Notify::new()),
            external_signal,
            data,
        }
    }

    pub fn start(&self) {
        let mut task_slot = self.main_loop_task.lock().unwrap();
        if task_slot.as_ref().is_some_and(|task| !task.is_finished()) {
            return;
        }
        let task = AbortOnDropHandle::new(tokio::spawn(Self::main_loop(
            self.launcher.clone(),
            self.data.clone(),
            self.run_signal.clone(),
            self.external_signal.clone(),
            self.peer_tasks.clone(),
        )));
        task_slot.replace(task);
    }

    pub async fn stop(&self) {
        let task = self.main_loop_task.lock().unwrap().take();
        if let Some(task) = task {
            task.abort();
            let _ = task.await;
        }
        let keys = self
            .peer_tasks
            .iter()
            .map(|entry| entry.key().clone())
            .collect::<Vec<_>>();
        for key in keys {
            if let Some((_, task)) = self.peer_tasks.remove(&key) {
                task.abort();
                let _ = task.await;
            }
        }
        self.peer_tasks.shrink_to_fit();
    }

    async fn main_loop(
        launcher: L,
        data: D,
        signal: Arc<Notify>,
        external_signal: Option<Arc<ExternalTaskSignal>>,
        peer_task_map: Arc<DashMap<C, AbortOnDropHandle<Result<T, Error>>>>,
    ) {
        let mut external_signal_version = external_signal.as_ref().map(|signal| signal.version());

        loop {
            let peers_to_connect = launcher.collect_peers_need_task(&data).await;

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
                            tracing::error!(
                                target: "easytier_core::peers::peer_task",
                                ?task_ret,
                                "hole punching task failed"
                            );
                        }
                        Err(e) => {
                            tracing::error!(
                                target: "easytier_core::peers::peer_task",
                                ?e,
                                "hole punching task aborted"
                            );
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

                    tracing::debug!(
                        target: "easytier_core::peers::peer_task",
                        ?item,
                        "launch hole punching task"
                    );
                    peer_task_map.insert(
                        item.clone(),
                        AbortOnDropHandle::new(launcher.launch_task(&data, item).await),
                    );
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
                    _ = crate::foundation::time::sleep(std::time::Duration::from_millis(
                        launcher.loop_interval_ms(),
                    )) => {},
                    _ = signal.notified() => {},
                    _ = &mut notified => {
                        external_signal_version = Some(external_signal.version());
                    }
                }
            } else {
                select! {
                    _ = crate::foundation::time::sleep(std::time::Duration::from_millis(
                        launcher.loop_interval_ms(),
                    )) => {},
                    _ = signal.notified() => {}
                }
            }
        }
    }

    pub fn data(&self) -> D {
        self.data.clone()
    }
}

#[cfg(test)]
mod tests {
    use std::sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    };

    use super::*;

    #[derive(Clone)]
    struct TestLauncher {
        active_tasks: Arc<AtomicUsize>,
    }

    struct ActiveTaskGuard(Arc<AtomicUsize>);

    impl Drop for ActiveTaskGuard {
        fn drop(&mut self) {
            self.0.fetch_sub(1, Ordering::SeqCst);
        }
    }

    #[async_trait]
    impl PeerTaskLauncher for TestLauncher {
        type PeerManager = ();
        type Data = ();
        type CollectPeerItem = u8;
        type TaskRet = ();

        fn new_data(&self, _peer_manager: Arc<()>) {}

        async fn collect_peers_need_task(&self, _data: &()) -> Vec<u8> {
            vec![1]
        }

        async fn launch_task(&self, _data: &(), _item: u8) -> JoinHandle<Result<(), Error>> {
            let active_tasks = self.active_tasks.clone();
            tokio::spawn(async move {
                active_tasks.fetch_add(1, Ordering::SeqCst);
                let _guard = ActiveTaskGuard(active_tasks);
                std::future::pending::<()>().await;
                Ok(())
            })
        }
    }

    #[tokio::test]
    async fn peer_task_manager_is_cold_and_joins_children_on_stop() {
        let active_tasks = Arc::new(AtomicUsize::new(0));
        let manager = PeerTaskManager::new_with_external_signal(
            TestLauncher {
                active_tasks: active_tasks.clone(),
            },
            Arc::new(()),
            None,
        );

        tokio::task::yield_now().await;
        assert_eq!(active_tasks.load(Ordering::SeqCst), 0);

        manager.start();
        crate::foundation::time::timeout(std::time::Duration::from_secs(1), async {
            while active_tasks.load(Ordering::SeqCst) == 0 {
                tokio::task::yield_now().await;
            }
        })
        .await
        .unwrap();

        manager.stop().await;
        assert_eq!(active_tasks.load(Ordering::SeqCst), 0);
    }
}
