use std::result::Result;
use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use dashmap::DashMap;
use tokio::task::JoinHandle;

use crate::common::error::Error;
use crate::common::scoped_task::ScopedTask;

use super::peer_manager::PeerManager;

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

    fn need_clear_task(&self, _data: &Self::Data) -> bool {
        false
    }

    async fn all_task_done(&self, _data: &Self::Data) {}

    fn loop_interval_ms(&self) -> u64 {
        5000
    }
}

struct PeerTaskManager<Launcher: PeerTaskLauncher> {
    launcher: Launcher,
    peer_mgr: Arc<PeerManager>,
    main_loop_task: Mutex<Option<ScopedTask<()>>>,
}

impl<D, C, T, L> PeerTaskManager<L>
where
    D: Send + Sync + Clone + 'static,
    C: Send + Sync + Clone + core::hash::Hash + Eq + 'static,
    T: Send + 'static,
    L: PeerTaskLauncher<Data = D, CollectPeerItem = C, TaskRet = T> + 'static,
{
    pub fn new(launcher: L, peer_mgr: Arc<PeerManager>) -> Self {
        Self {
            launcher,
            peer_mgr,
            main_loop_task: Mutex::new(None),
        }
    }

    pub fn start(&self) {
        let data = self.launcher.new_data(self.peer_mgr.clone());
        let task = tokio::spawn(Self::main_loop(self.launcher.clone(), data)).into();
        self.main_loop_task.lock().unwrap().replace(task);
    }

    async fn main_loop(launcher: L, data: D) {
        let peer_task_map = Arc::new(DashMap::<C, ScopedTask<Result<T, Error>>>::new());

        loop {
            let peers_to_connect = launcher.collect_peers_need_task(&data).await;
            let need_clear_task = launcher.need_clear_task(&data);

            // remove task not in peers_to_connect
            let mut to_remove = vec![];
            for item in peer_task_map.iter() {
                if !peers_to_connect.contains(item.key())
                    || item.value().is_finished()
                    || need_clear_task
                {
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
            }

            if !peers_to_connect.is_empty() {
                for item in peers_to_connect {
                    if peer_task_map.contains_key(&item) {
                        continue;
                    }

                    peer_task_map
                        .insert(item.clone(), launcher.launch_task(&data, item).await.into());
                }
            } else if peer_task_map.is_empty() {
                launcher.all_task_done(&data).await;
            }

            tokio::time::sleep(std::time::Duration::from_millis(
                launcher.loop_interval_ms(),
            ))
            .await;
        }
    }
}
