use std::{
    marker::PhantomData,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
};

use anyhow::Error;
use dashmap::DashMap;
use quanta::Instant;
use tokio::{
    sync::{Mutex, OwnedMutexGuard, TryLockError},
    task::JoinHandle,
};

use crate::{
    config::PeerId,
    connectivity::stun::StunInfoProvider,
    foundation::task::{ExternalTaskSignal, PeerTaskLauncher, PeerTaskManager},
    proto::common::NatType,
};

use crate::connectivity::hole_punch::policy::BackOff;

use super::{
    BLACKLIST_TIMEOUT_SEC, UdpBothEasySymPunchClient, UdpHolePunchClientError,
    UdpHolePunchPeerSource, UdpHolePunchRuntime, UdpHolePunchSignaling, UdpHolePunchTransportSink,
    UdpNatType, UdpPunchClientMethod, UdpPunchSocket, UdpPunchTaskInfo, UdpSymToConePunchClient,
    collect_udp_punch_tasks, punch_cone_to_cone, should_blacklist_signal_error,
};

#[derive(Clone, Default)]
pub struct UdpSymPunchLock {
    inner: Arc<Mutex<()>>,
}

impl UdpSymPunchLock {
    pub(crate) async fn lock(&self) -> OwnedMutexGuard<()> {
        self.inner.clone().lock_owned().await
    }

    pub(crate) fn try_lock(&self) -> Result<OwnedMutexGuard<()>, TryLockError> {
        self.inner.clone().try_lock_owned()
    }
}

struct UdpHolePunchBlacklist {
    items: DashMap<PeerId, Instant>,
}

impl UdpHolePunchBlacklist {
    fn new() -> Self {
        Self {
            items: DashMap::new(),
        }
    }

    fn contains(&self, peer_id: PeerId) -> bool {
        let Some(insert_time) = self.items.get(&peer_id) else {
            return false;
        };
        let expired = insert_time.elapsed().as_secs() >= BLACKLIST_TIMEOUT_SEC;
        drop(insert_time);

        if expired {
            self.items.remove(&peer_id);
            false
        } else {
            true
        }
    }

    fn insert(&self, peer_id: PeerId) {
        self.items.insert(peer_id, Instant::now());
    }

    fn cleanup(&self) {
        self.items
            .retain(|_, insert_time| insert_time.elapsed().as_secs() < BLACKLIST_TIMEOUT_SEC);
    }
}

struct UdpHolePunchConnectorParts<P, S, T, R>
where
    P: UdpHolePunchPeerSource + 'static,
    S: UdpHolePunchSignaling + 'static,
    T: UdpHolePunchTransportSink + 'static,
    R: UdpHolePunchRuntime,
{
    peer_source: Arc<P>,
    signaling: Arc<S>,
    transport_sink: Arc<T>,
    runtime: Arc<R>,
    stun: Arc<dyn StunInfoProvider>,
    sym_punch_lock: UdpSymPunchLock,
    try_cone_before_sym: AtomicBool,
}

pub struct UdpHolePunchConnectorData<P, S, T, R>
where
    P: UdpHolePunchPeerSource + 'static,
    S: UdpHolePunchSignaling + 'static,
    T: UdpHolePunchTransportSink + 'static,
    R: UdpHolePunchRuntime,
{
    peer_source: Arc<P>,
    signaling: Arc<S>,
    transport_sink: Arc<T>,
    runtime: Arc<R>,
    stun: Arc<dyn StunInfoProvider>,
    sym_punch_lock: UdpSymPunchLock,
    blacklist: UdpHolePunchBlacklist,
    try_cone_before_sym: Arc<AtomicBool>,
    pub sym_to_cone_client: UdpSymToConePunchClient<R, S>,
    pub both_easy_sym_client: UdpBothEasySymPunchClient<R, S>,
}

impl<P, S, T, R> UdpHolePunchConnectorData<P, S, T, R>
where
    P: UdpHolePunchPeerSource + 'static,
    S: UdpHolePunchSignaling + 'static,
    T: UdpHolePunchTransportSink + 'static,
    R: UdpHolePunchRuntime,
{
    fn new(parts: Arc<UdpHolePunchConnectorParts<P, S, T, R>>) -> Arc<Self> {
        Arc::new(Self {
            peer_source: parts.peer_source.clone(),
            signaling: parts.signaling.clone(),
            transport_sink: parts.transport_sink.clone(),
            runtime: parts.runtime.clone(),
            stun: parts.stun.clone(),
            sym_punch_lock: parts.sym_punch_lock.clone(),
            blacklist: UdpHolePunchBlacklist::new(),
            try_cone_before_sym: Arc::new(AtomicBool::new(
                parts.try_cone_before_sym.load(Ordering::Relaxed),
            )),
            sym_to_cone_client: UdpSymToConePunchClient::new(
                parts.runtime.clone(),
                parts.signaling.clone(),
                parts.stun.clone(),
            ),
            both_easy_sym_client: UdpBothEasySymPunchClient::new(
                parts.runtime.clone(),
                parts.signaling.clone(),
                parts.stun.clone(),
            ),
        })
    }

    fn should_skip_blacklisted(&self, peer_id: PeerId) -> bool {
        if self.blacklist.contains(peer_id) {
            tracing::debug!(
                dst_peer_id = peer_id,
                "peer is blacklisted, skipping hole punching"
            );
            true
        } else {
            false
        }
    }

    fn map_client_result(
        &self,
        dst_peer_id: PeerId,
        ret: Result<Option<UdpPunchSocket>, UdpHolePunchClientError>,
    ) -> Result<Option<UdpPunchSocket>, Error> {
        match ret {
            Ok(ret) => Ok(ret),
            Err(UdpHolePunchClientError::Signaling(err)) => {
                if should_blacklist_signal_error(&err) {
                    self.blacklist.insert(dst_peer_id);
                }
                Err(err.into())
            }
            Err(err) => Err(err.into()),
        }
    }

    #[tracing::instrument(skip(self))]
    async fn handle_punch_result(
        &self,
        ret: Result<Option<UdpPunchSocket>, Error>,
        backoff: Option<&mut BackOff>,
        round: Option<&mut u32>,
    ) -> bool {
        let op = |rollback: bool| {
            if rollback {
                if let Some(backoff) = backoff {
                    backoff.rollback();
                }
                if let Some(round) = round {
                    *round = round.saturating_sub(1);
                }
            } else if let Some(round) = round {
                *round += 1;
            }
        };

        match ret {
            Ok(Some(socket)) => {
                let (connected, requested_url) = socket.into_connected();
                if let Err(err) = self
                    .transport_sink
                    .add_client_transport(connected, requested_url)
                    .await
                {
                    tracing::warn!(?err, "upgrade or add UDP hole-punch transport failed");
                    op(true);
                    false
                } else {
                    tracing::info!("hole punching transport admitted successfully");
                    true
                }
            }
            Ok(None) => {
                tracing::info!("hole punching failed, no punched socket");
                op(false);
                false
            }
            Err(err) => {
                tracing::info!(?err, "hole punching failed");
                op(true);
                false
            }
        }
    }

    #[tracing::instrument(skip(self))]
    async fn cone_to_cone(self: Arc<Self>, task_info: UdpPunchTaskInfo) -> Result<(), Error> {
        let mut backoff = BackOff::new(vec![1000, 1000, 2000, 4000, 4000, 8000, 8000, 16000]);

        loop {
            backoff.sleep_for_next_backoff().await;

            if self.should_skip_blacklisted(task_info.dst_peer_id) {
                break;
            }

            let ret = punch_cone_to_cone(
                self.runtime.clone(),
                self.signaling.clone(),
                task_info.dst_peer_id,
            )
            .await;
            let ret = self.map_client_result(task_info.dst_peer_id, ret);

            if self
                .handle_punch_result(ret, Some(&mut backoff), None)
                .await
            {
                break;
            }
        }

        Ok(())
    }

    #[tracing::instrument(skip(self))]
    async fn sym_to_cone(self: Arc<Self>, task_info: UdpPunchTaskInfo) -> Result<(), Error> {
        let mut backoff =
            BackOff::new(vec![1000, 1000, 2000, 4000, 4000, 8000, 8000, 16000, 64000]);
        let mut round = 0;
        let mut port_idx = rand::random();

        loop {
            backoff.sleep_for_next_backoff().await;

            if self.should_skip_blacklisted(task_info.dst_peer_id) {
                break;
            }

            if self.try_cone_before_sym.load(Ordering::Relaxed) {
                let ret = punch_cone_to_cone(
                    self.runtime.clone(),
                    self.signaling.clone(),
                    task_info.dst_peer_id,
                )
                .await;
                let ret = self.map_client_result(task_info.dst_peer_id, ret);
                if self.handle_punch_result(ret, None, None).await {
                    break;
                }
                if self.should_skip_blacklisted(task_info.dst_peer_id) {
                    break;
                }
            }

            let ret = {
                let _lock = self.sym_punch_lock.lock().await;
                self.sym_to_cone_client
                    .do_hole_punching(
                        task_info.dst_peer_id,
                        round,
                        &mut port_idx,
                        task_info.my_nat_type,
                    )
                    .await
            };
            let ret = self.map_client_result(task_info.dst_peer_id, ret);

            if self
                .handle_punch_result(ret, Some(&mut backoff), Some(&mut round))
                .await
            {
                break;
            }
        }

        Ok(())
    }

    #[tracing::instrument(skip(self))]
    async fn both_easy_sym(self: Arc<Self>, task_info: UdpPunchTaskInfo) -> Result<(), Error> {
        let mut backoff =
            BackOff::new(vec![1000, 1000, 2000, 4000, 4000, 8000, 8000, 16000, 64000]);

        loop {
            backoff.sleep_for_next_backoff().await;

            if self.should_skip_blacklisted(task_info.dst_peer_id) {
                break;
            }

            if self.try_cone_before_sym.load(Ordering::Relaxed) {
                let ret = punch_cone_to_cone(
                    self.runtime.clone(),
                    self.signaling.clone(),
                    task_info.dst_peer_id,
                )
                .await;
                let ret = self.map_client_result(task_info.dst_peer_id, ret);
                if self.handle_punch_result(ret, None, None).await {
                    break;
                }
                if self.should_skip_blacklisted(task_info.dst_peer_id) {
                    break;
                }
            }

            let mut is_busy = false;
            let ret = {
                let _lock = self.sym_punch_lock.lock().await;
                self.both_easy_sym_client
                    .do_hole_punching(
                        task_info.dst_peer_id,
                        task_info.my_nat_type,
                        task_info.dst_nat_type,
                        &mut is_busy,
                    )
                    .await
            };
            let ret = self.map_client_result(task_info.dst_peer_id, ret);

            if is_busy {
                backoff.rollback();
            } else if self
                .handle_punch_result(ret, Some(&mut backoff), None)
                .await
            {
                break;
            }
        }

        Ok(())
    }
}

type UdpHolePunchPeerTaskMarker<P, S, T, R> = PhantomData<fn() -> (P, S, T, R)>;

struct UdpHolePunchPeerTaskLauncher<P, S, T, R>(UdpHolePunchPeerTaskMarker<P, S, T, R>);

impl<P, S, T, R> Clone for UdpHolePunchPeerTaskLauncher<P, S, T, R> {
    fn clone(&self) -> Self {
        Self(PhantomData)
    }
}

#[async_trait::async_trait]
impl<P, S, T, R> PeerTaskLauncher for UdpHolePunchPeerTaskLauncher<P, S, T, R>
where
    P: UdpHolePunchPeerSource + 'static,
    S: UdpHolePunchSignaling + 'static,
    T: UdpHolePunchTransportSink + 'static,
    R: UdpHolePunchRuntime,
{
    type PeerManager = UdpHolePunchConnectorParts<P, S, T, R>;
    type Data = Arc<UdpHolePunchConnectorData<P, S, T, R>>;
    type CollectPeerItem = UdpPunchTaskInfo;
    type TaskRet = ();

    fn new_data(&self, parts: Arc<Self::PeerManager>) -> Self::Data {
        UdpHolePunchConnectorData::new(parts)
    }

    async fn collect_peers_need_task(&self, data: &Self::Data) -> Vec<Self::CollectPeerItem> {
        let my_nat_type = data.stun.get_stun_info().udp_nat_type;
        let my_nat_type: UdpNatType = NatType::try_from(my_nat_type)
            .unwrap_or(NatType::Unknown)
            .into();
        if !my_nat_type.is_sym() {
            data.sym_to_cone_client.clear_udp_array().await;
        }

        if my_nat_type.is_open() {
            return Vec::new();
        }

        data.blacklist.cleanup();

        let my_peer_id = data.peer_source.local_peer_id();
        let policy = data.peer_source.p2p_policy_flags();
        let candidates = data.peer_source.candidates().await;
        let peers_to_connect =
            collect_udp_punch_tasks(my_peer_id, my_nat_type, policy, candidates, |peer_id| {
                data.blacklist.contains(peer_id)
            });
        for task in &peers_to_connect {
            tracing::info!(
                peer_id = task.dst_peer_id,
                peer_nat_type = ?task.dst_nat_type,
                ?my_nat_type,
                "found peer to do hole punching"
            );
        }

        peers_to_connect
    }

    async fn launch_task(
        &self,
        data: &Self::Data,
        item: Self::CollectPeerItem,
    ) -> JoinHandle<Result<Self::TaskRet, Error>> {
        let data = data.clone();
        let disable_sym_hole_punching = data
            .peer_source
            .p2p_policy_flags()
            .disable_sym_hole_punching;
        let punch_method = item
            .my_nat_type
            .get_punch_hole_method(item.dst_nat_type, disable_sym_hole_punching);
        match punch_method {
            UdpPunchClientMethod::ConeToCone => tokio::spawn(data.cone_to_cone(item)),
            UdpPunchClientMethod::SymToCone => tokio::spawn(data.sym_to_cone(item)),
            UdpPunchClientMethod::EasySymToEasySym => tokio::spawn(data.both_easy_sym(item)),
            _ => unreachable!(),
        }
    }

    async fn all_task_done(&self, data: &Self::Data) {
        data.sym_to_cone_client.clear_udp_array().await;
    }

    fn loop_interval_ms(&self) -> u64 {
        5000
    }
}

pub struct UdpHolePunchConnector<P, S, T, R>
where
    P: UdpHolePunchPeerSource + 'static,
    S: UdpHolePunchSignaling + 'static,
    T: UdpHolePunchTransportSink + 'static,
    R: UdpHolePunchRuntime,
{
    client: PeerTaskManager<UdpHolePunchPeerTaskLauncher<P, S, T, R>>,
}

impl<P, S, T, R> UdpHolePunchConnector<P, S, T, R>
where
    P: UdpHolePunchPeerSource + 'static,
    S: UdpHolePunchSignaling + 'static,
    T: UdpHolePunchTransportSink + 'static,
    R: UdpHolePunchRuntime,
{
    pub fn new(
        peer_source: Arc<P>,
        signaling: Arc<S>,
        transport_sink: Arc<T>,
        runtime: Arc<R>,
        stun: Arc<dyn StunInfoProvider>,
        sym_punch_lock: UdpSymPunchLock,
        external_signal: Option<Arc<ExternalTaskSignal>>,
    ) -> Self {
        let parts = Arc::new(UdpHolePunchConnectorParts {
            peer_source,
            signaling,
            transport_sink,
            runtime,
            stun,
            sym_punch_lock,
            try_cone_before_sym: AtomicBool::new(true),
        });
        Self {
            client: PeerTaskManager::new_with_external_signal(
                UdpHolePunchPeerTaskLauncher(PhantomData),
                parts,
                external_signal,
            ),
        }
    }

    pub fn run_as_client(&self) {
        self.client.start();
    }

    pub async fn stop(&self) {
        self.client.stop().await;
        self.client
            .data()
            .sym_to_cone_client
            .clear_udp_array()
            .await;
    }
}

#[cfg(test)]
mod tests {
    use super::UdpSymPunchLock;

    #[test]
    fn symmetric_punch_locks_are_scoped_per_instance() {
        let first = UdpSymPunchLock::default();
        let first_clone = first.clone();
        let second = UdpSymPunchLock::default();

        let _first_guard = first.try_lock().unwrap();
        assert!(first_clone.try_lock().is_err());
        assert!(second.try_lock().is_ok());
    }
}
