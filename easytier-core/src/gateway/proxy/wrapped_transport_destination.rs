use std::{
    net::SocketAddr,
    sync::{
        Arc,
        atomic::{AtomicBool, AtomicU8, Ordering},
    },
    time::{SystemTime, UNIX_EPOCH},
};

use dashmap::DashMap;
use guarden::defer;
use tokio::{sync::Mutex, task::JoinSet};
use tokio_util::sync::CancellationToken;

use crate::{
    config::runtime::CoreRuntimeConfigStore, connectivity::direct::DirectConnectorHost,
    connectivity::hole_punch::tcp::TcpHolePunchHost, listener::RunningListenerRegistry,
    peers::peer_manager::PeerManagerCore, process_runtime::ProtectedTcpPortRegistry,
    socket::SocketContext,
};

use super::{
    cidr_table::ProxyCidrTable,
    service::CoreProxyRuntime,
    tcp_proxy_engine::{TcpNatEntrySnapshot, TcpNatEntryState},
    tcp_socket_connector::TcpSocketProxyConnector,
    traits::TcpProxyDestinationConnector,
    wrapped_tcp_proxy::{WrappedTcpDestinationRequest, plan_wrapped_tcp_destination},
    wrapped_transport::{WrappedTransportAcceptedStream, WrappedTransportKind},
};

struct DestinationEntry {
    transport: WrappedTransportKind,
    src: SocketAddr,
    dst: SocketAddr,
    mapped_dst: std::sync::RwLock<SocketAddr>,
    start_time: u64,
    state: AtomicU8,
}

impl DestinationEntry {
    fn new(transport: WrappedTransportKind, src: SocketAddr, dst: SocketAddr) -> Self {
        Self {
            transport,
            src,
            dst,
            mapped_dst: std::sync::RwLock::new(dst),
            start_time: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map(|duration| duration.as_secs())
                .unwrap_or_default(),
            state: AtomicU8::new(TcpNatEntryState::ConnectingDst as u8),
        }
    }

    fn set_mapped_dst(&self, mapped_dst: SocketAddr) {
        *self
            .mapped_dst
            .write()
            .expect("wrapped destination entry mutex poisoned") = mapped_dst;
    }

    fn set_state(&self, state: TcpNatEntryState) {
        self.state.store(state as u8, Ordering::Release);
    }

    fn snapshot(&self) -> TcpNatEntrySnapshot {
        let state = match self.state.load(Ordering::Acquire) {
            value if value == TcpNatEntryState::Connected as u8 => TcpNatEntryState::Connected,
            _ => TcpNatEntryState::ConnectingDst,
        };
        TcpNatEntrySnapshot {
            src: self.src,
            dst: self.dst,
            mapped_dst: *self
                .mapped_dst
                .read()
                .expect("wrapped destination entry mutex poisoned"),
            start_time: self.start_time,
            state,
        }
    }
}

struct AcceptedDestination {
    transport: WrappedTransportKind,
    stream: WrappedTransportAcceptedStream,
}

#[derive(Clone)]
pub struct WrappedTransportDestinationIngress {
    transport: WrappedTransportKind,
    accepted: tokio::sync::mpsc::Sender<AcceptedDestination>,
}

impl WrappedTransportDestinationIngress {
    pub async fn submit(&self, stream: WrappedTransportAcceptedStream) -> anyhow::Result<()> {
        self.accepted
            .send(AcceptedDestination {
                transport: self.transport,
                stream,
            })
            .await
            .map_err(|_| anyhow::anyhow!("wrapped destination ingress is stopped"))
    }
}

#[derive(Default)]
pub(crate) struct WrappedTransportDestinationIngresses {
    pub(crate) kcp: Option<WrappedTransportDestinationIngress>,
    pub(crate) quic: Option<WrappedTransportDestinationIngress>,
}

struct DestinationRun {
    cancel: CancellationToken,
    supervisor: tokio::task::JoinHandle<()>,
}

async fn stop_destination_run(run: &Mutex<Option<DestinationRun>>) {
    let mut run = run.lock().await;
    if let Some(current) = run.as_mut() {
        current.cancel.cancel();
        let _ = (&mut current.supervisor).await;
        run.take();
    }
}

pub(crate) struct WrappedTransportDestinationModule<H>
where
    H: DirectConnectorHost + TcpHolePunchHost,
{
    runtime: Arc<CoreProxyRuntime<H>>,
    connector: TcpSocketProxyConnector<H>,
    cidr_table: Arc<ProxyCidrTable>,
    peer_manager: Arc<PeerManagerCore>,
    entries: DashMap<uuid::Uuid, Arc<DestinationEntry>>,
    run: Mutex<Option<DestinationRun>>,
    active: AtomicBool,
    enabled: AtomicU8,
}

#[async_trait::async_trait]
pub(crate) trait WrappedTransportDestinationLifecycle: Send + Sync {
    async fn start(
        self: Arc<Self>,
        kcp: bool,
        quic: bool,
    ) -> anyhow::Result<WrappedTransportDestinationIngresses>;
    async fn stop(&self);
    fn entry_snapshots(&self, transport: WrappedTransportKind) -> Vec<TcpNatEntrySnapshot>;
    fn is_started(&self, transport: WrappedTransportKind) -> bool;
}

impl<H> WrappedTransportDestinationModule<H>
where
    H: DirectConnectorHost + TcpHolePunchHost,
{
    const INGRESS_CAPACITY: usize = 128;

    pub(crate) fn new(
        peer_manager: Arc<PeerManagerCore>,
        host: Arc<H>,
        protected_tcp_ports: Arc<ProtectedTcpPortRegistry>,
        running_listeners: Arc<RunningListenerRegistry>,
        runtime_config: CoreRuntimeConfigStore,
        cidr_table: Arc<ProxyCidrTable>,
        socket_context: SocketContext,
    ) -> Arc<Self> {
        Arc::new(Self {
            runtime: CoreProxyRuntime::new(
                peer_manager.clone(),
                host.clone(),
                protected_tcp_ports,
                running_listeners,
                runtime_config,
                "TCP",
            ),
            connector: TcpSocketProxyConnector::new(host).with_socket_context(socket_context),
            cidr_table,
            peer_manager,
            entries: DashMap::new(),
            run: Mutex::new(None),
            active: AtomicBool::new(false),
            enabled: AtomicU8::new(0),
        })
    }

    pub(crate) async fn start(
        self: &Arc<Self>,
        kcp: bool,
        quic: bool,
    ) -> anyhow::Result<WrappedTransportDestinationIngresses> {
        let mut run = self.run.lock().await;
        if run.is_some() {
            anyhow::bail!("wrapped transport destination is already started");
        }

        let (accepted, mut receiver) = tokio::sync::mpsc::channel(Self::INGRESS_CAPACITY);
        let cancel = CancellationToken::new();
        let task_cancel = cancel.clone();
        let owner = Arc::downgrade(self);
        let supervisor = tokio::spawn(async move {
            let mut sessions = JoinSet::new();
            loop {
                tokio::select! {
                    biased;
                    _ = task_cancel.cancelled() => break,
                    accepted = receiver.recv() => {
                        let Some(accepted) = accepted else { break };
                        let Some(owner) = owner.upgrade() else { break };
                        sessions.spawn(async move {
                            if let Err(error) = owner.handle_destination(accepted).await {
                                tracing::debug!(?error, "wrapped destination session failed");
                            }
                        });
                    }
                    _ = sessions.join_next(), if !sessions.is_empty() => {}
                }
            }
            sessions.shutdown().await;
        });
        self.active.store(true, Ordering::Release);
        self.enabled
            .store((kcp as u8) | ((quic as u8) << 1), Ordering::Release);
        *run = Some(DestinationRun { cancel, supervisor });

        let ingress = |transport| WrappedTransportDestinationIngress {
            transport,
            accepted: accepted.clone(),
        };
        Ok(WrappedTransportDestinationIngresses {
            kcp: kcp.then(|| ingress(WrappedTransportKind::Kcp)),
            quic: quic.then(|| ingress(WrappedTransportKind::Quic)),
        })
    }

    pub(crate) async fn stop(&self) {
        self.active.store(false, Ordering::Release);
        self.enabled.store(0, Ordering::Release);
        stop_destination_run(&self.run).await;
        self.entries.clear();
    }

    pub(crate) fn entry_snapshots(
        &self,
        transport: WrappedTransportKind,
    ) -> Vec<TcpNatEntrySnapshot> {
        self.entries
            .iter()
            .filter(|entry| entry.value().transport == transport)
            .map(|entry| entry.value().snapshot())
            .collect()
    }

    pub(crate) fn is_started(&self, transport: WrappedTransportKind) -> bool {
        let mask = match transport {
            WrappedTransportKind::Kcp => 1,
            WrappedTransportKind::Quic => 2,
        };
        self.active.load(Ordering::Acquire) && self.enabled.load(Ordering::Acquire) & mask != 0
    }

    async fn handle_destination(&self, accepted: AcceptedDestination) -> anyhow::Result<()> {
        if !self.active.load(Ordering::Acquire) {
            anyhow::bail!("wrapped transport destination is not active");
        }

        let entry_id = uuid::Uuid::new_v4();
        let entry = Arc::new(DestinationEntry::new(
            accepted.transport,
            accepted.stream.src,
            accepted.stream.dst,
        ));
        self.entries.insert(entry_id, entry.clone());
        defer! {
            self.remove_entry(entry_id);
        }

        let route = self.peer_manager.get_route();
        let plan = plan_wrapped_tcp_destination(
            WrappedTcpDestinationRequest {
                src: accepted.stream.src,
                dst: accepted.stream.dst,
                initial_packet_size: accepted.stream.initial_acl_packet_size,
            },
            self.cidr_table.as_ref(),
            self.runtime.as_ref(),
            route.as_ref(),
            self.peer_manager.acl_filter(),
        )
        .await?;
        entry.set_mapped_dst(plan.socket_dst);

        tracing::debug!(dst = ?plan.socket_dst, "wrapped transport connect to destination");
        let destination = self
            .connector
            .connect("0.0.0.0:0".parse().unwrap(), plan.socket_dst)
            .await?;
        entry.set_state(TcpNatEntryState::Connected);

        plan.acl_handler
            .copy_bidirection_with_acl(accepted.stream.stream, destination)
            .await
    }

    fn remove_entry(&self, id: uuid::Uuid) {
        self.entries.remove(&id);
        if self.entries.capacity() - self.entries.len() > 16 {
            self.entries.shrink_to_fit();
        }
    }
}

#[async_trait::async_trait]
impl<H> WrappedTransportDestinationLifecycle for WrappedTransportDestinationModule<H>
where
    H: DirectConnectorHost + TcpHolePunchHost,
{
    async fn start(
        self: Arc<Self>,
        kcp: bool,
        quic: bool,
    ) -> anyhow::Result<WrappedTransportDestinationIngresses> {
        WrappedTransportDestinationModule::start(&self, kcp, quic).await
    }

    async fn stop(&self) {
        WrappedTransportDestinationModule::stop(self).await;
    }

    fn entry_snapshots(&self, transport: WrappedTransportKind) -> Vec<TcpNatEntrySnapshot> {
        WrappedTransportDestinationModule::entry_snapshots(self, transport)
    }

    fn is_started(&self, transport: WrappedTransportKind) -> bool {
        WrappedTransportDestinationModule::is_started(self, transport)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::sync::Notify;

    #[tokio::test]
    async fn cancelled_stop_retains_supervisor_for_retry() {
        let cancel = CancellationToken::new();
        let stop_entered = Arc::new(Notify::new());
        let release_stop = Arc::new(Notify::new());
        let supervisor = tokio::spawn({
            let cancel = cancel.clone();
            let stop_entered = stop_entered.clone();
            let release_stop = release_stop.clone();
            async move {
                cancel.cancelled().await;
                stop_entered.notify_one();
                release_stop.notified().await;
            }
        });
        let run = Arc::new(Mutex::new(Some(DestinationRun { cancel, supervisor })));

        let first_stop = tokio::spawn({
            let run = run.clone();
            async move { stop_destination_run(run.as_ref()).await }
        });
        stop_entered.notified().await;
        first_stop.abort();
        assert!(first_stop.await.unwrap_err().is_cancelled());
        assert!(run.lock().await.is_some());

        release_stop.notify_one();
        stop_destination_run(run.as_ref()).await;
        assert!(run.lock().await.is_none());
    }
}
