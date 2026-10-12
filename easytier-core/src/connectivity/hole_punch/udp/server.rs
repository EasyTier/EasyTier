use std::{
    net::{Ipv4Addr, SocketAddr, SocketAddrV4},
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    time::Duration,
};

use anyhow::Context;
use crossbeam_utils::atomic::AtomicCell;
use quanta::Instant;
use rand::{Rng, seq::SliceRandom as _};
use tokio::{
    sync::{Mutex, RwLock, RwLockReadGuard},
    task::JoinSet,
};
use tokio_util::task::AbortOnDropHandle;

use crate::{
    connectivity::{hole_punch::port_mapping::UdpPortMappingLease, stun::StunInfoProvider},
    packet::{HOLE_PUNCH_PACKET_BODY_LEN, new_hole_punch_packet},
    socket::{ListenerConnectionCounter, udp::VirtualUdpSocket},
};

use super::{
    MAX_PUBLIC_UDP_HOLE_PUNCH_LISTENERS, ReusableUdpPunchListener, SelectPunchListener,
    SelectPunchListenerResponse, SendPunchPacketBothEasySym, SendPunchPacketBothEasySymResponse,
    SendPunchPacketCone, SendPunchPacketEasySym, SendPunchPacketHardSym,
    SendPunchPacketHardSymResponse, UdpHolePunchInbound, UdpHolePunchRuntime,
    UdpHolePunchSignalError, UdpHolePunchTransportSink, UdpPunchListener, UdpSocketArray,
    UdpSymPunchLock, can_reuse_port_mapping_listener, can_reuse_public_listener,
    select_reusable_port_mapping_listener_idx, select_reusable_public_listener_idx,
    should_create_public_listener, should_retry_public_listener_selection,
};

const MAX_K1_FOR_RANDOM_HARD_SYM: u32 = 180;
// Selection precedes local socket/STUN preparation. Match the listener's
// selection lifetime so abandoned preparations expire without per-RPC tasks.
const PREPARED_CONE_PUNCH_TIMEOUT: Duration = Duration::from_secs(30);

pub struct SelectedUdpPunchListener<S> {
    /// Kept for listener-selection side effects and tests; production callers
    /// only consume `mapped_addr`.
    #[allow(dead_code)]
    pub socket: Arc<S>,
    pub mapped_addr: SocketAddr,
}

pub struct UdpHolePunchServer<R, T>
where
    R: UdpHolePunchRuntime,
    T: UdpHolePunchTransportSink + 'static,
{
    sym_punch_lock: UdpSymPunchLock,
    common: Arc<UdpHolePunchServerCommon<R, T>>,
    both_easy_sym_server: UdpBothEasySymPunchServer<R, T>,
    shuffled_port_vec: Arc<Vec<u16>>,
    admission: RwLock<()>,
    stopping: AtomicBool,
}

impl<R, T> UdpHolePunchServer<R, T>
where
    R: UdpHolePunchRuntime,
    T: UdpHolePunchTransportSink + 'static,
{
    pub fn new(
        runtime: Arc<R>,
        stun: Arc<dyn StunInfoProvider>,
        transport_sink: Arc<T>,
        sym_punch_lock: UdpSymPunchLock,
    ) -> Self {
        let common = Arc::new(UdpHolePunchServerCommon::new(
            runtime.clone(),
            stun.clone(),
            transport_sink.clone(),
        ));
        let both_easy_sym_common =
            Arc::new(UdpHolePunchServerCommon::new(runtime, stun, transport_sink));
        let both_easy_sym_server = UdpBothEasySymPunchServer::new(both_easy_sym_common);
        let mut shuffled_port_vec: Vec<u16> = (1..=65535).collect();
        shuffled_port_vec.shuffle(&mut rand::thread_rng());

        Self {
            sym_punch_lock,
            common,
            both_easy_sym_server,
            shuffled_port_vec: Arc::new(shuffled_port_vec),
            admission: RwLock::new(()),
            stopping: AtomicBool::new(true),
        }
    }

    pub async fn start(&self) {
        let _admission = self.admission.write().await;
        if !self.stopping.load(Ordering::Acquire) {
            return;
        }
        self.stop_inner().await;
        self.common.start().await;
        self.both_easy_sym_server.common.start().await;
        self.stopping.store(false, Ordering::Release);
    }

    pub fn begin_stop(&self) {
        self.stopping.store(true, Ordering::Release);
    }

    pub async fn stop(&self) {
        self.begin_stop();
        let _admission = self.admission.write().await;
        self.stopping.store(true, Ordering::Release);
        self.stop_inner().await;
    }

    async fn stop_inner(&self) {
        self.both_easy_sym_server.stop().await;
        self.both_easy_sym_server.common.stop().await;
        self.common.stop().await;
    }

    async fn admit(&self) -> Result<RwLockReadGuard<'_, ()>, UdpHolePunchSignalError> {
        if self.stopping.load(Ordering::Acquire) {
            return Err(UdpHolePunchSignalError::Transport(
                "udp hole punch server is stopping".into(),
            ));
        }
        let guard = self.admission.read().await;
        if self.stopping.load(Ordering::Acquire) {
            return Err(UdpHolePunchSignalError::Transport(
                "udp hole punch server is stopping".into(),
            ));
        }
        Ok(guard)
    }

    fn busy_signal_error() -> UdpHolePunchSignalError {
        UdpHolePunchSignalError::RemoteRejected("sym punch lock is busy".into())
    }

    fn anyhow_to_signal_error(error: anyhow::Error) -> UdpHolePunchSignalError {
        UdpHolePunchSignalError::RemoteRejected(error.to_string())
    }

    async fn send_punch_packet_easy_sym_inner(
        &self,
        request: SendPunchPacketEasySym,
    ) -> anyhow::Result<()> {
        tracing::info!("send_punch_packet_easy_sym start");

        let listener = self
            .common
            .find_listener(&request.listener_mapped_addr)
            .await
            .ok_or(anyhow::anyhow!(
                "send_punch_packet_easy_sym failed to find listener"
            ))?;

        if request.public_ips.is_empty() {
            tracing::warn!("send_punch_packet_easy_sym got zero len public ip");
            anyhow::bail!("send_punch_packet_easy_sym got zero len public ip");
        }

        let base_port_num = request.base_port_num;
        let max_port_num = request.max_port_num.max(1);
        let port_start = if request.is_incremental {
            base_port_num.saturating_add(1)
        } else {
            base_port_num.saturating_sub(max_port_num)
        };
        let port_end = if request.is_incremental {
            base_port_num.saturating_add(max_port_num)
        } else {
            base_port_num.saturating_sub(1)
        };

        if port_end <= port_start {
            anyhow::bail!("send_punch_packet_easy_sym invalid port range");
        }

        let ports = (port_start..=port_end)
            .map(|port| port as u16)
            .collect::<Vec<_>>();
        tracing::debug!(
            ?ports,
            public_ips = ?request.public_ips,
            "send_punch_packet_easy_sym send to ports"
        );

        for _ in 0..2 {
            send_symmetric_hole_punch_packet(
                &ports,
                listener.clone(),
                request.transaction_id,
                &request.public_ips,
                0,
                ports.len(),
            )
            .await
            .with_context(|| "failed to send symmetric hole punch packet")?;
        }

        Ok(())
    }

    async fn send_punch_packet_hard_sym_inner(
        &self,
        request: SendPunchPacketHardSym,
    ) -> anyhow::Result<SendPunchPacketHardSymResponse> {
        tracing::info!("try_punch_symmetric start");

        let listener = self
            .common
            .find_listener(&request.listener_mapped_addr)
            .await
            .ok_or(anyhow::anyhow!(
                "send_punch_packet_for_cone failed to find listener"
            ))?;

        if request.public_ips.is_empty() {
            tracing::warn!("try_punch_symmetric got zero len public ip");
            anyhow::bail!("try_punch_symmetric got zero len public ip");
        }

        let last_port_index = request.port_index as usize;
        let round = request.round.max(1);
        let mut max_k2: u32 = rand::thread_rng().gen_range(600..800);
        if round > 2 {
            max_k2 = (max_k2 * 2 / round).max(MAX_K1_FOR_RANDOM_HARD_SYM);
        }

        let mut next_port_index = 0;
        for _ in 0..2 {
            next_port_index = send_symmetric_hole_punch_packet(
                &self.shuffled_port_vec,
                listener.clone(),
                request.transaction_id,
                &request.public_ips,
                last_port_index,
                max_k2 as usize,
            )
            .await
            .with_context(|| "failed to send symmetric hole punch packet randomly")?;
        }

        Ok(SendPunchPacketHardSymResponse {
            next_port_index: next_port_index as u32,
        })
    }
}

#[async_trait::async_trait]
impl<R, T> UdpHolePunchInbound for UdpHolePunchServer<R, T>
where
    R: UdpHolePunchRuntime,
    T: UdpHolePunchTransportSink + 'static,
{
    async fn select_punch_listener(
        &self,
        request: SelectPunchListener,
    ) -> Result<SelectPunchListenerResponse, UdpHolePunchSignalError> {
        let _admission = self.admit().await?;
        let selected = self
            .common
            .select_listener(request.force_new, request.prefer_port_mapping)
            .await
            .ok_or_else(|| {
                UdpHolePunchSignalError::RemoteRejected("no listener available".into())
            })?;

        if let Some(transaction_id) = request.transaction_id {
            self.common
                .prepare_hole_punch(&selected.mapped_addr, transaction_id)
                .await
                .map_err(Self::anyhow_to_signal_error)?;
        }

        Ok(SelectPunchListenerResponse {
            listener_mapped_addr: selected.mapped_addr,
            transaction_id: request.transaction_id,
        })
    }

    async fn send_punch_packet_cone(
        &self,
        request: SendPunchPacketCone,
    ) -> Result<(), UdpHolePunchSignalError> {
        let _admission = self.admit().await?;
        let (listener, observer) = self
            .common
            .observe_hole_punch(&request.listener_mapped_addr, request.transaction_id)
            .await
            .map_err(Self::anyhow_to_signal_error)?;
        send_cone_hole_punch_packets(listener, &request, observer)
            .await
            .map_err(Self::anyhow_to_signal_error)
    }

    async fn send_punch_packet_hard_sym(
        &self,
        request: SendPunchPacketHardSym,
    ) -> Result<SendPunchPacketHardSymResponse, UdpHolePunchSignalError> {
        let _admission = self.admit().await?;
        let _locked = self
            .sym_punch_lock
            .try_lock()
            .map_err(|_| Self::busy_signal_error())?;
        self.send_punch_packet_hard_sym_inner(request)
            .await
            .map_err(Self::anyhow_to_signal_error)
    }

    async fn send_punch_packet_easy_sym(
        &self,
        request: SendPunchPacketEasySym,
    ) -> Result<(), UdpHolePunchSignalError> {
        let _admission = self.admit().await?;
        let _locked = self
            .sym_punch_lock
            .try_lock()
            .map_err(|_| Self::busy_signal_error())?;
        self.send_punch_packet_easy_sym_inner(request)
            .await
            .map_err(Self::anyhow_to_signal_error)
    }

    async fn send_punch_packet_both_easy_sym(
        &self,
        request: SendPunchPacketBothEasySym,
    ) -> Result<SendPunchPacketBothEasySymResponse, UdpHolePunchSignalError> {
        let _admission = self.admit().await?;
        let _locked = self
            .sym_punch_lock
            .try_lock()
            .map_err(|_| Self::busy_signal_error())?;
        self.both_easy_sym_server
            .send_punch_packet_both_easy_sym(request)
            .await
            .map_err(Self::anyhow_to_signal_error)
    }
}

type UdpPunchListenerRecords<S> = Arc<Mutex<Vec<Arc<UdpPunchListenerRecord<S>>>>>;

pub struct UdpHolePunchServerCommon<R, T>
where
    R: UdpHolePunchRuntime,
    T: UdpHolePunchTransportSink + 'static,
{
    runtime: Arc<R>,
    stun: Arc<dyn StunInfoProvider>,
    transport_sink: Arc<T>,
    listeners: UdpPunchListenerRecords<R::Socket>,
    pending: UdpPunchListenerRecords<R::Socket>,
    retiring: UdpPunchListenerRecords<R::Socket>,
    cleanup_task: Mutex<Option<AbortOnDropHandle<()>>>,
}

impl<R, T> UdpHolePunchServerCommon<R, T>
where
    R: UdpHolePunchRuntime,
    T: UdpHolePunchTransportSink + 'static,
{
    pub fn new(runtime: Arc<R>, stun: Arc<dyn StunInfoProvider>, transport_sink: Arc<T>) -> Self {
        let listeners = Arc::new(Mutex::new(Vec::new()));

        Self {
            runtime,
            stun,
            transport_sink,
            listeners,
            pending: Arc::new(Mutex::new(Vec::new())),
            retiring: Arc::new(Mutex::new(Vec::new())),
            cleanup_task: Mutex::new(None),
        }
    }

    pub async fn start(&self) {
        let mut task_slot = self.cleanup_task.lock().await;
        if task_slot.as_ref().is_some_and(|task| !task.is_finished()) {
            return;
        }
        let listeners = self.listeners.clone();
        let retiring = self.retiring.clone();
        task_slot.replace(AbortOnDropHandle::new(tokio::spawn(async move {
            loop {
                crate::foundation::time::sleep(Duration::from_secs(5)).await;
                {
                    let mut retiring = retiring.lock().await;
                    let mut listeners = listeners.lock().await;
                    let mut index = 0;
                    while index < listeners.len() {
                        let listener = &listeners[index];
                        listener.hole_punch_observers.expire_prepared();
                        let active = listener.last_active_time.load().elapsed().as_secs() < 40
                            || listener.last_select_time.load().elapsed().as_secs() < 30;
                        if active {
                            index += 1;
                        } else {
                            retiring.push(listeners.remove(index));
                        }
                    }
                }
                drain_retiring_listeners(retiring.as_ref()).await;
            }
        })));
    }

    pub async fn stop(&self) {
        let mut cleanup_task = self.cleanup_task.lock().await;
        if let Some(cleanup_task) = cleanup_task.as_mut() {
            cleanup_task.abort();
            let _ = cleanup_task.await;
        }
        cleanup_task.take();
        drop(cleanup_task);

        {
            let mut pending = self.pending.lock().await;
            let mut retiring = self.retiring.lock().await;
            let mut listeners = self.listeners.lock().await;
            retiring.extend(std::mem::take(&mut *pending));
            retiring.extend(std::mem::take(&mut *listeners));
        }
        drain_retiring_listeners(self.retiring.as_ref()).await;
    }

    pub async fn add_listener(&self, listener: UdpPunchListener<R::Socket>) {
        let mut listeners = self.listeners.lock().await;
        listeners.push(Arc::new(UdpPunchListenerRecord::new(
            listener,
            self.transport_sink.clone(),
        )));
    }

    async fn track_pending_listener(
        &self,
        listener: UdpPunchListener<R::Socket>,
    ) -> Arc<UdpPunchListenerRecord<R::Socket>> {
        let mut pending = self.pending.lock().await;
        let listener = Arc::new(UdpPunchListenerRecord::new(
            listener,
            self.transport_sink.clone(),
        ));
        pending.push(listener.clone());
        listener
    }

    async fn promote_pending_listener(&self, listener: Arc<UdpPunchListenerRecord<R::Socket>>) {
        let mut pending = self.pending.lock().await;
        let mut listeners = self.listeners.lock().await;
        if let Some(index) = pending
            .iter()
            .position(|candidate| Arc::ptr_eq(candidate, &listener))
        {
            pending.remove(index);
            listeners.push(listener);
        }
    }

    async fn retire_pending_listener(&self, listener: Arc<UdpPunchListenerRecord<R::Socket>>) {
        let mut pending = self.pending.lock().await;
        let mut retiring = self.retiring.lock().await;
        if let Some(index) = pending
            .iter()
            .position(|candidate| Arc::ptr_eq(candidate, &listener))
        {
            retiring.push(pending.remove(index));
        }
    }

    pub async fn find_listener(&self, addr: &SocketAddr) -> Option<Arc<R::Socket>> {
        let listeners = self.listeners.lock().await;

        let listener = listeners
            .iter()
            .find(|listener| listener.mapped_addr == *addr && listener.running.load())?;

        Some(listener.get_socket())
    }

    async fn prepare_hole_punch(
        &self,
        addr: &SocketAddr,
        transaction_id: u32,
    ) -> anyhow::Result<()> {
        let listeners = self.listeners.lock().await;
        let listener = listeners
            .iter()
            .find(|listener| listener.mapped_addr == *addr && listener.running.load())
            .ok_or_else(|| anyhow::anyhow!("failed to find hole-punch listener"))?;
        listener
            .hole_punch_observers
            .prepare(transaction_id, PREPARED_CONE_PUNCH_TIMEOUT)?;
        Ok(())
    }

    async fn observe_hole_punch(
        &self,
        addr: &SocketAddr,
        transaction_id: u32,
    ) -> anyhow::Result<(Arc<R::Socket>, crate::socket::udp::UdpHolePunchObserver)> {
        let listeners = self.listeners.lock().await;
        let listener = listeners
            .iter()
            .find(|listener| listener.mapped_addr == *addr && listener.running.load())
            .ok_or_else(|| anyhow::anyhow!("send_punch_packet_for_cone failed to find listener"))?;
        let observer = listener.hole_punch_observers.observe(transaction_id)?;
        Ok((listener.get_socket(), observer))
    }

    pub async fn select_listener(
        &self,
        force_new_listener: bool,
        prefer_port_mapping: bool,
    ) -> Option<SelectedUdpPunchListener<R::Socket>> {
        let mut force_new_listener = force_new_listener;

        loop {
            let (listener_count, has_reusable_listener, has_port_mapping_listener) = {
                let listeners = self.listeners.lock().await;
                let states = listener_reuse_states(listeners.as_slice());
                (
                    states.len(),
                    states.iter().any(can_reuse_public_listener),
                    states.iter().any(can_reuse_port_mapping_listener),
                )
            };
            let should_create = should_create_public_listener(
                listener_count,
                has_reusable_listener,
                has_port_mapping_listener,
                force_new_listener,
                prefer_port_mapping,
            );

            if should_create {
                tracing::warn!(
                    max_listeners = MAX_PUBLIC_UDP_HOLE_PUNCH_LISTENERS,
                    "creating udp hole punching listener"
                );
                match self.runtime.create_listener(prefer_port_mapping).await {
                    Ok(listener) => self.add_listener(listener).await,
                    Err(err) => {
                        tracing::warn!(?err, "failed to create udp hole punching listener");
                    }
                }
            }

            let mut listeners = self.listeners.lock().await;
            let listener_count = listeners.len();
            let states = listener_reuse_states(listeners.as_slice());
            let listener_idx = if prefer_port_mapping {
                select_reusable_port_mapping_listener_idx(&states)
                    .or_else(|| {
                        if should_create && states.last().is_some_and(can_reuse_public_listener) {
                            Some(states.len() - 1)
                        } else {
                            None
                        }
                    })
                    .or_else(|| select_reusable_public_listener_idx(&states))
            } else if should_create {
                listeners.len().checked_sub(1)
            } else {
                select_reusable_public_listener_idx(&states)
            };

            let Some(listener_idx) = listener_idx else {
                tracing::warn!(
                    ?force_new_listener,
                    ?prefer_port_mapping,
                    listener_count,
                    max_listeners = MAX_PUBLIC_UDP_HOLE_PUNCH_LISTENERS,
                    "no available udp hole punching listener with mapped address"
                );
                if should_retry_public_listener_selection(
                    force_new_listener,
                    listener_count,
                    prefer_port_mapping,
                    has_port_mapping_listener,
                ) {
                    force_new_listener = true;
                    continue;
                }
                return None;
            };

            let listener = &mut listeners[listener_idx];
            if !can_reuse_public_listener(&listener.reuse_state()) {
                tracing::warn!(
                    ?force_new_listener,
                    ?prefer_port_mapping,
                    listener_count,
                    max_listeners = MAX_PUBLIC_UDP_HOLE_PUNCH_LISTENERS,
                    "selected udp hole punching listener is not reusable"
                );
                return None;
            }

            return Some(SelectedUdpPunchListener {
                socket: listener.get_socket(),
                mapped_addr: listener.mapped_addr,
            });
        }
    }
}

struct UdpPunchListenerRecord<S> {
    socket: Arc<S>,
    hole_punch_observers: crate::socket::udp::UdpHolePunchObserverRegistry,
    tasks: Mutex<JoinSet<()>>,
    connection_tasks: Arc<Mutex<JoinSet<()>>>,
    running: Arc<AtomicCell<bool>>,
    mapped_addr: SocketAddr,
    has_port_mapping_lease: bool,
    _port_mapping_lease: Option<Box<dyn UdpPortMappingLease>>,
    conn_counter: Arc<dyn ListenerConnectionCounter>,

    _listen_time: Instant,
    last_select_time: AtomicCell<Instant>,
    last_active_time: Arc<AtomicCell<Instant>>,
}

impl<S> UdpPunchListenerRecord<S>
where
    S: VirtualUdpSocket + 'static,
{
    fn new<T>(listener: UdpPunchListener<S>, transport_sink: Arc<T>) -> Self
    where
        T: UdpHolePunchTransportSink + 'static,
    {
        let UdpPunchListener {
            socket,
            hole_punch_observers,
            mapped_addr,
            conn_counter,
            mut acceptor,
            port_mapping_lease,
        } = listener;

        let running = Arc::new(AtomicCell::new(true));
        let running_clone = running.clone();
        let mut tasks = JoinSet::new();
        let connection_tasks = Arc::new(Mutex::new(JoinSet::new()));
        let accept_connection_tasks = connection_tasks.clone();

        tasks.spawn(async move {
            while let Ok(socket) = acceptor.accept().await {
                tracing::warn!(?socket, "udp hole punching listener got peer connection");
                let (connected, requested_url) = socket.into_connected();
                let transport_sink = transport_sink.clone();
                let mut connection_tasks = accept_connection_tasks.lock().await;
                while connection_tasks.try_join_next().is_some() {}
                connection_tasks.spawn(async move {
                    if let Err(err) = transport_sink
                        .add_server_transport(connected, requested_url)
                        .await
                    {
                        tracing::error!(
                            ?err,
                            "failed to upgrade or add server UDP hole-punch transport"
                        );
                    }
                });
            }

            running_clone.store(false);
        });

        let last_active_time = Arc::new(AtomicCell::new(Instant::now()));
        let conn_counter_clone = conn_counter.clone();
        let last_active_time_clone = last_active_time.clone();
        tasks.spawn(async move {
            loop {
                crate::foundation::time::sleep(Duration::from_secs(5)).await;
                if conn_counter_clone.get().unwrap_or(0) != 0 {
                    last_active_time_clone.store(Instant::now());
                }
            }
        });

        tracing::warn!(?mapped_addr, "udp hole punching listener started");

        Self {
            socket,
            hole_punch_observers,
            tasks: Mutex::new(tasks),
            connection_tasks,
            running,
            mapped_addr,
            has_port_mapping_lease: port_mapping_lease.is_some(),
            _port_mapping_lease: port_mapping_lease,
            conn_counter,

            _listen_time: Instant::now(),
            last_select_time: AtomicCell::new(Instant::now()),
            last_active_time,
        }
    }

    fn get_socket(&self) -> Arc<S> {
        self.last_select_time.store(Instant::now());
        self.socket.clone()
    }

    fn conn_count(&self) -> usize {
        self.conn_counter.get().unwrap_or(0) as usize
    }

    fn reuse_state(&self) -> ReusableUdpPunchListener {
        ReusableUdpPunchListener {
            running: self.running.load(),
            mapped_addr: self.mapped_addr,
            has_port_mapping_lease: self.has_port_mapping_lease,
            last_active_time: self.last_active_time.load(),
        }
    }

    async fn stop(&self) {
        let mut tasks = self.tasks.lock().await;
        tasks.abort_all();
        while tasks.join_next().await.is_some() {}
        drop(tasks);

        let mut connection_tasks = self.connection_tasks.lock().await;
        connection_tasks.abort_all();
        while connection_tasks.join_next().await.is_some() {}
        self.running.store(false);
    }
}

async fn drain_retiring_listeners<S>(retiring: &Mutex<Vec<Arc<UdpPunchListenerRecord<S>>>>)
where
    S: VirtualUdpSocket + 'static,
{
    loop {
        let listener = retiring.lock().await.first().cloned();
        let Some(listener) = listener else {
            return;
        };
        listener.stop().await;
        let mut retiring = retiring.lock().await;
        if let Some(index) = retiring
            .iter()
            .position(|candidate| Arc::ptr_eq(candidate, &listener))
        {
            retiring.remove(index);
        }
    }
}

fn listener_reuse_states<S>(
    listeners: &[Arc<UdpPunchListenerRecord<S>>],
) -> Vec<ReusableUdpPunchListener>
where
    S: VirtualUdpSocket + 'static,
{
    listeners
        .iter()
        .map(|listener| listener.reuse_state())
        .collect()
}

pub async fn send_cone_hole_punch_packets<S>(
    udp: Arc<S>,
    request: &SendPunchPacketCone,
    mut observer: crate::socket::udp::UdpHolePunchObserver,
) -> anyhow::Result<()>
where
    S: VirtualUdpSocket + 'static,
{
    let dest_ip = request.dest_addr.ip();
    if dest_ip.is_unspecified() || dest_ip.is_multicast() {
        anyhow::bail!(
            "send_punch_packet_for_cone dest_ip is malformed: {:?}",
            request
        );
    }

    let udp = udp.as_ref();
    let send_batch = |dest_addr| async move {
        for _ in 0..request.packet_count_per_batch {
            let udp_packet =
                new_hole_punch_packet(request.transaction_id, HOLE_PUNCH_PACKET_BODY_LEN);
            if let Err(err) = udp.send_to(&udp_packet.into_bytes(), dest_addr).await {
                tracing::error!(
                    ?err,
                    ?dest_addr,
                    "failed to send hole punch packet to dest addr"
                );
            }
        }
    };
    let mut observed_addr = observer.source_addr();
    for _ in 0..request.packet_batch_count {
        tracing::info!(?request, "sending hole punching packet");

        send_batch(request.dest_addr).await;
        if let Some(addr) = observed_addr.filter(|addr| *addr != request.dest_addr) {
            send_batch(addr).await;
        }
        let interval = crate::foundation::time::sleep(Duration::from_millis(
            request.packet_interval_ms as u64,
        ));
        tokio::pin!(interval);
        if observed_addr.is_none() {
            tokio::select! {
                _ = &mut interval => {}
                addr = observer.wait_for_source_addr() => {
                    let addr = addr?;
                    observed_addr = Some(addr);
                    if addr != request.dest_addr {
                        send_batch(addr).await;
                    }
                    interval.await;
                }
            }
        } else {
            interval.await;
        }
    }

    Ok(())
}

#[tracing::instrument(err, ret(level = tracing::Level::DEBUG), skip(ports, udp))]
pub async fn send_symmetric_hole_punch_packet<S>(
    ports: &[u16],
    udp: Arc<S>,
    transaction_id: u32,
    public_ips: &[Ipv4Addr],
    port_start_idx: usize,
    max_packets: usize,
) -> anyhow::Result<usize>
where
    S: VirtualUdpSocket + 'static,
{
    tracing::debug!("sending hard symmetric hole punching packet");
    let mut sent_packets = 0;
    let mut cur_port_idx = port_start_idx;
    while sent_packets < max_packets {
        let port = ports[cur_port_idx % ports.len()];
        for pub_ip in public_ips {
            let addr = SocketAddr::V4(SocketAddrV4::new(*pub_ip, port));
            for _ in 0..3 {
                let packet = new_hole_punch_packet(transaction_id, HOLE_PUNCH_PACKET_BODY_LEN);
                udp.send_to(&packet.into_bytes(), addr).await?;
            }
            sent_packets += 1;
        }
        cur_port_idx = cur_port_idx.wrapping_add(1);
        crate::foundation::time::sleep(Duration::from_millis(1)).await;
    }
    Ok(cur_port_idx % ports.len())
}

pub struct UdpBothEasySymPunchServer<R, T>
where
    R: UdpHolePunchRuntime,
    T: UdpHolePunchTransportSink + 'static,
{
    common: Arc<UdpHolePunchServerCommon<R, T>>,
    task: Mutex<Option<AbortOnDropHandle<()>>>,
}

impl<R, T> UdpBothEasySymPunchServer<R, T>
where
    R: UdpHolePunchRuntime,
    T: UdpHolePunchTransportSink + 'static,
{
    pub fn new(common: Arc<UdpHolePunchServerCommon<R, T>>) -> Self {
        Self {
            common,
            task: Mutex::new(None),
        }
    }

    pub async fn stop(&self) {
        let mut task = self.task.lock().await;
        if let Some(task) = task.as_mut() {
            task.abort();
            let _ = task.await;
        }
        task.take();
    }

    #[tracing::instrument(skip(self), ret, err)]
    pub async fn send_punch_packet_both_easy_sym(
        &self,
        request: SendPunchPacketBothEasySym,
    ) -> anyhow::Result<SendPunchPacketBothEasySymResponse> {
        tracing::info!("send_punch_packet_both_easy_sym start");
        let busy_resp = Ok(SendPunchPacketBothEasySymResponse {
            is_busy: true,
            base_mapped_addr: None,
        });
        let Ok(mut locked_task) = self.task.try_lock() else {
            return busy_resp;
        };
        if locked_task.is_some() && !locked_task.as_ref().unwrap().is_finished() {
            return busy_resp;
        }

        let cur_mapped_addr = self
            .common
            .stun
            .get_udp_port_mapping(0)
            .await
            .with_context(|| "failed to get udp port mapping")?;

        tracing::info!("send_punch_packet_hard_sym start");
        let socket_count = request.udp_socket_count as usize;
        let transaction_id = request.transaction_id;

        let udp_array = UdpSocketArray::new_with_context(
            socket_count,
            self.common.runtime.clone(),
            self.common.runtime.socket_context(),
        );
        udp_array.start().await?;
        udp_array.add_intreast_tid(transaction_id);

        let punch_packet =
            new_hole_punch_packet(transaction_id, HOLE_PUNCH_PACKET_BODY_LEN).into_bytes();
        let common = self.common.clone();

        let task = tokio::spawn(async move {
            let mut listeners = Vec::new();
            let mut punched = Vec::new();
            let start_time = Instant::now();
            let wait_time_ms = request.wait_time_ms.min(8000);
            while start_time.elapsed() < Duration::from_millis(wait_time_ms as u64) {
                if let Err(e) = udp_array
                    .send_with_all(
                        &punch_packet,
                        SocketAddr::V4(SocketAddrV4::new(
                            request.public_ip,
                            request.dst_port_num as u16,
                        )),
                    )
                    .await
                {
                    tracing::error!(?e, "failed to send hole punch packet");
                    break;
                }

                crate::foundation::time::sleep(Duration::from_millis(100)).await;

                if let Some(s) = udp_array.try_fetch_punched_socket(transaction_id) {
                    tracing::info!(?s, ?transaction_id, "got punched socket in both easy sym");
                    assert!(Arc::strong_count(&s.socket) == 1);
                    let Some(port) = s.socket.local_addr().ok().map(|addr| addr.port()) else {
                        tracing::warn!("failed to get local addr from punched socket");
                        continue;
                    };
                    let remote_addr = s.remote_addr;
                    drop(s);

                    let listener = match common.runtime.create_port_bound_listener(port).await {
                        Ok(listener) => listener,
                        Err(e) => {
                            tracing::warn!(?e, "failed to create listener");
                            continue;
                        }
                    };
                    let socket = listener.socket.clone();
                    let record = common.track_pending_listener(listener).await;
                    punched.push((socket, remote_addr));
                    listeners.push(record);
                }

                for listener in &listeners {
                    if listener.conn_count() > 0 {
                        tracing::info!(?listener.mapped_addr, "got punched listener");
                        break;
                    }
                }

                if !punched.is_empty() {
                    tracing::debug!(
                        punched_count = punched.len(),
                        "got punched socket and keep sending punch packet"
                    );
                }

                for p in &punched {
                    let (socket, remote_addr) = p;
                    let send_remote_ret = socket.send_to(&punch_packet, *remote_addr).await;
                    tracing::debug!(
                        ?send_remote_ret,
                        ?remote_addr,
                        "send hole punch packet to punched remote"
                    );
                }
            }

            for listener in listeners {
                if listener.conn_count() > 0 {
                    common.promote_pending_listener(listener).await;
                } else {
                    common.retire_pending_listener(listener).await;
                }
            }
            drain_retiring_listeners(common.retiring.as_ref()).await;
        });

        *locked_task = Some(AbortOnDropHandle::new(task));
        Ok(SendPunchPacketBothEasySymResponse {
            is_busy: false,
            base_mapped_addr: Some(cur_mapped_addr),
        })
    }
}

#[cfg(test)]
mod tests {
    use std::{
        collections::VecDeque,
        io,
        sync::{
            Mutex as StdMutex,
            atomic::{AtomicUsize, Ordering},
        },
    };

    use async_trait::async_trait;

    use super::*;
    use crate::{
        connectivity::hole_punch::udp::{UdpPunchAcceptor, UdpPunchSocket, UdpResolvedPublicAddr},
        proto::common::StunInfo,
        socket::udp::{UdpBindOptions, UdpSession, UdpSessionKind},
    };

    struct MockSocket {
        local_addr: SocketAddr,
        sent: tokio::sync::Mutex<Vec<(Vec<u8>, SocketAddr)>>,
        fail_next_send: AtomicUsize,
        incoming: StdMutex<VecDeque<(Vec<u8>, SocketAddr)>>,
        incoming_notify: tokio::sync::Notify,
    }

    #[async_trait]
    impl VirtualUdpSocket for MockSocket {
        fn local_addr(&self) -> io::Result<SocketAddr> {
            Ok(self.local_addr)
        }

        async fn send_to(&self, data: &[u8], _addr: SocketAddr) -> io::Result<usize> {
            if self.fail_next_send.load(Ordering::Relaxed) != 0 {
                self.fail_next_send.fetch_sub(1, Ordering::Relaxed);
                return Err(io::Error::other("mock send failure"));
            }
            self.sent.lock().await.push((data.to_vec(), _addr));
            Ok(data.len())
        }

        async fn recv_from(&self, buf: &mut [u8]) -> io::Result<(usize, SocketAddr)> {
            loop {
                if let Some((data, addr)) = self.incoming.lock().unwrap().pop_front() {
                    let len = data.len().min(buf.len());
                    buf[..len].copy_from_slice(&data[..len]);
                    return Ok((len, addr));
                }
                self.incoming_notify.notified().await;
            }
        }
    }

    #[derive(Debug, Default)]
    struct MockCounter {
        count: AtomicCell<u32>,
    }

    impl ListenerConnectionCounter for MockCounter {
        fn get(&self) -> Option<u32> {
            Some(self.count.load())
        }
    }

    struct MockAcceptor {
        sockets: VecDeque<UdpPunchSocket>,
        _layer: Arc<crate::socket::udp::UdpSessionLayer<MockSocket>>,
    }

    #[async_trait]
    impl UdpPunchAcceptor for MockAcceptor {
        async fn accept(&mut self) -> anyhow::Result<UdpPunchSocket> {
            let Some(socket) = self.sockets.pop_front() else {
                return std::future::pending().await;
            };
            Ok(socket)
        }
    }

    struct MockRuntime {
        listeners: StdMutex<VecDeque<UdpPunchListener<MockSocket>>>,
    }

    impl MockRuntime {
        fn new(listeners: Vec<UdpPunchListener<MockSocket>>) -> Self {
            Self {
                listeners: StdMutex::new(listeners.into()),
            }
        }
    }

    #[async_trait]
    impl UdpHolePunchRuntime for MockRuntime {
        type Socket = MockSocket;

        async fn bind_udp(&self, _options: UdpBindOptions) -> anyhow::Result<Arc<Self::Socket>> {
            Ok(Arc::new(MockSocket {
                local_addr: SocketAddr::from(([127, 0, 0, 1], 0)),
                sent: tokio::sync::Mutex::new(Vec::new()),
                fail_next_send: AtomicUsize::new(0),
                incoming: StdMutex::new(VecDeque::new()),
                incoming_notify: tokio::sync::Notify::new(),
            }))
        }

        async fn resolve_udp_public_addr(
            &self,
            socket: Arc<Self::Socket>,
        ) -> anyhow::Result<UdpResolvedPublicAddr> {
            Ok(UdpResolvedPublicAddr {
                mapped_addr: socket.local_addr()?,
                port_mapping_lease: None,
            })
        }

        async fn create_listener(
            &self,
            _prefer_port_mapping: bool,
        ) -> anyhow::Result<UdpPunchListener<Self::Socket>> {
            self.listeners
                .lock()
                .unwrap()
                .pop_front()
                .ok_or_else(|| anyhow::anyhow!("no listener"))
        }

        async fn create_port_bound_listener(
            &self,
            _port: u16,
        ) -> anyhow::Result<UdpPunchListener<Self::Socket>> {
            self.create_listener(false).await
        }

        async fn connect_with_socket(
            &self,
            socket: Arc<Self::Socket>,
            remote: SocketAddr,
        ) -> anyhow::Result<UdpPunchSocket> {
            let session =
                UdpSession::identity_standalone(socket, remote, UdpSessionKind::EasyTierMux)?;
            Ok(UdpPunchSocket::new(session, remote, ()))
        }
    }

    struct MockStunInfoProvider;

    #[async_trait]
    impl StunInfoProvider for MockStunInfoProvider {
        fn get_stun_info(&self) -> StunInfo {
            StunInfo::default()
        }

        async fn get_udp_port_mapping(&self, _port: u16) -> anyhow::Result<SocketAddr> {
            Ok(SocketAddr::from(([203, 0, 113, 1], 10000)))
        }

        async fn get_tcp_port_mapping(&self, _port: u16) -> anyhow::Result<SocketAddr> {
            unreachable!("TCP mapping is not used by UDP hole-punch tests")
        }

        fn update_stun_info(&self) {}
    }

    fn mock_stun() -> Arc<dyn StunInfoProvider> {
        Arc::new(MockStunInfoProvider)
    }

    #[derive(Default)]
    struct MockSink {
        server_tunnels: AtomicUsize,
    }

    #[async_trait]
    impl UdpHolePunchTransportSink for MockSink {
        async fn add_client_transport(
            &self,
            _connected: crate::connectivity::transport::ConnectedUdpSession,
            _requested_url: url::Url,
        ) -> anyhow::Result<()> {
            Ok(())
        }

        async fn add_server_transport(
            &self,
            _connected: crate::connectivity::transport::ConnectedUdpSession,
            _requested_url: url::Url,
        ) -> anyhow::Result<()> {
            self.server_tunnels.fetch_add(1, Ordering::Relaxed);
            Ok(())
        }
    }

    fn listener(port: u16, sockets: Vec<UdpPunchSocket>) -> UdpPunchListener<MockSocket> {
        let socket = Arc::new(MockSocket {
            local_addr: SocketAddr::from(([127, 0, 0, 1], port)),
            sent: tokio::sync::Mutex::new(Vec::new()),
            fail_next_send: AtomicUsize::new(0),
            incoming: StdMutex::new(VecDeque::new()),
            incoming_notify: tokio::sync::Notify::new(),
        });
        let layer = Arc::new(crate::socket::udp::UdpSessionLayer::new(socket.clone()));
        UdpPunchListener {
            socket,
            hole_punch_observers: layer.hole_punch_observers(),
            mapped_addr: SocketAddr::from(([203, 0, 113, 1], port)),
            conn_counter: Arc::new(MockCounter::default()),
            acceptor: Box::new(MockAcceptor {
                sockets: sockets.into(),
                _layer: layer,
            }),
            port_mapping_lease: None,
        }
    }

    #[tokio::test]
    async fn server_keeps_both_easy_sym_listener_pool_separate() {
        let runtime = Arc::new(MockRuntime::new(Vec::new()));
        let sink = Arc::new(MockSink::default());
        let server =
            UdpHolePunchServer::new(runtime, mock_stun(), sink, UdpSymPunchLock::default());

        assert!(!Arc::ptr_eq(
            &server.common,
            &server.both_easy_sym_server.common
        ));
    }

    #[test]
    fn server_constructor_is_cold() {
        let runtime = Arc::new(MockRuntime::new(Vec::new()));
        let sink = Arc::new(MockSink::default());

        let _server =
            UdpHolePunchServer::new(runtime, mock_stun(), sink, UdpSymPunchLock::default());
    }

    #[tokio::test]
    async fn common_lifecycle_joins_cleanup_and_listener_tasks() {
        let runtime = Arc::new(MockRuntime::new(vec![listener(10003, Vec::new())]));
        let sink = Arc::new(MockSink::default());
        let common = Arc::new(UdpHolePunchServerCommon::new(runtime, mock_stun(), sink));

        common.start().await;
        common.select_listener(false, false).await.unwrap();
        common.stop().await;

        assert!(common.cleanup_task.lock().await.is_none());
        assert!(common.listeners.lock().await.is_empty());
    }

    #[tokio::test]
    async fn select_listener_creates_and_finds_listener() {
        let runtime = Arc::new(MockRuntime::new(vec![listener(10000, Vec::new())]));
        let sink = Arc::new(MockSink::default());
        let common = UdpHolePunchServerCommon::new(runtime, mock_stun(), sink);

        let selected = common.select_listener(false, true).await.unwrap();

        assert_eq!(
            selected.mapped_addr,
            SocketAddr::from(([203, 0, 113, 1], 10000))
        );
        assert_eq!(
            selected.socket.local_addr().unwrap(),
            SocketAddr::from(([127, 0, 0, 1], 10000))
        );
        assert!(common.find_listener(&selected.mapped_addr).await.is_some());
    }

    #[tokio::test]
    async fn accepted_tunnel_is_forwarded_to_sink() {
        let socket = Arc::new(MockSocket {
            local_addr: SocketAddr::from(([127, 0, 0, 1], 10001)),
            sent: tokio::sync::Mutex::new(Vec::new()),
            fail_next_send: AtomicUsize::new(0),
            incoming: StdMutex::new(VecDeque::new()),
            incoming_notify: tokio::sync::Notify::new(),
        });
        let remote_addr = SocketAddr::from(([127, 0, 0, 1], 20001));
        let session =
            UdpSession::identity_standalone(socket, remote_addr, UdpSessionKind::EasyTierMux)
                .unwrap();
        let punched_socket = UdpPunchSocket::new(session, remote_addr, ());
        let runtime = Arc::new(MockRuntime::new(vec![listener(
            10001,
            vec![punched_socket],
        )]));
        let sink = Arc::new(MockSink::default());
        let common = UdpHolePunchServerCommon::new(runtime, mock_stun(), sink.clone());

        common.select_listener(false, false).await.unwrap();

        for _ in 0..10 {
            if sink.server_tunnels.load(Ordering::Relaxed) == 1 {
                return;
            }
            tokio::task::yield_now().await;
        }

        assert_eq!(sink.server_tunnels.load(Ordering::Relaxed), 1);
    }

    #[tokio::test]
    async fn selected_listener_observes_first_packet_before_cone_rpc_arrives() {
        let runtime = Arc::new(MockRuntime::new(vec![listener(10002, Vec::new())]));
        let server = UdpHolePunchServer::new(
            runtime,
            mock_stun(),
            Arc::new(MockSink::default()),
            UdpSymPunchLock::default(),
        );
        server.start().await;
        let selected = server
            .select_punch_listener(SelectPunchListener {
                force_new: false,
                prefer_port_mapping: false,
                transaction_id: Some(0),
            })
            .await
            .unwrap();
        assert_eq!(selected.transaction_id, Some(0));
        let socket = server
            .common
            .find_listener(&selected.listener_mapped_addr)
            .await
            .unwrap();
        let source = SocketAddr::from(([198, 51, 100, 1], 33140));
        socket.incoming.lock().unwrap().push_back((
            new_hole_punch_packet(0, HOLE_PUNCH_PACKET_BODY_LEN)
                .into_bytes()
                .to_vec(),
            source,
        ));
        socket.incoming_notify.notify_one();
        tokio::time::timeout(Duration::from_secs(1), async {
            while !socket.incoming.lock().unwrap().is_empty() {
                tokio::task::yield_now().await;
            }
        })
        .await
        .unwrap();
        let dest_addr = SocketAddr::from(([198, 51, 100, 1], 33105));
        server
            .send_punch_packet_cone(SendPunchPacketCone {
                listener_mapped_addr: selected.listener_mapped_addr,
                dest_addr,
                transaction_id: 0,
                packet_count_per_batch: 2,
                packet_batch_count: 1,
                packet_interval_ms: 0,
            })
            .await
            .unwrap();
        let sent = socket.sent.lock().await;
        assert_eq!(sent.len(), 4);
        assert_eq!(
            sent.iter().filter(|(_, addr)| *addr == dest_addr).count(),
            2
        );
        assert_eq!(sent.iter().filter(|(_, addr)| *addr == source).count(), 2);
        drop(sent);
        server.stop().await;
    }

    #[tokio::test(start_paused = true)]
    async fn cleanup_expires_abandoned_listener_registration() {
        let runtime = Arc::new(MockRuntime::new(vec![listener(10002, Vec::new())]));
        let server = UdpHolePunchServer::new(
            runtime,
            mock_stun(),
            Arc::new(MockSink::default()),
            UdpSymPunchLock::default(),
        );
        server.start().await;
        let selected = server
            .select_punch_listener(SelectPunchListener {
                force_new: false,
                prefer_port_mapping: false,
                transaction_id: Some(9),
            })
            .await
            .unwrap();
        assert!(
            server
                .common
                .prepare_hole_punch(&selected.listener_mapped_addr, 9)
                .await
                .is_err()
        );
        // Let the existing periodic cleanup run as the paused clock advances.
        crate::foundation::time::sleep(PREPARED_CONE_PUNCH_TIMEOUT + Duration::from_secs(5)).await;
        server
            .common
            .prepare_hole_punch(&selected.listener_mapped_addr, 9)
            .await
            .unwrap();
        server.stop().await;
    }

    #[tokio::test]
    async fn cone_sender_adds_observed_source_during_last_batch_and_deduplicates() {
        let runtime = Arc::new(MockRuntime::new(vec![listener(10002, Vec::new())]));
        let server = UdpHolePunchServer::new(
            runtime,
            mock_stun(),
            Arc::new(MockSink::default()),
            UdpSymPunchLock::default(),
        );
        server.start().await;
        let selected = server
            .select_punch_listener(SelectPunchListener {
                force_new: false,
                prefer_port_mapping: false,
                transaction_id: None,
            })
            .await
            .unwrap();
        let socket = server
            .common
            .find_listener(&selected.listener_mapped_addr)
            .await
            .unwrap();
        let request = SendPunchPacketCone {
            listener_mapped_addr: selected.listener_mapped_addr,
            dest_addr: SocketAddr::from(([198, 51, 100, 1], 33105)),
            transaction_id: 9,
            packet_count_per_batch: 2,
            packet_batch_count: 1,
            packet_interval_ms: 100,
        };
        for observed_addr in [
            SocketAddr::from(([198, 51, 100, 1], 33140)),
            request.dest_addr,
        ] {
            socket.sent.lock().await.clear();
            let send = server.send_punch_packet_cone(request.clone());
            let observe = async {
                loop {
                    if socket.sent.lock().await.len() == 2 {
                        break;
                    }
                    tokio::task::yield_now().await;
                }
                socket.incoming.lock().unwrap().push_back((
                    new_hole_punch_packet(request.transaction_id, HOLE_PUNCH_PACKET_BODY_LEN)
                        .into_bytes()
                        .to_vec(),
                    observed_addr,
                ));
                socket.incoming_notify.notify_one();
            };
            let (result, _) = tokio::time::timeout(Duration::from_secs(2), async {
                tokio::join!(send, observe)
            })
            .await
            .unwrap();
            result.unwrap();
            let sent = socket.sent.lock().await;
            let expected_count = if observed_addr == request.dest_addr {
                2
            } else {
                4
            };
            assert_eq!(sent.len(), expected_count);
            assert_eq!(
                sent.iter()
                    .filter(|(_, addr)| *addr == request.dest_addr)
                    .count(),
                2
            );
            for (packet, _) in sent.iter() {
                assert_eq!(
                    crate::packet::hole_punch_packet_tid(packet, HOLE_PUNCH_PACKET_BODY_LEN),
                    Some(request.transaction_id)
                );
            }
            if observed_addr != request.dest_addr {
                assert_eq!(
                    sent.iter()
                        .filter(|(_, addr)| *addr == observed_addr)
                        .count(),
                    2
                );
            }
        }
        let (_, observer) = server
            .common
            .observe_hole_punch(&request.listener_mapped_addr, request.transaction_id)
            .await
            .unwrap();
        assert_eq!(observer.source_addr(), None);
        drop(observer);
        server.stop().await;
    }

    #[tokio::test]
    async fn cancelling_cone_sender_unregisters_observed_source() {
        let socket = Arc::new(MockSocket {
            local_addr: SocketAddr::from(([127, 0, 0, 1], 10002)),
            sent: tokio::sync::Mutex::new(Vec::new()),
            fail_next_send: AtomicUsize::new(0),
            incoming: StdMutex::new(VecDeque::new()),
            incoming_notify: tokio::sync::Notify::new(),
        });
        let layer = crate::socket::udp::UdpSessionLayer::new(socket.clone());
        let request = SendPunchPacketCone {
            listener_mapped_addr: SocketAddr::from(([203, 0, 113, 1], 10002)),
            dest_addr: SocketAddr::from(([198, 51, 100, 1], 33105)),
            transaction_id: 9,
            packet_count_per_batch: 2,
            packet_batch_count: 5,
            packet_interval_ms: 400,
        };
        let observer = layer
            .hole_punch_observers()
            .observe(request.transaction_id)
            .unwrap();
        let send_socket = socket.clone();
        let task = tokio::spawn(async move {
            send_cone_hole_punch_packets(send_socket, &request, observer).await
        });
        while socket.sent.lock().await.is_empty() {
            tokio::task::yield_now().await;
        }
        task.abort();
        assert!(task.await.unwrap_err().is_cancelled());
        assert_eq!(
            layer
                .hole_punch_observers()
                .observe(9)
                .unwrap()
                .source_addr(),
            None
        );
    }

    #[tokio::test]
    async fn cone_packet_sender_keeps_old_batch_shape() {
        let socket = Arc::new(MockSocket {
            local_addr: SocketAddr::from(([127, 0, 0, 1], 10002)),
            sent: tokio::sync::Mutex::new(Vec::new()),
            fail_next_send: AtomicUsize::new(0),
            incoming: StdMutex::new(VecDeque::new()),
            incoming_notify: tokio::sync::Notify::new(),
        });
        let request = SendPunchPacketCone {
            listener_mapped_addr: SocketAddr::from(([203, 0, 113, 1], 10002)),
            dest_addr: SocketAddr::from(([198, 51, 100, 1], 20000)),
            transaction_id: 9,
            packet_count_per_batch: 2,
            packet_batch_count: 3,
            packet_interval_ms: 0,
        };

        let layer = crate::socket::udp::UdpSessionLayer::new(socket.clone());
        let observer = layer
            .hole_punch_observers()
            .observe(request.transaction_id)
            .unwrap();
        send_cone_hole_punch_packets(socket.clone(), &request, observer)
            .await
            .unwrap();

        let sent = socket.sent.lock().await;
        assert_eq!(sent.len(), 6);
        assert!(sent.iter().all(|(_, addr)| *addr == request.dest_addr));
    }

    #[tokio::test]
    async fn cone_packet_sender_rejects_malformed_dest_ip() {
        let socket = Arc::new(MockSocket {
            local_addr: SocketAddr::from(([127, 0, 0, 1], 10004)),
            sent: tokio::sync::Mutex::new(Vec::new()),
            fail_next_send: AtomicUsize::new(0),
            incoming: StdMutex::new(VecDeque::new()),
            incoming_notify: tokio::sync::Notify::new(),
        });
        let request = SendPunchPacketCone {
            listener_mapped_addr: SocketAddr::from(([203, 0, 113, 1], 10004)),
            dest_addr: SocketAddr::from(([0, 0, 0, 0], 20000)),
            transaction_id: 9,
            packet_count_per_batch: 2,
            packet_batch_count: 3,
            packet_interval_ms: 0,
        };

        let layer = crate::socket::udp::UdpSessionLayer::new(socket.clone());
        let observer = layer
            .hole_punch_observers()
            .observe(request.transaction_id)
            .unwrap();
        let err = send_cone_hole_punch_packets(socket.clone(), &request, observer)
            .await
            .unwrap_err();

        assert!(err.to_string().contains("dest_ip is malformed"));
        assert!(socket.sent.lock().await.is_empty());
    }

    #[tokio::test]
    async fn cone_packet_sender_continues_after_send_error() {
        let socket = Arc::new(MockSocket {
            local_addr: SocketAddr::from(([127, 0, 0, 1], 10005)),
            sent: tokio::sync::Mutex::new(Vec::new()),
            fail_next_send: AtomicUsize::new(1),
            incoming: StdMutex::new(VecDeque::new()),
            incoming_notify: tokio::sync::Notify::new(),
        });
        let request = SendPunchPacketCone {
            listener_mapped_addr: SocketAddr::from(([203, 0, 113, 1], 10005)),
            dest_addr: SocketAddr::from(([198, 51, 100, 1], 20000)),
            transaction_id: 9,
            packet_count_per_batch: 2,
            packet_batch_count: 1,
            packet_interval_ms: 0,
        };

        let layer = crate::socket::udp::UdpSessionLayer::new(socket.clone());
        let observer = layer
            .hole_punch_observers()
            .observe(request.transaction_id)
            .unwrap();
        send_cone_hole_punch_packets(socket.clone(), &request, observer)
            .await
            .unwrap();

        let sent = socket.sent.lock().await;
        assert_eq!(sent.len(), 1);
    }

    #[tokio::test]
    async fn symmetric_packet_sender_returns_next_port_index() {
        let socket = Arc::new(MockSocket {
            local_addr: SocketAddr::from(([127, 0, 0, 1], 10003)),
            sent: tokio::sync::Mutex::new(Vec::new()),
            fail_next_send: AtomicUsize::new(0),
            incoming: StdMutex::new(VecDeque::new()),
            incoming_notify: tokio::sync::Notify::new(),
        });
        let next_idx = send_symmetric_hole_punch_packet(
            &[10, 11, 12],
            socket.clone(),
            9,
            &[Ipv4Addr::new(198, 51, 100, 1)],
            1,
            2,
        )
        .await
        .unwrap();

        assert_eq!(next_idx, 0);
        let sent = socket.sent.lock().await;
        assert_eq!(sent.len(), 6);
        assert_eq!(sent[0].1, SocketAddr::from(([198, 51, 100, 1], 11)));
        assert_eq!(sent[3].1, SocketAddr::from(([198, 51, 100, 1], 12)));
    }

    #[tokio::test]
    async fn symmetric_packet_sender_returns_send_error() {
        let socket = Arc::new(MockSocket {
            local_addr: SocketAddr::from(([127, 0, 0, 1], 10006)),
            sent: tokio::sync::Mutex::new(Vec::new()),
            fail_next_send: AtomicUsize::new(1),
            incoming: StdMutex::new(VecDeque::new()),
            incoming_notify: tokio::sync::Notify::new(),
        });

        let err = send_symmetric_hole_punch_packet(
            &[10],
            socket.clone(),
            9,
            &[Ipv4Addr::new(198, 51, 100, 1)],
            0,
            1,
        )
        .await
        .unwrap_err();

        assert!(err.to_string().contains("mock send failure"));
        assert!(socket.sent.lock().await.is_empty());
    }

    #[tokio::test]
    async fn both_easy_sym_server_reports_busy_while_task_running() {
        let runtime = Arc::new(MockRuntime::new(Vec::new()));
        let sink = Arc::new(MockSink::default());
        let common = Arc::new(UdpHolePunchServerCommon::new(runtime, mock_stun(), sink));
        let server = UdpBothEasySymPunchServer::new(common);
        let request = SendPunchPacketBothEasySym {
            udp_socket_count: 1,
            public_ip: Ipv4Addr::new(198, 51, 100, 1),
            transaction_id: 9,
            dst_port_num: 20000,
            wait_time_ms: 500,
        };

        let first_response = server
            .send_punch_packet_both_easy_sym(request.clone())
            .await
            .unwrap();
        assert!(!first_response.is_busy);
        assert_eq!(
            first_response.base_mapped_addr,
            Some(SocketAddr::from(([203, 0, 113, 1], 10000)))
        );

        let busy_response = server
            .send_punch_packet_both_easy_sym(request)
            .await
            .unwrap();
        assert!(busy_response.is_busy);
        assert!(busy_response.base_mapped_addr.is_none());
    }
}
