use std::{
    net::{IpAddr, SocketAddr},
    sync::{
        Arc, Weak,
        atomic::{AtomicBool, Ordering},
    },
    time::Duration,
};

use bytes::Bytes;
use dashmap::{DashMap, mapref::entry::Entry};
use tokio::sync::Notify;
use tokio_util::task::AbortOnDropHandle;

use crate::{
    foundation::time,
    socket::udp::{UdpBindOptions, VirtualUdpSocket, VirtualUdpSocketFactory},
};

use super::{
    traits::{
        ProxyRuntimeError, ProxyRuntimeInfo, ProxyRuntimeSnapshot, UdpProxyPolicy,
        UdpProxyResponseSink, UdpProxyRuntime,
    },
    udp_proxy_engine::UdpNatEntryId,
};

const UDP_PROXY_RECEIVE_BUFFER_SIZE: usize = 64 * 1024;

struct UdpSocketNatEntry<S>
where
    S: VirtualUdpSocket,
{
    socket: Arc<S>,
    receive_task: std::sync::Mutex<Option<AbortOnDropHandle<()>>>,
    closed: AtomicBool,
}

struct UdpSocketEntryState<S>
where
    S: VirtualUdpSocket,
{
    entry: Option<Arc<UdpSocketNatEntry<S>>>,
    error: Option<String>,
}

struct UdpSocketEntrySlot<S>
where
    S: VirtualUdpSocket,
{
    state: std::sync::Mutex<UdpSocketEntryState<S>>,
    changed: Notify,
    closed: AtomicBool,
}

impl<S> UdpSocketEntrySlot<S>
where
    S: VirtualUdpSocket,
{
    fn new() -> Arc<Self> {
        Arc::new(Self {
            state: std::sync::Mutex::new(UdpSocketEntryState {
                entry: None,
                error: None,
            }),
            changed: Notify::new(),
            closed: AtomicBool::new(false),
        })
    }

    async fn wait_for_entry(&self) -> Result<Arc<UdpSocketNatEntry<S>>, ProxyRuntimeError> {
        loop {
            let changed = self.changed.notified();
            {
                let state = self.state.lock().unwrap();
                if let Some(entry) = &state.entry {
                    return Ok(entry.clone());
                }
                if let Some(error) = &state.error {
                    return Err(ProxyRuntimeError::Other(anyhow::anyhow!(error.clone())));
                }
                if self.closed.load(Ordering::Acquire) {
                    return Err(ProxyRuntimeError::Other(anyhow::anyhow!(
                        "UDP proxy socket entry was closed while being created"
                    )));
                }
            }
            changed.await;
        }
    }

    fn fail(&self, error: &ProxyRuntimeError) {
        self.state.lock().unwrap().error = Some(error.to_string());
        self.changed.notify_waiters();
    }

    fn cancel_creation(&self) {
        self.closed.store(true, Ordering::Release);
        self.state.lock().unwrap().error =
            Some("UDP proxy socket creation was cancelled".to_owned());
        self.changed.notify_waiters();
    }

    fn close(&self) {
        self.closed.store(true, Ordering::Release);
        if let Some(entry) = self.state.lock().unwrap().entry.take() {
            entry.stop();
        }
        self.changed.notify_waiters();
    }
}

fn remove_entry_slot<S>(
    entries: &DashMap<UdpNatEntryId, Arc<UdpSocketEntrySlot<S>>>,
    entry_id: UdpNatEntryId,
    slot: &Arc<UdpSocketEntrySlot<S>>,
) where
    S: VirtualUdpSocket,
{
    if let Entry::Occupied(entry) = entries.entry(entry_id)
        && Arc::ptr_eq(entry.get(), slot)
    {
        entry.remove();
    }
}

struct UdpSocketCreationGuard<S>
where
    S: VirtualUdpSocket,
{
    entries: Arc<DashMap<UdpNatEntryId, Arc<UdpSocketEntrySlot<S>>>>,
    entry_id: UdpNatEntryId,
    slot: Arc<UdpSocketEntrySlot<S>>,
    armed: bool,
}

impl<S> UdpSocketCreationGuard<S>
where
    S: VirtualUdpSocket,
{
    fn new(
        entries: Arc<DashMap<UdpNatEntryId, Arc<UdpSocketEntrySlot<S>>>>,
        entry_id: UdpNatEntryId,
        slot: Arc<UdpSocketEntrySlot<S>>,
    ) -> Self {
        Self {
            entries,
            entry_id,
            slot,
            armed: true,
        }
    }

    fn disarm(&mut self) {
        self.armed = false;
    }
}

impl<S> Drop for UdpSocketCreationGuard<S>
where
    S: VirtualUdpSocket,
{
    fn drop(&mut self) {
        if !self.armed {
            return;
        }
        self.slot.cancel_creation();
        remove_entry_slot(&self.entries, self.entry_id, &self.slot);
    }
}

impl<S> UdpSocketNatEntry<S>
where
    S: VirtualUdpSocket,
{
    fn new(socket: Arc<S>) -> Arc<Self> {
        Arc::new(Self {
            socket,
            receive_task: std::sync::Mutex::new(None),
            closed: AtomicBool::new(false),
        })
    }

    fn start_receive_task(
        self: &Arc<Self>,
        entry_id: UdpNatEntryId,
        response_sink: Weak<dyn UdpProxyResponseSink>,
        receive_timeout: Duration,
    ) {
        if self.closed.load(Ordering::Acquire) {
            return;
        }

        let socket = self.socket.clone();
        let task = AbortOnDropHandle::new(tokio::spawn(async move {
            loop {
                let mut buffer = vec![0; UDP_PROXY_RECEIVE_BUFFER_SIZE];
                let (length, source) =
                    match time::timeout(receive_timeout, socket.recv_from(&mut buffer)).await {
                        Ok(Ok(received)) => received,
                        Ok(Err(error)) => {
                            tracing::error!(?error, ?entry_id, "UDP proxy receive failed");
                            break;
                        }
                        Err(error) => {
                            tracing::error!(?error, ?entry_id, "UDP proxy receive timed out");
                            break;
                        }
                    };

                let Some(response_sink) = response_sink.upgrade() else {
                    break;
                };
                response_sink
                    .handle_socket_response(
                        entry_id,
                        source,
                        Bytes::copy_from_slice(&buffer[..length]),
                    )
                    .await;
            }
        }));

        let mut receive_task = self.receive_task.lock().unwrap();
        if self.closed.load(Ordering::Acquire) {
            drop(task);
        } else {
            receive_task.replace(task);
        }
    }

    fn stop(&self) {
        self.closed.store(true, Ordering::Release);
        self.receive_task.lock().unwrap().take();
    }
}

pub struct UdpSocketProxyRuntime<F, P>
where
    F: VirtualUdpSocketFactory,
    P: UdpProxyPolicy,
{
    factory: Arc<F>,
    policy: Arc<P>,
    bind_options: UdpBindOptions,
    receive_timeout: Duration,
    entries: Arc<DashMap<UdpNatEntryId, Arc<UdpSocketEntrySlot<F::Socket>>>>,
    closing: AtomicBool,
}

impl<F, P> UdpSocketProxyRuntime<F, P>
where
    F: VirtualUdpSocketFactory,
    P: UdpProxyPolicy,
{
    pub fn new(
        factory: Arc<F>,
        policy: Arc<P>,
        bind_options: UdpBindOptions,
        receive_timeout: Duration,
    ) -> Self {
        Self {
            factory,
            policy,
            bind_options,
            receive_timeout,
            entries: Arc::new(DashMap::new()),
            closing: AtomicBool::new(false),
        }
    }

    async fn ensure_socket_entry(
        &self,
        entry_id: UdpNatEntryId,
        response_sink: Weak<dyn UdpProxyResponseSink>,
    ) -> Result<Arc<UdpSocketNatEntry<F::Socket>>, ProxyRuntimeError> {
        if self.closing.load(Ordering::Acquire) {
            return Err(ProxyRuntimeError::Other(anyhow::anyhow!(
                "UDP proxy runtime is closing"
            )));
        }

        let (slot, create) = match self.entries.entry(entry_id) {
            Entry::Occupied(entry) => (entry.get().clone(), false),
            Entry::Vacant(entry) => {
                let slot = UdpSocketEntrySlot::new();
                entry.insert(slot.clone());
                (slot, true)
            }
        };
        if self.closing.load(Ordering::Acquire) {
            slot.close();
            self.remove_slot(entry_id, &slot);
            return Err(ProxyRuntimeError::Other(anyhow::anyhow!(
                "UDP proxy runtime is closing"
            )));
        }
        if !create {
            return slot.wait_for_entry().await;
        }

        let mut creation =
            UdpSocketCreationGuard::new(self.entries.clone(), entry_id, slot.clone());

        let socket = match self.factory.bind_udp(self.bind_options.clone()).await {
            Ok(socket) => socket,
            Err(error) => {
                let error = ProxyRuntimeError::Other(error);
                slot.fail(&error);
                self.remove_slot(entry_id, &slot);
                creation.disarm();
                return Err(error);
            }
        };
        let candidate = UdpSocketNatEntry::new(socket);
        {
            let mut state = slot.state.lock().unwrap();
            if slot.closed.load(Ordering::Acquire) || self.closing.load(Ordering::Acquire) {
                candidate.stop();
                drop(state);
                slot.changed.notify_waiters();
                self.remove_slot(entry_id, &slot);
                creation.disarm();
                return Err(ProxyRuntimeError::Other(anyhow::anyhow!(
                    "UDP proxy socket entry was closed while being created"
                )));
            }
            candidate.start_receive_task(entry_id, response_sink, self.receive_timeout);
            state.entry = Some(candidate.clone());
        }
        slot.changed.notify_waiters();
        creation.disarm();
        Ok(candidate)
    }

    fn remove_slot(&self, entry_id: UdpNatEntryId, slot: &Arc<UdpSocketEntrySlot<F::Socket>>) {
        remove_entry_slot(&self.entries, entry_id, slot);
    }

    pub fn close_all(&self) {
        self.closing.store(true, Ordering::Release);
        for slot in self.entries.iter() {
            slot.close();
        }
        self.entries.clear();
        self.entries.shrink_to_fit();
    }
}

impl<F, P> ProxyRuntimeInfo for UdpSocketProxyRuntime<F, P>
where
    F: VirtualUdpSocketFactory,
    P: UdpProxyPolicy,
{
    fn proxy_runtime_snapshot(&self) -> ProxyRuntimeSnapshot {
        self.policy.proxy_runtime_snapshot()
    }

    fn is_ip_local_virtual_ip(&self, ip: &IpAddr) -> bool {
        self.policy.is_ip_local_virtual_ip(ip)
    }
}

#[async_trait::async_trait]
impl<F, P> UdpProxyRuntime for UdpSocketProxyRuntime<F, P>
where
    F: VirtualUdpSocketFactory,
    P: UdpProxyPolicy,
{
    fn should_deny_udp_proxy(&self, dst: SocketAddr) -> bool {
        self.policy.should_deny_udp_proxy(dst)
    }

    fn udp_response_ipv4_mtu(&self) -> usize {
        self.policy.udp_response_ipv4_mtu()
    }

    async fn send_udp_to_socket(
        &self,
        entry_id: UdpNatEntryId,
        dst: SocketAddr,
        payload: Bytes,
        response_sink: Weak<dyn UdpProxyResponseSink>,
    ) -> Result<(), ProxyRuntimeError> {
        let entry = self.ensure_socket_entry(entry_id, response_sink).await?;
        if entry.closed.load(Ordering::Acquire) {
            return Err(ProxyRuntimeError::Other(anyhow::anyhow!(
                "UDP proxy socket entry is closed"
            )));
        }
        entry.socket.send_to(&payload, dst).await?;
        Ok(())
    }

    fn close_udp_socket(&self, entry_id: UdpNatEntryId) {
        if let Some((_, slot)) = self.entries.remove(&entry_id) {
            slot.close();
        }
        self.entries.shrink_to_fit();
    }
}

impl<F, P> Drop for UdpSocketProxyRuntime<F, P>
where
    F: VirtualUdpSocketFactory,
    P: UdpProxyPolicy,
{
    fn drop(&mut self) {
        self.close_all();
    }
}

#[cfg(test)]
mod tests {
    use std::{
        io,
        net::Ipv4Addr,
        sync::atomic::{AtomicUsize, Ordering as AtomicOrdering},
    };

    use super::*;
    use crate::socket::udp::UdpSocketPurpose;

    #[derive(Default)]
    struct RecordingSocket {
        sent: std::sync::Mutex<Vec<(Vec<u8>, SocketAddr)>>,
    }

    #[async_trait::async_trait]
    impl VirtualUdpSocket for RecordingSocket {
        fn local_addr(&self) -> io::Result<SocketAddr> {
            Ok("127.0.0.1:40000".parse().unwrap())
        }

        async fn send_to(&self, data: &[u8], addr: SocketAddr) -> io::Result<usize> {
            self.sent.lock().unwrap().push((data.to_vec(), addr));
            Ok(data.len())
        }

        async fn recv_from(&self, _buf: &mut [u8]) -> io::Result<(usize, SocketAddr)> {
            std::future::pending().await
        }
    }

    #[derive(Default)]
    struct RecordingFactory {
        options: std::sync::Mutex<Vec<UdpBindOptions>>,
        socket: Arc<RecordingSocket>,
    }

    #[async_trait::async_trait]
    impl VirtualUdpSocketFactory for RecordingFactory {
        type Socket = RecordingSocket;

        async fn bind_udp(&self, options: UdpBindOptions) -> anyhow::Result<Arc<Self::Socket>> {
            self.options.lock().unwrap().push(options);
            Ok(self.socket.clone())
        }
    }

    #[derive(Default)]
    struct DelayedFactory {
        socket: Arc<RecordingSocket>,
        bind_calls: AtomicUsize,
        bind_started: Notify,
        release_bind: Notify,
    }

    #[async_trait::async_trait]
    impl VirtualUdpSocketFactory for DelayedFactory {
        type Socket = RecordingSocket;

        async fn bind_udp(&self, _options: UdpBindOptions) -> anyhow::Result<Arc<Self::Socket>> {
            self.bind_calls.fetch_add(1, AtomicOrdering::AcqRel);
            self.bind_started.notify_one();
            self.release_bind.notified().await;
            Ok(self.socket.clone())
        }
    }

    struct TestPolicy;

    impl ProxyRuntimeInfo for TestPolicy {
        fn proxy_runtime_snapshot(&self) -> ProxyRuntimeSnapshot {
            ProxyRuntimeSnapshot::default()
        }

        fn is_ip_local_virtual_ip(&self, _ip: &IpAddr) -> bool {
            false
        }
    }

    impl UdpProxyPolicy for TestPolicy {
        fn should_deny_udp_proxy(&self, _dst: SocketAddr) -> bool {
            false
        }

        fn udp_response_ipv4_mtu(&self) -> usize {
            1280
        }
    }

    struct NoopResponseSink;

    #[async_trait::async_trait]
    impl UdpProxyResponseSink for NoopResponseSink {
        async fn handle_socket_response(
            &self,
            _entry_id: UdpNatEntryId,
            _src: SocketAddr,
            _payload: Bytes,
        ) {
        }
    }

    #[tokio::test]
    async fn reuses_one_host_socket_per_nat_entry_and_recreates_after_close() {
        let factory = Arc::new(RecordingFactory::default());
        let runtime = UdpSocketProxyRuntime::new(
            factory.clone(),
            Arc::new(TestPolicy),
            UdpBindOptions::proxy_nat(),
            Duration::from_secs(120),
        );
        let sink: Arc<dyn UdpProxyResponseSink> = Arc::new(NoopResponseSink);
        let entry_id = UdpNatEntryId::new();
        let destination = SocketAddr::from((Ipv4Addr::LOCALHOST, 53));

        runtime
            .send_udp_to_socket(
                entry_id,
                destination,
                Bytes::from_static(b"first"),
                Arc::downgrade(&sink),
            )
            .await
            .unwrap();
        runtime
            .send_udp_to_socket(
                entry_id,
                destination,
                Bytes::from_static(b"second"),
                Arc::downgrade(&sink),
            )
            .await
            .unwrap();

        assert_eq!(factory.options.lock().unwrap().len(), 1);
        assert_eq!(
            factory.options.lock().unwrap()[0].purpose,
            UdpSocketPurpose::ProxyNat
        );
        assert_eq!(factory.socket.sent.lock().unwrap().len(), 2);

        runtime.close_udp_socket(entry_id);
        runtime
            .send_udp_to_socket(
                entry_id,
                destination,
                Bytes::from_static(b"third"),
                Arc::downgrade(&sink),
            )
            .await
            .unwrap();
        assert_eq!(factory.options.lock().unwrap().len(), 2);
    }

    #[tokio::test]
    async fn close_all_cancels_an_inflight_socket_creation() {
        let factory = Arc::new(DelayedFactory::default());
        let runtime = Arc::new(UdpSocketProxyRuntime::new(
            factory.clone(),
            Arc::new(TestPolicy),
            UdpBindOptions::proxy_nat(),
            Duration::from_secs(120),
        ));
        let sink: Arc<dyn UdpProxyResponseSink> = Arc::new(NoopResponseSink);
        let entry_id = UdpNatEntryId::new();
        let destination = SocketAddr::from((Ipv4Addr::LOCALHOST, 53));
        let send_task = tokio::spawn({
            let runtime = runtime.clone();
            let sink = Arc::downgrade(&sink);
            async move {
                runtime
                    .send_udp_to_socket(entry_id, destination, Bytes::from_static(b"request"), sink)
                    .await
            }
        });

        factory.bind_started.notified().await;
        runtime.close_all();
        factory.release_bind.notify_one();

        let error = send_task.await.unwrap().unwrap_err();
        assert!(error.to_string().contains("closed while being created"));
        assert_eq!(factory.bind_calls.load(AtomicOrdering::Acquire), 1);
        assert!(factory.socket.sent.lock().unwrap().is_empty());
        assert!(runtime.entries.is_empty());
    }

    #[tokio::test]
    async fn cancelled_creator_releases_the_slot_for_retry() {
        let factory = Arc::new(DelayedFactory::default());
        let runtime = Arc::new(UdpSocketProxyRuntime::new(
            factory.clone(),
            Arc::new(TestPolicy),
            UdpBindOptions::proxy_nat(),
            Duration::from_secs(120),
        ));
        let sink: Arc<dyn UdpProxyResponseSink> = Arc::new(NoopResponseSink);
        let entry_id = UdpNatEntryId::new();
        let destination = SocketAddr::from((Ipv4Addr::LOCALHOST, 53));
        let first_send = tokio::spawn({
            let runtime = runtime.clone();
            let sink = Arc::downgrade(&sink);
            async move {
                runtime
                    .send_udp_to_socket(entry_id, destination, Bytes::from_static(b"first"), sink)
                    .await
            }
        });

        factory.bind_started.notified().await;
        first_send.abort();
        assert!(first_send.await.unwrap_err().is_cancelled());

        let retry = tokio::spawn({
            let runtime = runtime.clone();
            let sink = Arc::downgrade(&sink);
            async move {
                runtime
                    .send_udp_to_socket(entry_id, destination, Bytes::from_static(b"retry"), sink)
                    .await
            }
        });
        factory.bind_started.notified().await;
        factory.release_bind.notify_one();

        time::timeout(Duration::from_secs(1), retry)
            .await
            .unwrap()
            .unwrap()
            .unwrap();
        assert_eq!(factory.bind_calls.load(AtomicOrdering::Acquire), 2);
        assert_eq!(factory.socket.sent.lock().unwrap().len(), 1);
    }
}
