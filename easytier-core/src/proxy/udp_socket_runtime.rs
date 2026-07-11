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
use tokio_util::task::AbortOnDropHandle;

use crate::socket::udp::{UdpBindOptions, VirtualUdpSocket, VirtualUdpSocketFactory};

use super::{
    runtime::{
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
        let task =
            AbortOnDropHandle::new(tokio::spawn(async move {
                loop {
                    let mut buffer = vec![0; UDP_PROXY_RECEIVE_BUFFER_SIZE];
                    let (length, source) =
                        match tokio::time::timeout(receive_timeout, socket.recv_from(&mut buffer))
                            .await
                        {
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
    entries: DashMap<UdpNatEntryId, Arc<UdpSocketNatEntry<F::Socket>>>,
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
            entries: DashMap::new(),
        }
    }

    async fn ensure_socket_entry(
        &self,
        entry_id: UdpNatEntryId,
        response_sink: Weak<dyn UdpProxyResponseSink>,
    ) -> Result<Arc<UdpSocketNatEntry<F::Socket>>, ProxyRuntimeError> {
        if let Some(entry) = self.entries.get(&entry_id) {
            return Ok(entry.clone());
        }

        let socket = self.factory.bind_udp(self.bind_options.clone()).await?;
        let candidate = UdpSocketNatEntry::new(socket);
        let entry = match self.entries.entry(entry_id) {
            Entry::Occupied(entry) => entry.get().clone(),
            Entry::Vacant(entry) => {
                entry.insert(candidate.clone());
                candidate.start_receive_task(entry_id, response_sink, self.receive_timeout);
                candidate
            }
        };
        Ok(entry)
    }

    pub fn close_all(&self) {
        for entry in self.entries.iter() {
            entry.stop();
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
        if let Some((_, entry)) = self.entries.remove(&entry_id) {
            entry.stop();
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
    use std::{io, net::Ipv4Addr};

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
}
