use std::{io, sync::Weak};

use tokio::sync::{Notify, mpsc, oneshot};

use super::*;
use crate::{
    config::{IpPrefix, peers::PeerRuntimeSnapshot, runtime::CoreRuntimeConfig},
    host::{
        packet::{HostPacketReceiver, host_packet_channel},
        testkit::TestHost,
    },
    peers::peer_manager::{PeerManagerCore, PortablePeerManagerConfig},
    socket::tcp::TcpConnectOptions,
};

type Datagram = (Vec<u8>, SocketAddr);

struct ReloadUdpSocket {
    address: SocketAddr,
    incoming: Option<Mutex<mpsc::UnboundedReceiver<Datagram>>>,
    sent: mpsc::UnboundedSender<Datagram>,
}

#[async_trait::async_trait]
impl VirtualUdpSocket for ReloadUdpSocket {
    fn local_addr(&self) -> io::Result<SocketAddr> {
        Ok(self.address)
    }

    async fn send_to(&self, data: &[u8], address: SocketAddr) -> io::Result<usize> {
        self.sent.send((data.to_vec(), address)).unwrap();
        Ok(data.len())
    }

    async fn recv_from(&self, buf: &mut [u8]) -> io::Result<(usize, SocketAddr)> {
        let Some(incoming) = &self.incoming else {
            return std::future::pending().await;
        };
        let (data, address) = incoming.lock().await.recv().await.unwrap();
        buf[..data.len()].copy_from_slice(&data);
        Ok((data.len(), address))
    }
}

struct ReloadUdpHost {
    incoming: std::sync::Mutex<Option<mpsc::UnboundedReceiver<Datagram>>>,
    sent: mpsc::UnboundedSender<Datagram>,
    sockets: std::sync::Mutex<Vec<Weak<ReloadUdpSocket>>>,
    open_started: Notify,
    open_release: std::sync::Mutex<Option<oneshot::Receiver<()>>>,
}

#[async_trait::async_trait]
impl VirtualTcpSocketFactory for ReloadUdpHost {
    type Socket = <TestHost as VirtualTcpSocketFactory>::Socket;

    async fn connect_tcp(&self, options: TcpConnectOptions) -> anyhow::Result<Self::Socket> {
        TestHost::default().connect_tcp(options).await
    }
}

#[async_trait::async_trait]
impl VirtualTcpListenerFactory for ReloadUdpHost {
    type Listener = <TestHost as VirtualTcpListenerFactory>::Listener;

    async fn bind_tcp(&self, options: TcpListenOptions) -> anyhow::Result<Arc<Self::Listener>> {
        TestHost::default().bind_tcp(options).await
    }
}

#[async_trait::async_trait]
impl VirtualUdpSocketFactory for ReloadUdpHost {
    type Socket = ReloadUdpSocket;

    async fn bind_udp(&self, options: UdpBindOptions) -> anyhow::Result<Arc<Self::Socket>> {
        let address = options.local_addr.unwrap();
        let incoming = if address.port() != 0 {
            self.incoming.lock().unwrap().take().map(Mutex::new)
        } else {
            let release = self.open_release.lock().unwrap().take();
            if let Some(release) = release {
                self.open_started.notify_one();
                release.await.unwrap();
            }
            None
        };
        let socket = Arc::new(ReloadUdpSocket {
            address,
            incoming,
            sent: self.sent.clone(),
        });
        self.sockets.lock().unwrap().push(Arc::downgrade(&socket));
        Ok(socket)
    }
}

struct UdpReloadTest {
    adapter: Arc<PortForwardAdapter<ReloadUdpHost>>,
    host: Arc<ReloadUdpHost>,
    incoming: mpsc::UnboundedSender<Datagram>,
    sent: mpsc::UnboundedReceiver<Datagram>,
    _peer_manager: Arc<PeerManagerCore>,
    _packets: HostPacketReceiver,
}

impl UdpReloadTest {
    async fn new() -> Self {
        let mut runtime = PeerRuntimeSnapshot::default().runtime;
        runtime.core.routes.ipv4 = Some(IpPrefix::new("10.144.0.2".parse().unwrap(), 24).unwrap());
        let peer_config = PortablePeerManagerConfig::new(runtime);
        let runtime_config = CoreRuntimeConfigStore::new(
            CoreRuntimeConfig::default(),
            Arc::new(peer_config.snapshot.clone()),
        );
        let (packet_sender, packets) = host_packet_channel();
        let peer_manager =
            Arc::new(PeerManagerCore::new_portable_for_test(peer_config, packet_sender).unwrap());
        let (incoming, receiver) = mpsc::unbounded_channel();
        let (sent, sent_receiver) = mpsc::unbounded_channel();
        let host = Arc::new(ReloadUdpHost {
            incoming: std::sync::Mutex::new(Some(receiver)),
            sent,
            sockets: std::sync::Mutex::new(Vec::new()),
            open_started: Notify::new(),
            open_release: std::sync::Mutex::new(None),
        });
        let data_plane = DataPlaneRuntime::new(
            runtime_config.clone(),
            peer_manager.clone(),
            None,
            host.clone(),
            SocketContext::default(),
        );
        data_plane.start_runtime().await.unwrap();
        let adapter = PortForwardAdapter::new(
            runtime_config,
            data_plane,
            host.clone(),
            SocketContext::default(),
            Arc::new(()),
            None,
        );
        adapter.start().await.unwrap();
        Self {
            adapter,
            host,
            incoming,
            sent: sent_receiver,
            _peer_manager: peer_manager,
            _packets: packets,
        }
    }

    async fn apply(&self, port: u16) -> PortForwardConfig {
        let config = PortForwardConfig {
            proto: "udp".to_owned(),
            bind_addr: "127.0.0.1:19491".parse().unwrap(),
            dst_addr: SocketAddr::from(([10, 144, 0, 2], port)),
        };
        self.adapter
            .prepare(std::slice::from_ref(&config))
            .await
            .unwrap()
            .unwrap()
            .commit()
            .await
            .unwrap();
        config
    }

    fn send(&self, payload: &[u8]) {
        self.incoming
            .send((payload.to_vec(), "127.0.0.1:40000".parse().unwrap()))
            .unwrap();
    }

    async fn receive(&mut self) -> Datagram {
        tokio::time::timeout(Duration::from_secs(2), self.sent.recv())
            .await
            .unwrap()
            .unwrap()
    }

    async fn stop(&self) {
        self.adapter.stop().await;
        self.adapter.data_plane.stop_runtime().await;
    }
}

#[tokio::test]
async fn udp_target_update_reuses_listener_and_releases_old_flow() {
    let mut test = UdpReloadTest::new().await;
    let first = test.apply(19381).await;
    test.send(b"first");
    assert_eq!(test.receive().await, (b"first".to_vec(), first.dst_addr));
    let second = test.apply(19382).await;
    assert!(test.adapter.udp_clients.is_empty());
    {
        let sockets = test.host.sockets.lock().unwrap();
        assert_eq!(
            sockets.len(),
            2,
            "target changes must not bind a new listener"
        );
        assert!(sockets[0].upgrade().is_some());
        assert!(sockets[1].upgrade().is_none(), "old flow must be released");
    }
    test.send(b"second");
    assert_eq!(test.receive().await, (b"second".to_vec(), second.dst_addr));
    assert_eq!(test.adapter.udp_clients.len(), 1);
    test.stop().await;
}

#[tokio::test]
async fn udp_target_update_during_open_discards_old_flow() {
    let mut test = UdpReloadTest::new().await;
    test.apply(19381).await;
    let (release, waiting) = oneshot::channel();
    *test.host.open_release.lock().unwrap() = Some(waiting);
    test.send(b"old");
    tokio::time::timeout(Duration::from_secs(2), test.host.open_started.notified())
        .await
        .unwrap();
    let next = test.apply(19382).await;
    release.send(()).unwrap();
    test.send(b"new");
    assert_eq!(test.receive().await, (b"new".to_vec(), next.dst_addr));
    assert!(
        test.adapter
            .udp_clients
            .iter()
            .all(|entry| entry.key().forward == next)
    );
    assert!(test.host.sockets.lock().unwrap()[1].upgrade().is_none());
    test.stop().await;
}

#[cfg(not(any(target_arch = "wasm32", target_os = "wasi")))]
#[tokio::test]
async fn udp_removal_waits_for_response_tasks_already_removed_from_map() {
    let test = UdpReloadTest::new().await;
    let forward = test.apply(19381).await;
    let socket = test.host.sockets.lock().unwrap()[0].upgrade().unwrap();
    let tracker = test
        .adapter
        .listeners
        .lock()
        .unwrap()
        .get(&(forward.proto.clone(), forward.bind_addr))
        .unwrap()
        .udp_tasks
        .clone();
    let (started, ready) = oneshot::channel();
    let (release, waiting) = std::sync::mpsc::channel();
    // A running blocking task makes the delay between abort and socket release
    // deterministic, as can happen when a response task is currently executing.
    let task = tracker.spawn_blocking(move || {
        started.send(()).unwrap();
        waiting.recv().unwrap();
        drop(socket);
    });
    let key = UdpClientKey {
        client_addr: "127.0.0.1:40000".parse().unwrap(),
        forward,
    };
    test.adapter
        .udp_response_tasks
        .insert(key, AbortOnDropHandle::new(task));
    ready.await.unwrap();
    test.adapter.udp_response_tasks.clear();
    let cleanup = test.adapter.prepare(&[]).await.unwrap().unwrap().commit();
    drop(cleanup);
    let mut next = std::pin::pin!(test.adapter.prepare(&[]));
    let result = tokio::time::timeout(Duration::from_millis(20), &mut next).await;
    let pending = result.is_err();
    release.send(()).unwrap();
    let prepared = match result {
        Ok(prepared) => prepared,
        Err(_) => tokio::time::timeout(Duration::from_secs(2), next)
            .await
            .unwrap(),
    };
    prepared.unwrap().unwrap().commit().await.unwrap();
    assert!(
        pending,
        "dropping the cleanup waiter released the operation lock before the socket"
    );
    assert!(test.host.sockets.lock().unwrap()[0].upgrade().is_none());
    test.stop().await;
}
