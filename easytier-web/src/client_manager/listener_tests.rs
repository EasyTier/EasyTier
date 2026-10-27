use super::*;

use easytier::proto::rpc::standalone::{
    RuntimeRpcListener, runtime_rpc_dialer, runtime_rpc_listener, runtime_udp_tunnel_listener,
};
use easytier_core::connectivity::protocol::raw::TunnelDialer;
use std::sync::atomic::AtomicUsize;
use tokio::{io::AsyncReadExt, net::TcpStream, sync::Notify, time::timeout};

#[derive(Debug)]
struct FailingListener {
    inner: RuntimeRpcListener,
    attempts: Arc<std::sync::Mutex<Vec<tokio::time::Instant>>>,
    errors_remaining: usize,
    error_kind: std::io::ErrorKind,
}

#[async_trait::async_trait]
impl SocketListener for FailingListener {
    type Accepted = Box<dyn Tunnel>;

    async fn listen(&mut self) -> anyhow::Result<()> {
        self.inner.listen().await
    }

    async fn accept(&mut self) -> anyhow::Result<Self::Accepted> {
        self.attempts
            .lock()
            .unwrap()
            .push(tokio::time::Instant::now());
        if self.errors_remaining > 0 {
            self.errors_remaining -= 1;
            return Err(std::io::Error::from(self.error_kind).into());
        }
        self.inner.accept().await
    }

    fn local_url(&self) -> url::Url {
        self.inner.local_url()
    }
}

#[derive(Debug)]
struct TestListener {
    inner: RuntimeRpcListener,
    accepted: Arc<AtomicUsize>,
    second_accept: Option<Arc<Notify>>,
}

#[async_trait::async_trait]
impl SocketListener for TestListener {
    type Accepted = Box<dyn Tunnel>;

    async fn listen(&mut self) -> anyhow::Result<()> {
        self.inner.listen().await
    }

    async fn accept(&mut self) -> anyhow::Result<Self::Accepted> {
        let tunnel = self.inner.accept().await?;
        if self.accepted.fetch_add(1, Ordering::SeqCst) == 1
            && let Some(ready) = &self.second_accept
        {
            // Model a listener that has accepted a socket but is still
            // performing its transport upgrade when another handshake ends.
            ready.notified().await;
        }
        Ok(tunnel)
    }

    fn local_url(&self) -> url::Url {
        self.inner.local_url()
    }
}

async fn wait_until(mut condition: impl FnMut() -> bool) {
    timeout(Duration::from_secs(1), async {
        while !condition() {
            tokio::time::sleep(Duration::from_millis(1)).await;
        }
    })
    .await
    .expect("listener did not make progress");
}

async fn manager() -> ClientManager {
    ClientManager::new(
        Db::memory_db().await,
        None,
        HeartbeatPolicy::default(),
        Arc::new(FeatureFlags::default()),
        Arc::new(crate::webhook::WebhookConfig::new(
            None, None, None, None, None,
        )),
    )
}

#[tokio::test]
async fn accept_errors_rebind_listener_with_fixed_delay() {
    for error_kind in [std::io::ErrorKind::OutOfMemory, std::io::ErrorKind::Other] {
        let mut manager = manager().await;
        let attempts = Arc::new(std::sync::Mutex::new(Vec::new()));
        let url = manager
            .add_listener(FailingListener {
                inner: runtime_rpc_listener("127.0.0.1:0".parse().unwrap()),
                attempts: attempts.clone(),
                errors_remaining: 2,
                error_kind,
            })
            .await
            .unwrap();
        wait_until(|| attempts.lock().unwrap().len() >= 3).await;
        assert!(manager.is_running());

        let client = runtime_rpc_dialer(url).connect().await.unwrap();
        let _client = timeout(
            Duration::from_secs(1),
            web_security::upgrade_client_tunnel(client),
        )
        .await
        .expect("listener did not recover after accept errors")
        .unwrap();
        wait_until(|| manager.client_sessions.len() == 1).await;
        {
            let attempts = attempts.lock().unwrap();
            assert!(attempts.len() >= 3);
            for pair in attempts[..3].windows(2) {
                assert!(pair[1] - pair[0] >= Duration::from_millis(100));
            }
        }
        assert!(manager.is_running());
        drop(manager);
        wait_until(|| Arc::strong_count(&attempts) == 1).await;
    }
}

#[tokio::test]
async fn manager_shutdown_cancels_accept_error_retries() {
    let mut manager = manager().await;
    let attempts = Arc::new(std::sync::Mutex::new(Vec::new()));
    let url = manager
        .add_listener(FailingListener {
            inner: runtime_rpc_listener("127.0.0.1:0".parse().unwrap()),
            attempts: attempts.clone(),
            errors_remaining: usize::MAX,
            error_kind: std::io::ErrorKind::Other,
        })
        .await
        .unwrap();
    wait_until(|| !attempts.lock().unwrap().is_empty()).await;
    assert!(manager.is_running());
    drop(manager);
    wait_until(|| Arc::strong_count(&attempts) == 1).await;
    let addr = url.socket_addrs(|| None).unwrap()[0];
    assert!(TcpStream::connect(addr).await.is_err());
}

#[tokio::test]
async fn slow_handshakes_do_not_block_other_clients() {
    let mut manager = manager().await;
    let url = manager
        .add_listener(runtime_rpc_listener("127.0.0.1:0".parse().unwrap()))
        .await
        .unwrap();
    let addr = url.socket_addrs(|| None).unwrap()[0];
    let mut idle_clients = Vec::new();
    for _ in 0..4 {
        idle_clients.push(TcpStream::connect(addr).await.unwrap());
    }

    // A client that sends its handshake must not wait for the preceding
    // connections' three-second first-packet timeouts.
    let client = runtime_rpc_dialer(url).connect().await.unwrap();
    let _client = timeout(
        Duration::from_secs(1),
        web_security::upgrade_client_tunnel(client),
    )
    .await
    .expect("healthy client was blocked by idle connections")
    .unwrap();
    wait_until(|| manager.client_sessions.len() == 1).await;

    // Dropping the manager must also cancel handshakes that are still waiting.
    drop(manager);
    for mut client in idle_clients {
        let mut byte = [0];
        assert_eq!(
            timeout(Duration::from_secs(1), client.read(&mut byte))
                .await
                .expect("pending handshake survived manager shutdown")
                .unwrap(),
            0,
        );
    }
}

#[tokio::test]
#[ignore = "opens 4097 TCP connections; run explicitly with a sufficient file descriptor limit"]
async fn pending_handshakes_are_bounded_and_release_capacity() {
    let mut manager = manager().await;
    let accepted = Arc::new(AtomicUsize::new(0));
    let url = manager
        .add_listener(TestListener {
            inner: runtime_rpc_listener("127.0.0.1:0".parse().unwrap()),
            accepted: accepted.clone(),
            second_accept: None,
        })
        .await
        .unwrap();
    let addr = url.socket_addrs(|| None).unwrap()[0];
    let mut clients = Vec::new();
    for _ in 0..=MAX_PENDING_HANDSHAKES {
        clients.push(TcpStream::connect(addr).await.unwrap());
    }
    wait_until(|| accepted.load(Ordering::SeqCst) >= MAX_PENDING_HANDSHAKES).await;
    tokio::time::sleep(Duration::from_millis(50)).await;
    assert_eq!(accepted.load(Ordering::SeqCst), MAX_PENDING_HANDSHAKES);

    drop(clients.remove(0));
    wait_until(|| accepted.load(Ordering::SeqCst) == MAX_PENDING_HANDSHAKES + 1).await;
}

#[tokio::test]
async fn completed_handshake_does_not_cancel_pending_accept() {
    let mut manager = manager().await;
    let accepted = Arc::new(AtomicUsize::new(0));
    let ready = Arc::new(Notify::new());
    let url = manager
        .add_listener(TestListener {
            inner: runtime_rpc_listener("127.0.0.1:0".parse().unwrap()),
            accepted: accepted.clone(),
            second_accept: Some(ready.clone()),
        })
        .await
        .unwrap();
    let dialer = runtime_rpc_dialer(url);
    let first = dialer.connect().await.unwrap();
    let second = dialer.connect().await.unwrap();
    wait_until(|| accepted.load(Ordering::SeqCst) == 2).await;

    let _first = timeout(
        Duration::from_secs(1),
        web_security::upgrade_client_tunnel(first),
    )
    .await
    .unwrap()
    .unwrap();
    wait_until(|| manager.client_sessions.len() == 1).await;
    ready.notify_one();
    let _second = timeout(
        Duration::from_secs(1),
        web_security::upgrade_client_tunnel(second),
    )
    .await
    .expect("pending accept was cancelled when the first handshake completed")
    .unwrap();
    wait_until(|| manager.client_sessions.len() == 2).await;
}

#[tokio::test]
async fn failed_udp_listener_is_not_counted_as_running() {
    for bind_addr in ["127.0.0.1:0", "[::1]:0"] {
        let occupied = tokio::net::UdpSocket::bind(bind_addr).await.unwrap();
        let addr = occupied.local_addr().unwrap();
        let mut manager = manager().await;
        manager
            .add_listener(runtime_udp_tunnel_listener(
                format!("udp://{addr}").parse().unwrap(),
                addr,
            ))
            .await
            .unwrap_err();
        assert!(!manager.is_running());
    }
}

#[tokio::test]
async fn ephemeral_udp_listener_is_counted_as_running() {
    let mut manager = manager().await;
    let local_url = "udp://127.0.0.1:0".parse().unwrap();
    let bound_url = manager
        .add_listener(runtime_udp_tunnel_listener(
            local_url,
            "127.0.0.1:0".parse().unwrap(),
        ))
        .await
        .unwrap();
    assert!(bound_url.port().is_some_and(|port| port != 0));
    assert!(manager.is_running());
}
