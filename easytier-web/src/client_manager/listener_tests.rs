use super::*;

use easytier::proto::rpc::standalone::{
    RuntimeRpcListener, runtime_rpc_dialer, runtime_rpc_listener,
};
use easytier_core::connectivity::protocol::raw::TunnelDialer;
use std::sync::atomic::AtomicUsize;
use tokio::{io::AsyncReadExt, net::TcpStream, sync::Notify, time::timeout};

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

#[derive(Debug)]
struct UnboundListener {
    listened: bool,
}

#[async_trait::async_trait]
impl SocketListener for UnboundListener {
    type Accepted = Box<dyn Tunnel>;

    async fn listen(&mut self) -> anyhow::Result<()> {
        self.listened = true;
        Ok(())
    }

    async fn accept(&mut self) -> anyhow::Result<Self::Accepted> {
        unreachable!("an unbound listener must not accept connections")
    }

    fn local_url(&self) -> url::Url {
        let port = if self.listened { 0 } else { 22020 };
        format!("udp://[::]:{port}").parse().unwrap()
    }
}

#[tokio::test]
async fn unbound_listener_is_not_counted_as_running() {
    let mut manager = manager().await;
    let error = manager
        .add_listener(UnboundListener { listened: false })
        .await
        .unwrap_err();
    assert!(
        error.to_string().contains("did not bind requested address"),
        "{error}"
    );
    assert!(!manager.is_running());
}
