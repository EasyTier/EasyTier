use std::sync::{
    Arc, Mutex,
    atomic::{AtomicBool, Ordering},
};

use futures::{SinkExt as _, StreamExt};
use tokio::task::JoinSet;

use crate::{
    foundation::{
        stats::{ArcRpcMetrics, RpcMetricsProvider},
        time::timeout,
    },
    packet::PacketType,
    proto::rpc_types::error::Error,
    tunnel::{Tunnel, ring::create_ring_tunnel_pair},
};

use super::{client::Client, server::Server, service_registry::ServiceRegistry};

pub struct BidirectRpcManager {
    rpc_client: Client,
    rpc_server: Server,

    rx_timeout: Option<std::time::Duration>,
    error: Arc<Mutex<Option<Error>>>,
    tunnel: Mutex<Option<Box<dyn Tunnel>>>,
    running: Arc<AtomicBool>,

    tasks: Mutex<Option<JoinSet<()>>>,
}

impl Default for BidirectRpcManager {
    fn default() -> Self {
        Self::new()
    }
}

impl BidirectRpcManager {
    pub fn new() -> Self {
        Self {
            rpc_client: Client::new(),
            rpc_server: Server::new(),

            rx_timeout: None,
            error: Arc::new(Mutex::new(None)),
            tunnel: Mutex::new(None),
            running: Arc::new(AtomicBool::new(false)),

            tasks: Mutex::new(None),
        }
    }

    pub fn new_with_stats_manager<T>(stats_manager: T) -> Self
    where
        T: Clone + RpcMetricsProvider,
    {
        Self {
            rpc_client: Client::new_with_stats_manager(stats_manager.clone()),
            rpc_server: Server::new_with_registry_and_stats_manager(
                Arc::new(ServiceRegistry::new()),
                stats_manager,
            ),

            rx_timeout: None,
            error: Arc::new(Mutex::new(None)),
            tunnel: Mutex::new(None),
            running: Arc::new(AtomicBool::new(false)),

            tasks: Mutex::new(None),
        }
    }

    pub fn new_with_metrics(metrics: ArcRpcMetrics) -> Self {
        Self {
            rpc_client: Client::new_with_metrics(metrics.clone()),
            rpc_server: Server::new_with_registry_and_metrics(
                Arc::new(ServiceRegistry::new()),
                metrics,
            ),

            rx_timeout: None,
            error: Arc::new(Mutex::new(None)),
            tunnel: Mutex::new(None),
            running: Arc::new(AtomicBool::new(false)),

            tasks: Mutex::new(None),
        }
    }

    pub fn set_rx_timeout(mut self, timeout: Option<std::time::Duration>) -> Self {
        self.rx_timeout = timeout;
        self
    }

    pub fn run_and_create_tunnel(&self) -> Box<dyn Tunnel> {
        let (ret, inner) = create_ring_tunnel_pair();
        self.run_with_tunnel(inner);
        ret
    }

    pub fn run_with_tunnel(&self, inner: Box<dyn Tunnel>) {
        let mut tasks = JoinSet::new();
        self.rpc_client.run();
        self.rpc_server.run();
        self.running.store(true, Ordering::Relaxed);

        let (server_tx, mut server_rx) = (
            self.rpc_server.get_transport_sink(),
            self.rpc_server.get_transport_stream(),
        );
        let (client_tx, mut client_rx) = (
            self.rpc_client.get_transport_sink(),
            self.rpc_client.get_transport_stream(),
        );

        let (mut inner_rx, mut inner_tx) = inner.split();
        self.tunnel.lock().unwrap().replace(inner);

        let e_clone = self.error.clone();
        let r_clone = self.running.clone();
        tasks.spawn(async move {
            loop {
                let packet = tokio::select! {
                    Some(Ok(packet)) = server_rx.next() => {
                        tracing::trace!(?packet, "recv rpc packet from server");
                        packet
                    }
                    Some(Ok(packet)) = client_rx.next() => {
                        tracing::trace!(?packet, "recv rpc packet from client");
                        packet
                    }
                    else => {
                        tracing::warn!("rpc transport read aborted, exiting");
                        r_clone.store(false, Ordering::Relaxed);
                        break;
                    }
                };

                if let Err(e) = inner_tx.send(packet).await {
                    tracing::error!(error = ?e, "send to peer failed");
                    e_clone.lock().unwrap().replace(Error::from(e));
                    r_clone.store(false, Ordering::Relaxed);
                    break;
                }
            }
        });

        let recv_timeout = self.rx_timeout;
        let e_clone = self.error.clone();
        let r_clone = self.running.clone();
        tasks.spawn(async move {
            loop {
                let ret = if let Some(recv_timeout) = recv_timeout {
                    match timeout(recv_timeout, inner_rx.next()).await {
                        Ok(ret) => ret,
                        Err(e) => {
                            e_clone.lock().unwrap().replace(e.into());
                            r_clone.store(false, Ordering::Relaxed);
                            break;
                        }
                    }
                } else {
                    inner_rx.next().await
                };

                let o = match ret {
                    Some(Ok(o)) => o,
                    Some(Err(e)) => {
                        tracing::error!(error = ?e, "recv from peer failed");
                        e_clone.lock().unwrap().replace(Error::from(e));
                        r_clone.store(false, Ordering::Relaxed);
                        break;
                    }
                    None => {
                        tracing::warn!("peer rpc transport read aborted, exiting");
                        e_clone.lock().unwrap().replace(Error::Shutdown);
                        r_clone.store(false, Ordering::Relaxed);
                        break;
                    }
                };

                let Some(peer_manager_header) = o.peer_manager_header() else {
                    tracing::error!("peer manager header not found");
                    continue;
                };
                if peer_manager_header.packet_type == PacketType::RpcReq as u8 {
                    if let Err(e) = server_tx.send(o).await {
                        tracing::error!(error = ?e, "send rpc request to server failed");
                        e_clone.lock().unwrap().replace(Error::from(e));
                        r_clone.store(false, Ordering::Relaxed);
                        break;
                    }
                    continue;
                } else if peer_manager_header.packet_type == PacketType::RpcResp as u8 {
                    if let Err(e) = client_tx.send(o).await {
                        tracing::error!(error = ?e, "send rpc response to client failed");
                        e_clone.lock().unwrap().replace(Error::from(e));
                        r_clone.store(false, Ordering::Relaxed);
                        break;
                    }
                    continue;
                }
            }
        });

        self.tasks.lock().unwrap().replace(tasks);
    }

    pub fn rpc_client(&self) -> &Client {
        &self.rpc_client
    }

    pub fn rpc_server(&self) -> &Server {
        &self.rpc_server
    }

    pub async fn stop(&self) {
        self.running.store(false, Ordering::Relaxed);
        self.tunnel.lock().unwrap().take();
        self.rpc_client.stop().await;
        self.rpc_server.stop().await;
        let Some(mut tasks) = self.tasks.lock().unwrap().take() else {
            return;
        };
        tasks.abort_all();
        while tasks.join_next().await.is_some() {}
    }

    pub fn take_error(&self) -> Option<Error> {
        self.error.lock().unwrap().take()
    }

    pub async fn wait(&self) {
        let Some(mut tasks) = self.tasks.lock().unwrap().take() else {
            return;
        };
        while tasks.join_next().await.is_some() {
            tasks.abort_all();
        }
        self.running.store(false, Ordering::Relaxed);
        self.tunnel.lock().unwrap().take();
        self.rpc_client.stop().await;
        self.rpc_server.stop().await;
    }

    pub fn is_running(&self) -> bool {
        self.running.load(Ordering::Relaxed)
    }
}
