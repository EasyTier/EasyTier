use std::sync::{atomic::AtomicBool, Arc, Mutex};

use futures::{SinkExt as _, StreamExt};
use tokio::{task::JoinSet, time::timeout};

use crate::{
    defer,
    proto::rpc_types::error::Error,
    tunnel::{packet_def::PacketType, ring::create_ring_tunnel_pair, Tunnel},
};

use super::{client::Client, server::Server};

pub struct BidirectRpcManager {
    rpc_client: Client,
    rpc_server: Server,

    rx_timeout: Option<std::time::Duration>,
    error: Arc<Mutex<Option<Error>>>,
    tunnel: Mutex<Option<Box<dyn Tunnel>>>,
    running: Arc<AtomicBool>,

    tasks: Mutex<Option<JoinSet<()>>>,
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
        self.running
            .store(true, std::sync::atomic::Ordering::Relaxed);

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
            defer! {
                r_clone.store(false, std::sync::atomic::Ordering::Relaxed);
            }
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
                        break;
                    }
                };

                if let Err(e) = inner_tx.send(packet).await {
                    tracing::error!(error = ?e, "send to peer failed");
                    e_clone.lock().unwrap().replace(Error::from(e));
                }
            }
        });

        let recv_timeout = self.rx_timeout;
        let e_clone = self.error.clone();
        let r_clone = self.running.clone();
        tasks.spawn(async move {
            defer! {
                r_clone.store(false, std::sync::atomic::Ordering::Relaxed);
            }
            loop {
                let ret = if let Some(recv_timeout) = recv_timeout {
                    match timeout(recv_timeout, inner_rx.next()).await {
                        Ok(ret) => ret,
                        Err(e) => {
                            e_clone.lock().unwrap().replace(e.into());
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
                        break;
                    }
                    None => {
                        tracing::warn!("peer rpc transport read aborted, exiting");
                        e_clone.lock().unwrap().replace(Error::Shutdown);
                        break;
                    }
                };

                if o.peer_manager_header().unwrap().packet_type == PacketType::RpcReq as u8 {
                    server_tx.send(o).await.unwrap();
                    continue;
                } else if o.peer_manager_header().unwrap().packet_type == PacketType::RpcResp as u8
                {
                    client_tx.send(o).await.unwrap();
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
        let Some(mut tasks) = self.tasks.lock().unwrap().take() else {
            return;
        };
        tasks.abort_all();
        while let Some(_) = tasks.join_next().await {}
    }

    pub fn take_error(&self) -> Option<Error> {
        self.error.lock().unwrap().take()
    }

    pub async fn wait(&self) {
        let Some(mut tasks) = self.tasks.lock().unwrap().take() else {
            return;
        };
        while let Some(_) = tasks.join_next().await {
            // when any task is done, abort all tasks
            tasks.abort_all();
        }
    }

    pub fn is_running(&self) -> bool {
        self.running.load(std::sync::atomic::Ordering::Relaxed)
    }
}
