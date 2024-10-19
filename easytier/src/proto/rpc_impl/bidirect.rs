use std::sync::{Arc, Mutex};

use futures::{SinkExt as _, StreamExt};
use tokio::task::JoinSet;

use crate::tunnel::{packet_def::PacketType, ring::create_ring_tunnel_pair, Tunnel};

use super::{client::Client, server::Server};

pub struct BidirectRpcManager {
    rpc_client: Client,
    rpc_server: Server,

    tasks: Arc<Mutex<JoinSet<()>>>,
}

impl BidirectRpcManager {
    pub fn new() -> Self {
        Self {
            rpc_client: Client::new(),
            rpc_server: Server::new(),

            tasks: Arc::new(Mutex::new(JoinSet::new())),
        }
    }

    pub fn run_and_create_tunnel(&self) -> Box<dyn Tunnel> {
        let (ret, inner) = create_ring_tunnel_pair();
        self.run_with_tunnel(inner);
        ret
    }

    pub fn run_with_tunnel(&self, inner: Box<dyn Tunnel>) {
        if !self.tasks.lock().unwrap().is_empty() {
            panic!("rpc manager already running");
        }

        self.rpc_client.run();
        self.rpc_server.run();

        let (server_tx, mut server_rx) = (
            self.rpc_server.get_transport_sink(),
            self.rpc_server.get_transport_stream(),
        );
        let (client_tx, mut client_rx) = (
            self.rpc_client.get_transport_sink(),
            self.rpc_client.get_transport_stream(),
        );

        let (mut inner_rx, mut inner_tx) = inner.split();

        self.tasks.lock().unwrap().spawn(async move {
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
                }
            }
        });

        self.tasks.lock().unwrap().spawn(async move {
            loop {
                let Some(Ok(o)) = inner_rx.next().await else {
                    tracing::warn!("peer rpc transport read aborted, exiting");
                    break;
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
    }

    pub fn rpc_client(&self) -> &Client {
        &self.rpc_client
    }

    pub fn rpc_server(&self) -> &Server {
        &self.rpc_server
    }

    pub async fn stop(&self) {
        self.tasks.lock().unwrap().abort_all();
        while let Some(_) = self.tasks.lock().unwrap().join_next().await {}
    }
}
