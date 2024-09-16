use std::sync::Arc;

use futures::StreamExt;

use crate::{
    common::{error::Error, PeerId},
    proto::rpc_impl,
    tunnel::packet_def::{PacketType, ZCPacket},
};

const RPC_PACKET_CONTENT_MTU: usize = 1300;

type PeerRpcServiceId = u32;
type PeerRpcTransactId = u32;

#[async_trait::async_trait]
#[auto_impl::auto_impl(Arc)]
pub trait PeerRpcManagerTransport: Send + Sync + 'static {
    fn my_peer_id(&self) -> PeerId;
    async fn send(&self, msg: ZCPacket, dst_peer_id: PeerId) -> Result<(), Error>;
    async fn recv(&self) -> Result<ZCPacket, Error>;
}

// handle rpc request from one peer
pub struct PeerRpcManager {
    tspt: Arc<Box<dyn PeerRpcManagerTransport>>,
    rpc_client: rpc_impl::client::Client,
    rpc_server: rpc_impl::server::Server,
}

impl std::fmt::Debug for PeerRpcManager {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PeerRpcManager")
            .field("node_id", &self.tspt.my_peer_id())
            .finish()
    }
}

impl PeerRpcManager {
    pub fn new(tspt: impl PeerRpcManagerTransport) -> Self {
        Self {
            tspt: Arc::new(Box::new(tspt)),
            rpc_client: rpc_impl::client::Client::new(),
            rpc_server: rpc_impl::server::Server::new(),
        }
    }

    pub fn run(&self) {
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

        let tspt = self.tspt.clone();

        tokio::spawn(async move {
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

                let dst_peer_id = packet.peer_manager_header().unwrap().to_peer_id.into();
                if let Err(e) = tspt.send(packet, dst_peer_id).await {
                    tracing::error!(error = ?e, dst_peer_id = ?dst_peer_id, "send to peer failed");
                }
            }
        });

        let tspt = self.tspt.clone();
        tokio::spawn(async move {
            loop {
                let Ok(o) = tspt.recv().await else {
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

    pub fn rpc_client(&self) -> &rpc_impl::client::Client {
        &self.rpc_client
    }

    pub fn rpc_server(&self) -> &rpc_impl::server::Server {
        &self.rpc_server
    }

    pub fn my_peer_id(&self) -> PeerId {
        self.tspt.my_peer_id()
    }
}

#[cfg(test)]
pub mod tests {
    use std::{pin::Pin, sync::Arc};

    use futures::{SinkExt, StreamExt};
    use tokio::sync::Mutex;

    use crate::{
        common::{error::Error, new_peer_id, PeerId},
        peers::{
            peer_rpc::PeerRpcManager,
            tests::{connect_peer_manager, create_mock_peer_manager, wait_route_appear},
        },
        proto::{
            rpc_impl::RpcController,
            tests::{GreetingClientFactory, GreetingServer, GreetingService, SayHelloRequest},
        },
        tunnel::{
            common::tests::enable_log, packet_def::ZCPacket, ring::create_ring_tunnel_pair, Tunnel,
            ZCPacketSink, ZCPacketStream,
        },
    };

    use super::PeerRpcManagerTransport;

    fn random_string(len: usize) -> String {
        use rand::distributions::Alphanumeric;
        use rand::Rng;
        let mut rng = rand::thread_rng();
        let s: Vec<u8> = std::iter::repeat(())
            .map(|()| rng.sample(Alphanumeric))
            .take(len)
            .collect();
        String::from_utf8(s).unwrap()
    }

    pub fn register_service(rpc_mgr: &PeerRpcManager, domain: &str, delay_ms: u64, prefix: &str) {
        rpc_mgr.rpc_server().registry().register(
            GreetingServer::new(GreetingService {
                delay_ms,
                prefix: prefix.to_string(),
            }),
            domain,
        );
    }

    #[tokio::test]
    async fn peer_rpc_basic_test() {
        struct MockTransport {
            sink: Arc<Mutex<Pin<Box<dyn ZCPacketSink>>>>,
            stream: Arc<Mutex<Pin<Box<dyn ZCPacketStream>>>>,
            my_peer_id: PeerId,
        }

        #[async_trait::async_trait]
        impl PeerRpcManagerTransport for MockTransport {
            fn my_peer_id(&self) -> PeerId {
                self.my_peer_id
            }
            async fn send(&self, msg: ZCPacket, _dst_peer_id: PeerId) -> Result<(), Error> {
                println!("rpc mgr send: {:?}", msg);
                self.sink.lock().await.send(msg).await.unwrap();
                Ok(())
            }
            async fn recv(&self) -> Result<ZCPacket, Error> {
                let ret = self.stream.lock().await.next().await.unwrap();
                println!("rpc mgr recv: {:?}", ret);
                return ret.map_err(|e| e.into());
            }
        }

        let (ct, st) = create_ring_tunnel_pair();
        let (cts, ctsr) = ct.split();
        let (sts, stsr) = st.split();

        let server_rpc_mgr = PeerRpcManager::new(MockTransport {
            sink: Arc::new(Mutex::new(ctsr)),
            stream: Arc::new(Mutex::new(cts)),
            my_peer_id: new_peer_id(),
        });
        server_rpc_mgr.run();
        register_service(&server_rpc_mgr, "test", 0, "Hello");

        let client_rpc_mgr = PeerRpcManager::new(MockTransport {
            sink: Arc::new(Mutex::new(stsr)),
            stream: Arc::new(Mutex::new(sts)),
            my_peer_id: new_peer_id(),
        });
        client_rpc_mgr.run();

        let stub = client_rpc_mgr
            .rpc_client()
            .scoped_client::<GreetingClientFactory<RpcController>>(1, 1, "test".to_string());

        let msg = random_string(8192);
        let ret = stub
            .say_hello(RpcController {}, SayHelloRequest { name: msg.clone() })
            .await
            .unwrap();

        println!("ret: {:?}", ret);
        assert_eq!(ret.greeting, format!("Hello {}!", msg));

        let msg = random_string(10);
        let ret = stub
            .say_hello(RpcController {}, SayHelloRequest { name: msg.clone() })
            .await
            .unwrap();

        println!("ret: {:?}", ret);
        assert_eq!(ret.greeting, format!("Hello {}!", msg));
    }

    #[tokio::test]
    async fn test_rpc_with_peer_manager() {
        let peer_mgr_a = create_mock_peer_manager().await;
        let peer_mgr_b = create_mock_peer_manager().await;
        let peer_mgr_c = create_mock_peer_manager().await;
        connect_peer_manager(peer_mgr_a.clone(), peer_mgr_b.clone()).await;
        connect_peer_manager(peer_mgr_b.clone(), peer_mgr_c.clone()).await;

        wait_route_appear(peer_mgr_a.clone(), peer_mgr_b.clone())
            .await
            .unwrap();
        wait_route_appear(peer_mgr_a.clone(), peer_mgr_c.clone())
            .await
            .unwrap();

        assert_eq!(peer_mgr_a.get_peer_map().list_peers().await.len(), 1);
        assert_eq!(
            peer_mgr_a.get_peer_map().list_peers().await[0],
            peer_mgr_b.my_peer_id()
        );

        assert_eq!(peer_mgr_c.get_peer_map().list_peers().await.len(), 1);
        assert_eq!(
            peer_mgr_c.get_peer_map().list_peers().await[0],
            peer_mgr_b.my_peer_id()
        );

        register_service(&peer_mgr_b.get_peer_rpc_mgr(), "test", 0, "Hello");

        let msg = random_string(16 * 1024);
        let stub = peer_mgr_a
            .get_peer_rpc_mgr()
            .rpc_client()
            .scoped_client::<GreetingClientFactory<RpcController>>(
                peer_mgr_a.my_peer_id(),
                peer_mgr_b.my_peer_id(),
                "test".to_string(),
            );

        let ret = stub
            .say_hello(RpcController {}, SayHelloRequest { name: msg.clone() })
            .await
            .unwrap();
        assert_eq!(ret.greeting, format!("Hello {}!", msg));

        // call again
        let msg = random_string(16 * 1024);
        let ret = stub
            .say_hello(RpcController {}, SayHelloRequest { name: msg.clone() })
            .await
            .unwrap();
        assert_eq!(ret.greeting, format!("Hello {}!", msg));

        let msg = random_string(16 * 1024);
        let ret = stub
            .say_hello(RpcController {}, SayHelloRequest { name: msg.clone() })
            .await
            .unwrap();
        assert_eq!(ret.greeting, format!("Hello {}!", msg));
    }

    #[tokio::test]
    async fn test_multi_domain_with_peer_manager() {
        let peer_mgr_a = create_mock_peer_manager().await;
        let peer_mgr_b = create_mock_peer_manager().await;
        connect_peer_manager(peer_mgr_a.clone(), peer_mgr_b.clone()).await;
        wait_route_appear(peer_mgr_a.clone(), peer_mgr_b.clone())
            .await
            .unwrap();

        assert_eq!(peer_mgr_a.get_peer_map().list_peers().await.len(), 1);
        assert_eq!(
            peer_mgr_a.get_peer_map().list_peers().await[0],
            peer_mgr_b.my_peer_id()
        );

        register_service(&peer_mgr_b.get_peer_rpc_mgr(), "test1", 0, "Hello");
        register_service(&peer_mgr_b.get_peer_rpc_mgr(), "test2", 20000, "Hello2");

        let stub1 = peer_mgr_a
            .get_peer_rpc_mgr()
            .rpc_client()
            .scoped_client::<GreetingClientFactory<RpcController>>(
                peer_mgr_a.my_peer_id(),
                peer_mgr_b.my_peer_id(),
                "test1".to_string(),
            );

        let stub2 = peer_mgr_a
            .get_peer_rpc_mgr()
            .rpc_client()
            .scoped_client::<GreetingClientFactory<RpcController>>(
                peer_mgr_a.my_peer_id(),
                peer_mgr_b.my_peer_id(),
                "test2".to_string(),
            );

        let msg = random_string(16 * 1024);
        let ret = stub1
            .say_hello(RpcController {}, SayHelloRequest { name: msg.clone() })
            .await
            .unwrap();
        assert_eq!(ret.greeting, format!("Hello {}!", msg));

        let ret = stub2
            .say_hello(RpcController {}, SayHelloRequest { name: msg.clone() })
            .await;
        assert!(ret.is_err() && ret.unwrap_err().to_string().contains("Timeout"));
    }
}
