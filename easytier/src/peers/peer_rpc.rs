use std::sync::{Arc, Mutex};

use futures::{SinkExt as _, StreamExt};
use tokio::task::JoinSet;

use crate::{
    common::{error::Error, stats_manager::StatsManager, PeerId},
    proto::rpc_impl::{self, bidirect::BidirectRpcManager},
    tunnel::packet_def::ZCPacket,
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
    bidirect_rpc: BidirectRpcManager,
    tasks: Mutex<JoinSet<()>>,
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
            bidirect_rpc: BidirectRpcManager::new(),

            tasks: Mutex::new(JoinSet::new()),
        }
    }

    pub fn new_with_stats_manager(
        tspt: impl PeerRpcManagerTransport,
        stats_manager: Arc<StatsManager>,
    ) -> Self {
        Self {
            tspt: Arc::new(Box::new(tspt)),
            bidirect_rpc: BidirectRpcManager::new_with_stats_manager(stats_manager),

            tasks: Mutex::new(JoinSet::new()),
        }
    }

    pub fn run(&self) {
        let ret = self.bidirect_rpc.run_and_create_tunnel();
        let (mut rx, mut tx) = ret.split();
        let tspt = self.tspt.clone();
        self.tasks.lock().unwrap().spawn(async move {
            while let Some(Ok(packet)) = rx.next().await {
                let dst_peer_id = packet.peer_manager_header().unwrap().to_peer_id.into();
                if let Err(e) = tspt.send(packet, dst_peer_id).await {
                    tracing::error!("send to rpc tspt error: {:?}", e);
                }
            }
        });

        let tspt = self.tspt.clone();
        self.tasks.lock().unwrap().spawn(async move {
            while let Ok(packet) = tspt.recv().await {
                if let Err(e) = tx.send(packet).await {
                    tracing::error!("send to rpc tspt error: {:?}", e);
                }
            }
        });
    }

    pub fn rpc_client(&self) -> &rpc_impl::client::Client {
        self.bidirect_rpc.rpc_client()
    }

    pub fn rpc_server(&self) -> &rpc_impl::server::Server {
        self.bidirect_rpc.rpc_server()
    }

    pub fn my_peer_id(&self) -> PeerId {
        self.tspt.my_peer_id()
    }
}

impl Drop for PeerRpcManager {
    fn drop(&mut self) {
        tracing::debug!("PeerRpcManager drop, my_peer_id: {:?}", self.my_peer_id());
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
            packet_def::ZCPacket, ring::create_ring_tunnel_pair, Tunnel, ZCPacketSink,
            ZCPacketStream,
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
            .say_hello(
                RpcController::default(),
                SayHelloRequest { name: msg.clone() },
            )
            .await
            .unwrap();

        println!("ret: {:?}", ret);
        assert_eq!(ret.greeting, format!("Hello {}!", msg));

        let msg = random_string(10);
        let ret = stub
            .say_hello(
                RpcController::default(),
                SayHelloRequest { name: msg.clone() },
            )
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
            .say_hello(
                RpcController::default(),
                SayHelloRequest { name: msg.clone() },
            )
            .await
            .unwrap();
        assert_eq!(ret.greeting, format!("Hello {}!", msg));

        // call again
        let msg = random_string(16 * 1024);
        let ret = stub
            .say_hello(
                RpcController::default(),
                SayHelloRequest { name: msg.clone() },
            )
            .await
            .unwrap();
        assert_eq!(ret.greeting, format!("Hello {}!", msg));

        let msg = random_string(16 * 1024);
        let ret = stub
            .say_hello(
                RpcController::default(),
                SayHelloRequest { name: msg.clone() },
            )
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
            .say_hello(
                RpcController::default(),
                SayHelloRequest { name: msg.clone() },
            )
            .await
            .unwrap();
        assert_eq!(ret.greeting, format!("Hello {}!", msg));

        let ret = stub2
            .say_hello(
                RpcController::default(),
                SayHelloRequest { name: msg.clone() },
            )
            .await;
        assert!(ret.is_err() && ret.unwrap_err().to_string().contains("Timeout"));
    }
}
