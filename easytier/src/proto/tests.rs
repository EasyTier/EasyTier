include!(concat!(env!("OUT_DIR"), "/tests.rs"));

use std::sync::{Arc, Mutex};

use futures::StreamExt as _;
use tokio::task::JoinSet;

use super::rpc_impl::RpcController;

#[derive(Clone)]
pub struct GreetingService {
    pub delay_ms: u64,
    pub prefix: String,
}

#[async_trait::async_trait]
impl Greeting for GreetingService {
    type Controller = RpcController;
    async fn say_hello(
        &self,
        _ctrl: Self::Controller,
        input: SayHelloRequest,
    ) -> crate::proto::rpc_types::error::Result<SayHelloResponse> {
        let resp = SayHelloResponse {
            greeting: format!("{} {}!", self.prefix, input.name),
        };
        tokio::time::sleep(std::time::Duration::from_millis(self.delay_ms)).await;
        Ok(resp)
    }
    /// Generates a "goodbye" greeting based on the supplied info.
    async fn say_goodbye(
        &self,
        _ctrl: Self::Controller,
        input: SayGoodbyeRequest,
    ) -> crate::proto::rpc_types::error::Result<SayGoodbyeResponse> {
        let resp = SayGoodbyeResponse {
            greeting: format!("Goodbye, {}!", input.name),
        };
        tokio::time::sleep(std::time::Duration::from_millis(self.delay_ms)).await;
        Ok(resp)
    }
}

use crate::proto::common::{CompressionAlgoPb, RpcCompressionInfo};
use crate::proto::rpc_impl::client::Client;
use crate::proto::rpc_impl::server::Server;

struct TestContext {
    client: Client,
    server: Server,
    tasks: Arc<Mutex<JoinSet<()>>>,
}

impl TestContext {
    fn new() -> Self {
        let rpc_server = Server::new();
        rpc_server.run();

        let client = Client::new();
        client.run();

        let tasks = Arc::new(Mutex::new(JoinSet::new()));
        let (mut rx, tx) = (
            rpc_server.get_transport_stream(),
            client.get_transport_sink(),
        );

        tasks.lock().unwrap().spawn(async move {
            while let Some(Ok(packet)) = rx.next().await {
                if let Err(err) = tx.send(packet).await {
                    println!("{:?}", err);
                    break;
                }
            }
        });

        let (mut rx, tx) = (
            client.get_transport_stream(),
            rpc_server.get_transport_sink(),
        );
        tasks.lock().unwrap().spawn(async move {
            while let Some(Ok(packet)) = rx.next().await {
                if let Err(err) = tx.send(packet).await {
                    println!("{:?}", err);
                    break;
                }
            }
        });

        Self {
            client,
            server: rpc_server,
            tasks,
        }
    }
}

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

#[tokio::test]
async fn rpc_basic_test() {
    // enable_log();
    let ctx = TestContext::new();

    let server = GreetingServer::new(GreetingService {
        delay_ms: 0,
        prefix: "Hello".to_string(),
    });
    ctx.server.registry().register(server, "");

    let out = ctx
        .client
        .scoped_client::<GreetingClientFactory<RpcController>>(1, 1, "".to_string());

    // // small size req and resp

    let ctrl = RpcController::default();
    let input = SayHelloRequest {
        name: "world".to_string(),
    };
    let ret = out.say_hello(ctrl, input).await;
    assert_eq!(ret.unwrap().greeting, "Hello world!");

    assert_eq!(1, ctx.client.peer_info_table().len());
    let first_peer_info = ctx.client.peer_info_table().iter().next().unwrap().clone();
    assert_eq!(
        first_peer_info.compression_info.accepted_algo(),
        CompressionAlgoPb::Zstd,
    );

    println!("{:?}", ctx.client.peer_info_table());

    let ctrl = RpcController::default();
    let input = SayGoodbyeRequest {
        name: "world".to_string(),
    };
    let ret = out.say_goodbye(ctrl, input).await;
    assert_eq!(ret.unwrap().greeting, "Goodbye, world!");

    // large size req and resp
    let ctrl = RpcController::default();
    let name = random_string(20 * 1024 * 1024);
    let input = SayGoodbyeRequest { name: name.clone() };
    let ret = out.say_goodbye(ctrl, input).await;
    assert_eq!(ret.unwrap().greeting, format!("Goodbye, {}!", name));

    assert_eq!(0, ctx.client.inflight_count());
    assert_eq!(0, ctx.server.inflight_count());

    let first_peer_info = ctx.client.peer_info_table().iter().next().unwrap().clone();
    assert_eq!(
        first_peer_info.compression_info,
        RpcCompressionInfo {
            algo: CompressionAlgoPb::Zstd.into(),
            accepted_algo: CompressionAlgoPb::Zstd.into(),
        }
    );
}

#[tokio::test]
async fn rpc_timeout_test() {
    let ctx = TestContext::new();

    let server = GreetingServer::new(GreetingService {
        delay_ms: 10000,
        prefix: "Hello".to_string(),
    });
    ctx.server.registry().register(server, "test");

    let out = ctx
        .client
        .scoped_client::<GreetingClientFactory<RpcController>>(1, 1, "test".to_string());

    let ctrl = RpcController::default();
    let input = SayHelloRequest {
        name: "world".to_string(),
    };
    let ret = out.say_hello(ctrl, input).await;
    assert!(ret.is_err());
    assert!(matches!(
        ret.unwrap_err(),
        crate::proto::rpc_types::error::Error::Timeout(_)
    ));

    assert_eq!(0, ctx.client.inflight_count());
    assert_eq!(0, ctx.server.inflight_count());
}

#[tokio::test]
async fn rpc_tunnel_stuck_test() {
    use crate::proto::rpc_types;
    use crate::tunnel::ring::RING_TUNNEL_CAP;

    let rpc_server = Server::new();
    rpc_server.run();
    let server = GreetingServer::new(GreetingService {
        delay_ms: 0,
        prefix: "Hello".to_string(),
    });
    rpc_server.registry().register(server, "test");

    let client = Client::new();
    client.run();

    let rpc_tasks = Arc::new(Mutex::new(JoinSet::new()));
    let (mut rx, tx) = (
        rpc_server.get_transport_stream(),
        client.get_transport_sink(),
    );

    rpc_tasks.lock().unwrap().spawn(async move {
        while let Some(Ok(packet)) = rx.next().await {
            if let Err(err) = tx.send(packet).await {
                println!("{:?}", err);
                break;
            }
        }
    });

    // mock server is stuck (no task to do forwards)

    let mut tasks = JoinSet::new();
    for _ in 0..RING_TUNNEL_CAP + 15 {
        let out =
            client.scoped_client::<GreetingClientFactory<RpcController>>(1, 1, "test".to_string());
        tasks.spawn(async move {
            let mut ctrl = RpcController::default();
            ctrl.timeout_ms = 1000;

            let input = SayHelloRequest {
                name: "world".to_string(),
            };

            out.say_hello(ctrl, input).await
        });
    }
    while let Some(ret) = tasks.join_next().await {
        assert!(matches!(ret, Ok(Err(rpc_types::error::Error::Timeout(_)))));
    }

    // start server consumer, new requests should be processed
    let (mut rx, tx) = (
        client.get_transport_stream(),
        rpc_server.get_transport_sink(),
    );
    rpc_tasks.lock().unwrap().spawn(async move {
        while let Some(Ok(packet)) = rx.next().await {
            if let Err(err) = tx.send(packet).await {
                println!("{:?}", err);
                break;
            }
        }
    });

    let out =
        client.scoped_client::<GreetingClientFactory<RpcController>>(1, 1, "test".to_string());
    let mut ctrl = RpcController::default();
    ctrl.timeout_ms = 1000;
    let input = SayHelloRequest {
        name: "fuck world".to_string(),
    };
    let ret = out.say_hello(ctrl, input).await.unwrap();
    assert_eq!(ret.greeting, "Hello fuck world!");
}

#[tokio::test]
async fn standalone_rpc_test() {
    use crate::proto::rpc_impl::standalone::{StandAloneClient, StandAloneServer};
    use crate::tunnel::tcp::{TcpTunnelConnector, TcpTunnelListener};

    let mut server = StandAloneServer::new(TcpTunnelListener::new(
        "tcp://0.0.0.0:33455".parse().unwrap(),
    ));
    let service = GreetingServer::new(GreetingService {
        delay_ms: 0,
        prefix: "Hello".to_string(),
    });
    server.registry().register(service, "test");
    server.serve().await.unwrap();

    tokio::time::sleep(std::time::Duration::from_millis(100)).await;

    let mut client = StandAloneClient::new(TcpTunnelConnector::new(
        "tcp://127.0.0.1:33455".parse().unwrap(),
    ));

    let out = client
        .scoped_client::<GreetingClientFactory<RpcController>>("test".to_string())
        .await
        .unwrap();

    let ctrl = RpcController::default();
    let input = SayHelloRequest {
        name: "world".to_string(),
    };
    let ret = out.say_hello(ctrl, input).await;
    assert_eq!(ret.unwrap().greeting, "Hello world!");

    let out = client
        .scoped_client::<GreetingClientFactory<RpcController>>("test".to_string())
        .await
        .unwrap();

    let ctrl = RpcController::default();
    let input = SayGoodbyeRequest {
        name: "world".to_string(),
    };
    let ret = out.say_goodbye(ctrl, input).await;
    assert_eq!(ret.unwrap().greeting, "Goodbye, world!");

    drop(client);

    tokio::time::sleep(std::time::Duration::from_secs(1)).await;
    assert_eq!(0, server.inflight_server());
}

#[tokio::test]
async fn test_bidirect_rpc_manager() {
    use crate::common::scoped_task::ScopedTask;
    use crate::proto::rpc_impl::bidirect::BidirectRpcManager;
    use crate::tunnel::tcp::{TcpTunnelConnector, TcpTunnelListener};
    use crate::tunnel::{TunnelConnector, TunnelListener};
    use tokio::sync::Notify;

    let c = BidirectRpcManager::new();
    let s = BidirectRpcManager::new();

    let service = GreetingServer::new(GreetingService {
        delay_ms: 0,
        prefix: "Hello Client".to_string(),
    });
    c.rpc_server().registry().register(service, "test");

    let service = GreetingServer::new(GreetingService {
        delay_ms: 0,
        prefix: "Hello Server".to_string(),
    });
    s.rpc_server().registry().register(service, "test");

    let server_test_done = Arc::new(Notify::new());
    let server_test_done_clone = server_test_done.clone();
    let mut tcp_listener = TcpTunnelListener::new("tcp://0.0.0.0:55443".parse().unwrap());
    let s_task: ScopedTask<()> = tokio::spawn(async move {
        tcp_listener.listen().await.unwrap();
        let tunnel = tcp_listener.accept().await.unwrap();
        s.run_with_tunnel(tunnel);

        let s_c = s
            .rpc_client()
            .scoped_client::<GreetingClientFactory<RpcController>>(1, 1, "test".to_string());
        let ret = s_c
            .say_hello(
                RpcController::default(),
                SayHelloRequest {
                    name: "world".to_string(),
                },
            )
            .await
            .unwrap();
        assert_eq!(ret.greeting, "Hello Client world!");
        println!("server done, {:?}", ret);

        server_test_done_clone.notify_one();

        s.wait().await;
    })
    .into();

    tokio::time::sleep(std::time::Duration::from_secs(1)).await;

    let mut tcp_connector = TcpTunnelConnector::new("tcp://0.0.0.0:55443".parse().unwrap());
    let c_tunnel = tcp_connector.connect().await.unwrap();
    c.run_with_tunnel(c_tunnel);

    let c_c = c
        .rpc_client()
        .scoped_client::<GreetingClientFactory<RpcController>>(1, 1, "test".to_string());
    let ret = c_c
        .say_hello(
            RpcController::default(),
            SayHelloRequest {
                name: "world".to_string(),
            },
        )
        .await
        .unwrap();
    assert_eq!(ret.greeting, "Hello Server world!");
    println!("client done, {:?}", ret);

    server_test_done.notified().await;
    drop(c);
    s_task.await.unwrap();
}
