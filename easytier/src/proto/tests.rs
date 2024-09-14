include!(concat!(env!("OUT_DIR"), "/tests.rs"));

use std::sync::{Arc, Mutex};

use futures::StreamExt as _;
use tokio::task::JoinSet;

use super::rpc_impl::RpcController;

#[derive(Clone)]
struct GreetingService {
    delay_ms: u64,
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
            greeting: format!("Hello, {}!", input.name),
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

        let mut server_t = rpc_server.get_transport().unwrap();
        let mut client_t = client.get_transport().unwrap();

        let tasks = Arc::new(Mutex::new(JoinSet::new()));
        let (mut rx, tx) = (server_t.get_stream(), client_t.get_sink());

        tasks.lock().unwrap().spawn(async move {
            while let Some(Ok(packet)) = rx.next().await {
                if let Err(err) = tx.send(packet).await {
                    println!("{:?}", err);
                    break;
                }
            }
        });

        let (mut rx, tx) = (client_t.get_stream(), server_t.get_sink());
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
    let ctx = TestContext::new();

    let server = GreetingServer::new(GreetingService { delay_ms: 0 });
    ctx.server.registry().register(server);

    let out = ctx
        .client
        .scoped_client::<GreetingClientFactory<RpcController>>(1, 1);

    // small size req and resp

    let ctrl = RpcController {};
    let input = SayHelloRequest {
        name: "world".to_string(),
    };
    let ret = out.say_hello(ctrl, input).await;
    assert_eq!(ret.unwrap().greeting, "Hello, world!");

    let ctrl = RpcController {};
    let input = SayGoodbyeRequest {
        name: "world".to_string(),
    };
    let ret = out.say_goodbye(ctrl, input).await;
    assert_eq!(ret.unwrap().greeting, "Goodbye, world!");

    // large size req and resp
    let ctrl = RpcController {};
    let name = random_string(20 * 1024 * 1024);
    let input = SayGoodbyeRequest { name: name.clone() };
    let ret = out.say_goodbye(ctrl, input).await;
    assert_eq!(ret.unwrap().greeting, format!("Goodbye, {}!", name));

    assert_eq!(0, ctx.client.inflight_count());
    assert_eq!(0, ctx.server.inflight_count());
}

#[tokio::test]
async fn rpc_timeout_test() {
    let ctx = TestContext::new();

    let server = GreetingServer::new(GreetingService { delay_ms: 10000 });
    ctx.server.registry().register(server);

    let out = ctx
        .client
        .scoped_client::<GreetingClientFactory<RpcController>>(1, 1);

    let ctrl = RpcController {};
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
