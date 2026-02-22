use crate::dns::node_mgr::DnsNodeMgr;
use crate::dns::utils::addr::NameServerAddr;
use crate::peers::peer_manager::PeerManager;
use crate::proto::dns::DnsNodeMgrRpcServer;
use derivative::Derivative;
use derive_more::{Deref, DerefMut, From, Into};
use hickory_proto::rr::Record;
use hickory_proto::serialize::binary::BinEncoder;
use hickory_proto::xfer::Protocol;
use hickory_server::{
    authority::{Catalog, MessageResponse},
    server::{Request, RequestHandler, ResponseHandler, ResponseInfo},
    ServerFuture,
};
use itertools::Itertools;
use parking_lot::Mutex;
use std::collections::HashSet;
use std::io;
use std::{sync::Arc, time::Duration};
use tokio::net::{TcpListener, UdpSocket};
use tokio::{sync::RwLock, task::JoinHandle};
use tokio_util::sync::CancellationToken;

#[derive(Clone)]
pub struct DynamicCatalog {
    inner: Arc<RwLock<Catalog>>,
}

impl DynamicCatalog {
    pub fn new() -> Self {
        Self {
            inner: Arc::new(RwLock::new(Catalog::new())),
        }
    }

    pub async fn replace(&self, new: Catalog) {
        *self.inner.write().await = new;
    }
}

#[async_trait::async_trait]
impl RequestHandler for DynamicCatalog {
    async fn handle_request<R: ResponseHandler>(
        &self,
        request: &Request,
        response_handle: R,
    ) -> ResponseInfo {
        self.inner
            .read()
            .await
            .handle_request(request, response_handle)
            .await
    }
}

struct DnsServerRuntime {
    token: CancellationToken,
    task: JoinHandle<()>,
}

impl DnsServerRuntime {
    async fn stop(self) -> anyhow::Result<()> {
        self.token.cancel();
        self.task.await?;
        Ok(())
    }

    fn start<T: RequestHandler>(mut server: ServerFuture<T>) -> Self {
        Self {
            token: server.shutdown_token().clone(),
            task: tokio::spawn(async move {
                server
                    .block_until_done()
                    .await
                    .unwrap_or_else(|e| tracing::error!("DNS server exited with error: {:?}", e));
            }),
        }
    }
}

// ResponseWrapper for serializing DNS responses into a byte buffer.
// Used by the address hijacking NIC packet filter to produce DNS replies in-place.
#[derive(Debug, Clone, From, Into, Deref, DerefMut)]
struct Response(Arc<Mutex<Vec<u8>>>);

impl Response {
    pub fn new(capacity: usize) -> Self {
        Self(Arc::new(Mutex::new(Vec::with_capacity(capacity))))
    }

    pub fn into_inner(self) -> Option<Vec<u8>> {
        Arc::into_inner(self.0).map(Mutex::into_inner)
    }
}

trait RecordIter<'r>: Iterator<Item = &'r Record> + Send + 'r {}
impl<'r, T> RecordIter<'r> for T where T: Iterator<Item = &'r Record> + Send + 'r {}

#[async_trait::async_trait]
impl ResponseHandler for Response {
    async fn send_response<'r>(
        &mut self,
        response: MessageResponse<
            '_,
            'r,
            impl RecordIter<'r>,
            impl RecordIter<'r>,
            impl RecordIter<'r>,
            impl RecordIter<'r>,
        >,
    ) -> io::Result<ResponseInfo> {
        let max_size = if let Some(edns) = response.get_edns() {
            edns.max_payload()
        } else {
            hickory_proto::udp::MAX_RECEIVE_BUFFER_SIZE as u16
        };

        let mut this = self.lock();
        let mut encoder = BinEncoder::new(this.as_mut());
        encoder.set_max_size(max_size);
        response
            .destructive_emit(&mut encoder)
            .map_err(io::Error::other)
    }
}

#[derive(Derivative)]
#[derivative(Debug)]
pub struct DnsServer {
    mgr: Arc<DnsNodeMgr>,

    #[derivative(Debug = "ignore")]
    catalog: DynamicCatalog,
}

const DNS_SERVER_LISTENER_TCP_TIMEOUT: Duration = Duration::from_secs(5);

impl DnsServer {
    pub fn new(peer_mgr: Arc<PeerManager>) -> Self {
        let mgr = Arc::new(DnsNodeMgr::new());
        peer_mgr
            .get_peer_rpc_mgr()
            .rpc_server()
            .registry()
            .register(
                DnsNodeMgrRpcServer::new_arc(mgr.clone()),
                &peer_mgr.get_global_ctx_ref().get_network_name(),
            );

        Self {
            mgr,
            catalog: DynamicCatalog::new(),
        }
    }

    async fn reload_addresses(
        &self,
        addresses: impl IntoIterator<Item = NameServerAddr>,
        current: &mut HashSet<NameServerAddr>,
    ) {
        let addresses = addresses.into_iter().collect::<HashSet<_>>();

        let added = addresses.difference(&current).cloned().collect_vec();
        let removed = current.difference(&addresses).cloned().collect_vec();

        if added.is_empty() && removed.is_empty() {
            return;
        }

        *current = addresses;

        // TODO
    }

    async fn reload_listeners(
        &self,
        listeners: impl IntoIterator<Item = NameServerAddr>,
        runtime: &mut Option<DnsServerRuntime>,
    ) -> anyhow::Result<()> {
        if let Some(old) = runtime.take() {
            old.stop().await?;
        }

        let mut new = ServerFuture::new(self.catalog.clone());
        for listener in listeners {
            match listener.protocol {
                Protocol::Udp => match UdpSocket::bind(listener.addr).await {
                    Ok(socket) => new.register_socket(socket),
                    Err(e) => tracing::error!("failed to bind udp socket {}: {}", listener.addr, e),
                },
                Protocol::Tcp => match TcpListener::bind(listener.addr).await {
                    Ok(listener) => {
                        new.register_listener(listener, DNS_SERVER_LISTENER_TCP_TIMEOUT)
                    }
                    Err(e) => {
                        tracing::error!("failed to bind tcp listener {}: {}", listener.addr, e)
                    }
                },
                _ => unimplemented!(),
            }
        }

        runtime.replace(DnsServerRuntime::start(new));

        Ok(())
    }

    pub async fn run(&self) {
        let dirty = &self.mgr.dirty;

        tokio::join!(
            async {
                loop {
                    dirty.catalog.notified().await;
                    if dirty.catalog.reset() {
                        self.catalog.replace(self.mgr.catalog()).await;
                    }
                    tokio::time::sleep(Duration::from_secs(1)).await;
                }
            },
            async {
                let mut addresses = HashSet::new();
                loop {
                    dirty.addresses.notified().await;
                    if dirty.addresses.reset() {
                        self.reload_addresses(self.mgr.iter_addresses(), &mut addresses)
                            .await;
                    }
                    tokio::time::sleep(Duration::from_secs(1)).await;
                }
            },
            async {
                let mut runtime = None;
                loop {
                    dirty.listeners.notified().await;
                    if dirty.listeners.reset() {
                        if let Err(e) = self
                            .reload_listeners(self.mgr.iter_listeners(), &mut runtime)
                            .await
                        {
                            tracing::error!("failed to reload listeners: {:?}", e);
                            dirty.listeners.mark();
                        }
                    }
                    tokio::time::sleep(Duration::from_secs(1)).await;
                }
            },
        );
    }
}
