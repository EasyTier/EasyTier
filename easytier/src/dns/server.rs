use super::{utils::NameServerAddr, zone::Zone};
use crate::dns::utils::DirtyFlag;
use crate::dns::zone::ZoneGroup;
use crate::proto::dns::DnsSnapshot;
use crate::proto::rpc_types;
use crate::proto::{
    dns::{DnsServerRpc, HeartbeatRequest, HeartbeatResponse},
    rpc_types::controller::BaseController,
};
use crate::utils::{DeterministicDigest, MapTryInto};
use anyhow::Error;
use hickory_proto::xfer::Protocol;
use hickory_server::{
    authority::Catalog,
    server::{Request, RequestHandler, ResponseHandler, ResponseInfo},
    ServerFuture,
};
use itertools::Itertools;
use moka::future::Cache;
use std::collections::HashSet;
use std::{sync::Arc, time::Duration};
use derivative::Derivative;
use derive_more::{Deref, DerefMut};
use tokio::net::{TcpListener, UdpSocket};
use tokio::{sync::RwLock, task::JoinHandle};
use tokio::sync::Notify;
use tokio_util::sync::CancellationToken;
use uuid::Uuid;

#[derive(Debug, Clone, Default)]
pub struct DnsClientInfo {
    digest: Vec<u8>,
    zones: ZoneGroup,
    addresses: HashSet<NameServerAddr>,
    listeners: HashSet<NameServerAddr>,
}

impl TryFrom<&DnsSnapshot> for DnsClientInfo {
    type Error = Error;

    fn try_from(value: &DnsSnapshot) -> Result<Self, Self::Error> {
        Ok(Self {
            digest: value.digest(),
            zones: (&value.zones).try_into()?,
            addresses: value.addresses.iter().map_try_into().try_collect()?,
            listeners: value.listeners.iter().map_try_into().try_collect()?,
        })
    }
}

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

// TODO: same as DnsPeerMgrDirtyState
#[derive(Debug, Default, Deref, DerefMut)]
pub struct DnsServerDirtyState {
    zones: DirtyFlag,
    addresses: DirtyFlag,
    listeners: DirtyFlag,
    #[deref]
    #[deref_mut]
    notify: Notify,
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


#[derive(Derivative)]
#[derivative(Debug)]
pub struct DnsServer {
    clients: Cache<Uuid, DnsClientInfo>,
    dirty: DnsServerDirtyState,

    #[derivative(Debug = "ignore")]
    catalog: DynamicCatalog,
}

const DNS_CLIENT_TTL: Duration = Duration::from_secs(5);
const DNS_SERVER_LISTENER_TCP_TIMEOUT: Duration = Duration::from_secs(5);

impl DnsServer {
    async fn reload_zones(&self) {
        let mut zones = vec![Zone::system()];
        let mut local = HashSet::<NameServerAddr>::new();

        for (_, info) in self.clients.iter() {
            zones.extend(info.zones.iter().cloned());
            local.extend(info.addresses.iter());
            local.extend(info.listeners.iter());
        }

        let mut catalog = Catalog::new();

        for zone in zones.iter_mut() {
            if let Some(forward) = zone.forward.as_mut() {
                forward
                    .name_servers
                    .retain(|ns| !local.contains(&ns.clone().into()));
            }
        }

        for zone in zones.iter() {
            catalog.upsert(
                zone.origin.clone(),
                zone.create_memory_authority().into_iter().collect(),
            );
        }

        for zone in zones.iter() {
            catalog.upsert(
                zone.origin.clone(),
                zone.create_forward_authority().into_iter().collect(),
            );
        }

        self.catalog.replace(catalog).await;
    }

    async fn reload_addresses(&self) {
        todo!()
    }

    async fn reload_listeners(&self, runtime: &mut Option<DnsServerRuntime>) -> anyhow::Result<()> {
        let listeners = self
            .clients
            .iter()
            .map(|(_, info)| info.listeners.into_iter())
            .flatten()
            .collect_vec();

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
        let dirty = &self.dirty;
        let mut runtime = None;
        loop {
            dirty.notified().await;

            if dirty.zones.reset() {
                self.reload_zones().await;
            }

            if dirty.addresses.reset() {
                self.reload_addresses().await;
            }

            if dirty.listeners.reset() {
                if let Err(e) = self.reload_listeners(&mut runtime).await {
                    tracing::error!("failed to reload listeners: {:?}", e);
                    self.dirty.listeners.mark();
                    self.dirty.notify_one();
                }
            }

            tokio::time::sleep(Duration::from_secs(1)).await;
        }
    }

    // pub async fn run(&self) {
    //     let server = self.clone();
    //     tokio::spawn(async move {
    //         loop {
    //             tokio::time::sleep(Duration::from_secs(5)).await;
    //             let mut expired = Vec::new();
    //             let now = Instant::now();
    //
    //             let mut clients_guard = server.clients.write().await;
    //             // Check expired
    //             for (id, (_, last_heartbeat, _)) in clients_guard.iter() {
    //                 if now.duration_since(*last_heartbeat) > Duration::from_secs(30) {
    //                     expired.push(*id);
    //                 }
    //             }
    //
    //             let mut changed = !expired.is_empty();
    //             for id in expired {
    //                 clients_guard.remove(&id);
    //             }
    //             drop(clients_guard);
    //
    //             if changed {
    //                 server.rebuild_catalog().await;
    //             }
    //         }
    //     });
    // }
    //
    // async fn update_listeners_from_clients(&self) {
    //     let guard = self.clients.read().await;
    //     // Collect all unique listeners
    //     let mut listeners = std::collections::HashSet::new();
    //     for (_, (snapshot, _, _)) in guard.iter() {
    //         for listener in &snapshot.listeners {
    //             if let Ok(addr) = NameServerAddr::try_from(PbUrl::from(listener.clone())) {
    //                 // We need SocketAddr. NameServerAddr -> Url -> SocketAddrs -> SocketAddr.
    //                 // Or assume NameServerAddr stores SocketAddr.
    //                 if let Ok(url) = Url::parse(&addr.to_string()) {
    //                     if let Ok(addrs) = url.socket_addrs(|| None) {
    //                         listeners.extend(addrs);
    //                     }
    //                 }
    //             }
    //         }
    //     }
    //     drop(guard);
    //
    //     let listeners_vec: Vec<_> = listeners.into_iter().collect();
    //     // We should check if listeners changed before restarting server.
    //     // But update_listeners handles simple restart.
    //     // TODO: optimize to check diff.
    //
    //     let _ = self.update_listeners(&listeners_vec).await;
    // }
    //
    // pub async fn get_hijack_addresses(&self) -> Vec<SocketAddr> {
    //     let guard = self.clients.read().await;
    //     let mut addresses = std::collections::HashSet::new();
    //     for (_, (snapshot, _, _)) in guard.iter() {
    //         for addr in &snapshot.addresses {
    //             addresses.insert(SocketAddr::from(addr.clone()));
    //         }
    //     }
    //     addresses.into_iter().collect()
    // }
}

#[async_trait::async_trait]
impl DnsServerRpc for DnsServer {
    type Controller = BaseController;

    async fn heartbeat(
        &self,
        _: BaseController,
        input: HeartbeatRequest,
    ) -> rpc_types::error::Result<HeartbeatResponse> {
        let id = input
            .id
            .ok_or(anyhow::anyhow!(
                "missing id in heartbeat request: {:?}",
                input
            ))?
            .into();

        let resync = if let Some(snapshot) = input.snapshot.as_ref() {
            let new = DnsClientInfo::try_from(snapshot)?;
            let old = self.clients.get(&id).await.unwrap_or_default();
            if new.digest != old.digest {
                if new.zones != old.zones {
                    self.dirty.zones.mark();
                }
                if new.addresses != old.addresses {
                    self.dirty.addresses.mark();
                }
                if new.listeners != old.listeners {
                    self.dirty.listeners.mark();
                }

                self.clients.insert(id, new).await;
                self.dirty.notify_one();
            }
            false
        } else {
            self.clients
                .get(&id)
                .await
                .is_none_or(|info| info.digest != input.digest)
        };

        Ok(HeartbeatResponse { resync })
    }
}
