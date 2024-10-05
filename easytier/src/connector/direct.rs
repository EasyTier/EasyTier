// try connect peers directly, with either its public ip or lan ip

use std::{net::SocketAddr, sync::Arc, time::Duration};

use crate::{
    common::{error::Error, global_ctx::ArcGlobalCtx, PeerId},
    peers::{
        peer_manager::PeerManager, peer_rpc::PeerRpcManager,
        peer_rpc_service::DirectConnectorManagerRpcServer,
    },
    proto::{
        peer_rpc::{
            DirectConnectorRpc, DirectConnectorRpcClientFactory, DirectConnectorRpcServer,
            GetIpListRequest, GetIpListResponse,
        },
        rpc_types::controller::BaseController,
    },
};

use crate::proto::cli::PeerConnInfo;
use anyhow::Context;
use rand::Rng;
use tokio::{task::JoinSet, time::timeout};
use tracing::Instrument;
use url::Host;

use super::create_connector_by_url;

pub const DIRECT_CONNECTOR_SERVICE_ID: u32 = 1;
pub const DIRECT_CONNECTOR_BLACKLIST_TIMEOUT_SEC: u64 = 300;

#[async_trait::async_trait]
pub trait PeerManagerForDirectConnector {
    async fn list_peers(&self) -> Vec<PeerId>;
    async fn list_peer_conns(&self, peer_id: PeerId) -> Option<Vec<PeerConnInfo>>;
    fn get_peer_rpc_mgr(&self) -> Arc<PeerRpcManager>;
}

#[async_trait::async_trait]
impl PeerManagerForDirectConnector for PeerManager {
    async fn list_peers(&self) -> Vec<PeerId> {
        let mut ret = vec![];

        let routes = self.list_routes().await;
        for r in routes
            .iter()
            .filter(|r| r.feature_flag.map(|r| !r.is_public_server).unwrap_or(true))
        {
            ret.push(r.peer_id);
        }

        ret
    }

    async fn list_peer_conns(&self, peer_id: PeerId) -> Option<Vec<PeerConnInfo>> {
        self.get_peer_map().list_peer_conns(peer_id).await
    }

    fn get_peer_rpc_mgr(&self) -> Arc<PeerRpcManager> {
        self.get_peer_rpc_mgr()
    }
}

#[derive(Hash, Eq, PartialEq, Clone)]
struct DstBlackListItem(PeerId, String);

#[derive(Hash, Eq, PartialEq, Clone)]
struct DstListenerUrlBlackListItem(PeerId, url::Url);

struct DirectConnectorManagerData {
    global_ctx: ArcGlobalCtx,
    peer_manager: Arc<PeerManager>,
    dst_blacklist: timedmap::TimedMap<DstBlackListItem, ()>,
    dst_listener_blacklist: timedmap::TimedMap<DstListenerUrlBlackListItem, ()>,
}

impl DirectConnectorManagerData {
    pub fn new(global_ctx: ArcGlobalCtx, peer_manager: Arc<PeerManager>) -> Self {
        Self {
            global_ctx,
            peer_manager,
            dst_blacklist: timedmap::TimedMap::new(),
            dst_listener_blacklist: timedmap::TimedMap::new(),
        }
    }
}

impl std::fmt::Debug for DirectConnectorManagerData {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DirectConnectorManagerData")
            .field("peer_manager", &self.peer_manager)
            .finish()
    }
}

pub struct DirectConnectorManager {
    global_ctx: ArcGlobalCtx,
    data: Arc<DirectConnectorManagerData>,

    tasks: JoinSet<()>,
}

impl DirectConnectorManager {
    pub fn new(global_ctx: ArcGlobalCtx, peer_manager: Arc<PeerManager>) -> Self {
        Self {
            global_ctx: global_ctx.clone(),
            data: Arc::new(DirectConnectorManagerData::new(global_ctx, peer_manager)),
            tasks: JoinSet::new(),
        }
    }

    pub fn run(&mut self) {
        if self.global_ctx.get_flags().disable_p2p {
            return;
        }

        self.run_as_server();
        self.run_as_client();
    }

    pub fn run_as_server(&mut self) {
        self.data
            .peer_manager
            .get_peer_rpc_mgr()
            .rpc_server()
            .registry()
            .register(
                DirectConnectorRpcServer::new(DirectConnectorManagerRpcServer::new(
                    self.global_ctx.clone(),
                )),
                &self.data.global_ctx.get_network_name(),
            );
    }

    pub fn run_as_client(&mut self) {
        let data = self.data.clone();
        let my_peer_id = self.data.peer_manager.my_peer_id();
        self.tasks.spawn(
            async move {
                loop {
                    let peers = data.peer_manager.list_peers().await;
                    let mut tasks = JoinSet::new();
                    for peer_id in peers {
                        if peer_id == my_peer_id {
                            continue;
                        }
                        tasks.spawn(Self::do_try_direct_connect(data.clone(), peer_id));
                    }

                    while let Some(task_ret) = tasks.join_next().await {
                        tracing::debug!(?task_ret, ?my_peer_id, "direct connect task ret");
                    }
                    tokio::time::sleep(std::time::Duration::from_secs(5)).await;
                }
            }
            .instrument(
                tracing::info_span!("direct_connector_client", my_id = ?self.global_ctx.id),
            ),
        );
    }

    async fn do_try_connect_to_ip(
        data: Arc<DirectConnectorManagerData>,
        dst_peer_id: PeerId,
        addr: String,
    ) -> Result<(), Error> {
        data.dst_blacklist.cleanup();
        if data
            .dst_blacklist
            .contains(&DstBlackListItem(dst_peer_id.clone(), addr.clone()))
        {
            tracing::debug!("try_connect_to_ip failed, addr in blacklist: {}", addr);
            return Err(Error::UrlInBlacklist);
        }

        let connector = create_connector_by_url(&addr, &data.global_ctx).await?;
        let (peer_id, conn_id) = timeout(
            std::time::Duration::from_secs(5),
            data.peer_manager.try_connect(connector),
        )
        .await??;

        // let (peer_id, conn_id) = data.peer_manager.try_connect(connector).await?;

        if peer_id != dst_peer_id {
            tracing::info!(
                "connect to ip succ: {}, but peer id mismatch, expect: {}, actual: {}",
                addr,
                dst_peer_id,
                peer_id
            );
            data.peer_manager
                .get_peer_map()
                .close_peer_conn(peer_id, &conn_id)
                .await?;
            return Err(Error::InvalidUrl(addr));
        }
        Ok(())
    }

    #[tracing::instrument]
    async fn try_connect_to_ip(
        data: Arc<DirectConnectorManagerData>,
        dst_peer_id: PeerId,
        addr: String,
    ) -> Result<(), Error> {
        let mut rand_gen = rand::rngs::OsRng::default();
        let backoff_ms = vec![1000, 2000, 4000];
        let mut backoff_idx = 0;

        loop {
            let ret = Self::do_try_connect_to_ip(data.clone(), dst_peer_id, addr.clone()).await;
            tracing::debug!(?ret, ?dst_peer_id, ?addr, "try_connect_to_ip return");
            if matches!(ret, Err(Error::UrlInBlacklist) | Ok(_)) {
                return ret;
            }

            if backoff_idx < backoff_ms.len() {
                let delta = backoff_ms[backoff_idx] >> 1;
                assert!(delta > 0);
                assert!(delta < backoff_ms[backoff_idx]);

                tokio::time::sleep(Duration::from_millis(
                    (backoff_ms[backoff_idx] + rand_gen.gen_range(-delta..delta)) as u64,
                ))
                .await;

                backoff_idx += 1;
                continue;
            } else {
                data.dst_blacklist.insert(
                    DstBlackListItem(dst_peer_id.clone(), addr.clone()),
                    (),
                    std::time::Duration::from_secs(DIRECT_CONNECTOR_BLACKLIST_TIMEOUT_SEC),
                );

                return ret;
            }
        }
    }

    #[tracing::instrument]
    async fn do_try_direct_connect_internal(
        data: Arc<DirectConnectorManagerData>,
        dst_peer_id: PeerId,
        ip_list: GetIpListResponse,
    ) -> Result<(), Error> {
        data.dst_listener_blacklist.cleanup();

        let enable_ipv6 = data.global_ctx.get_flags().enable_ipv6;
        let available_listeners = ip_list
            .listeners
            .into_iter()
            .map(Into::<url::Url>::into)
            .filter_map(|l| if l.scheme() != "ring" { Some(l) } else { None })
            .filter(|l| l.port().is_some() && l.host().is_some())
            .filter(|l| {
                !data
                    .dst_listener_blacklist
                    .contains(&DstListenerUrlBlackListItem(dst_peer_id.clone(), l.clone()))
            })
            .filter(|l| enable_ipv6 || !matches!(l.host().unwrap().to_owned(), Host::Ipv6(_)))
            .collect::<Vec<_>>();

        tracing::debug!(?available_listeners, "got available listeners");

        let mut listener = available_listeners.get(0).ok_or(anyhow::anyhow!(
            "peer {} have no valid listener",
            dst_peer_id
        ))?;

        // if have default listener, use it first
        listener = available_listeners
            .iter()
            .find(|l| l.scheme() == data.global_ctx.get_flags().default_protocol)
            .unwrap_or(listener);

        let mut tasks = JoinSet::new();

        let listener_host = listener.socket_addrs(|| None).unwrap().pop();
        match listener_host {
            Some(SocketAddr::V4(_)) => {
                ip_list.interface_ipv4s.iter().for_each(|ip| {
                    let mut addr = (*listener).clone();
                    if addr.set_host(Some(ip.to_string().as_str())).is_ok() {
                        tasks.spawn(Self::try_connect_to_ip(
                            data.clone(),
                            dst_peer_id.clone(),
                            addr.to_string(),
                        ));
                    } else {
                        tracing::error!(
                            ?ip,
                            ?listener,
                            ?dst_peer_id,
                            "failed to set host for interface ipv4"
                        );
                    }
                });

                if let Some(public_ipv4) = ip_list.public_ipv4 {
                    let mut addr = (*listener).clone();
                    if addr
                        .set_host(Some(public_ipv4.to_string().as_str()))
                        .is_ok()
                    {
                        tasks.spawn(Self::try_connect_to_ip(
                            data.clone(),
                            dst_peer_id.clone(),
                            addr.to_string(),
                        ));
                    } else {
                        tracing::error!(
                            ?public_ipv4,
                            ?listener,
                            ?dst_peer_id,
                            "failed to set host for public ipv4"
                        );
                    }
                }
            }
            Some(SocketAddr::V6(_)) => {
                ip_list.interface_ipv6s.iter().for_each(|ip| {
                    let mut addr = (*listener).clone();
                    if addr
                        .set_host(Some(format!("[{}]", ip.to_string()).as_str()))
                        .is_ok()
                    {
                        tasks.spawn(Self::try_connect_to_ip(
                            data.clone(),
                            dst_peer_id.clone(),
                            addr.to_string(),
                        ));
                    } else {
                        tracing::error!(
                            ?ip,
                            ?listener,
                            ?dst_peer_id,
                            "failed to set host for interface ipv6"
                        );
                    }
                });

                if let Some(public_ipv6) = ip_list.public_ipv6 {
                    let mut addr = (*listener).clone();
                    if addr
                        .set_host(Some(format!("[{}]", public_ipv6.to_string()).as_str()))
                        .is_ok()
                    {
                        tasks.spawn(Self::try_connect_to_ip(
                            data.clone(),
                            dst_peer_id.clone(),
                            addr.to_string(),
                        ));
                    } else {
                        tracing::error!(
                            ?public_ipv6,
                            ?listener,
                            ?dst_peer_id,
                            "failed to set host for public ipv6"
                        );
                    }
                }
            }
            p => {
                tracing::error!(?p, ?listener, "failed to parse ip version from listener");
            }
        }

        let mut has_succ = false;
        while let Some(ret) = tasks.join_next().await {
            match ret {
                Ok(Ok(_)) => {
                    has_succ = true;
                    tracing::info!(
                        ?dst_peer_id,
                        ?listener,
                        "try direct connect to peer success"
                    );
                    break;
                }
                Ok(Err(e)) => {
                    tracing::info!(?e, "try direct connect to peer failed");
                }
                Err(e) => {
                    tracing::error!(?e, "try direct connect to peer task join failed");
                }
            }
        }

        if !has_succ {
            data.dst_listener_blacklist.insert(
                DstListenerUrlBlackListItem(dst_peer_id.clone(), listener.clone()),
                (),
                std::time::Duration::from_secs(DIRECT_CONNECTOR_BLACKLIST_TIMEOUT_SEC),
            );
        }

        Ok(())
    }

    #[tracing::instrument]
    async fn do_try_direct_connect(
        data: Arc<DirectConnectorManagerData>,
        dst_peer_id: PeerId,
    ) -> Result<(), Error> {
        let peer_manager = data.peer_manager.clone();
        // check if we have direct connection with dst_peer_id
        if let Some(c) = peer_manager.list_peer_conns(dst_peer_id).await {
            // currently if we have any type of direct connection (udp or tcp), we will not try to connect
            if !c.is_empty() {
                return Ok(());
            }
        }

        tracing::debug!("try direct connect to peer: {}", dst_peer_id);

        let rpc_stub = peer_manager
            .get_peer_rpc_mgr()
            .rpc_client()
            .scoped_client::<DirectConnectorRpcClientFactory<BaseController>>(
                peer_manager.my_peer_id(),
                dst_peer_id,
                data.global_ctx.get_network_name(),
            );

        let ip_list = rpc_stub
            .get_ip_list(BaseController::default(), GetIpListRequest {})
            .await
            .with_context(|| format!("get ip list from peer {}", dst_peer_id))?;

        tracing::info!(ip_list = ?ip_list, dst_peer_id = ?dst_peer_id, "got ip list");

        Self::do_try_direct_connect_internal(data, dst_peer_id, ip_list).await
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use crate::{
        connector::direct::{
            DirectConnectorManager, DirectConnectorManagerData, DstBlackListItem,
            DstListenerUrlBlackListItem,
        },
        instance::listeners::ListenerManager,
        peers::tests::{
            connect_peer_manager, create_mock_peer_manager, wait_route_appear,
            wait_route_appear_with_cost,
        },
        proto::peer_rpc::GetIpListResponse,
    };

    #[rstest::rstest]
    #[tokio::test]
    async fn direct_connector_basic_test(
        #[values("tcp", "udp", "wg")] proto: &str,
        #[values("true", "false")] ipv6: bool,
    ) {
        if ipv6 && proto != "udp" {
            return;
        }

        let p_a = create_mock_peer_manager().await;
        let p_b = create_mock_peer_manager().await;
        let p_c = create_mock_peer_manager().await;
        connect_peer_manager(p_a.clone(), p_b.clone()).await;
        connect_peer_manager(p_b.clone(), p_c.clone()).await;

        wait_route_appear(p_a.clone(), p_c.clone()).await.unwrap();

        let mut dm_a = DirectConnectorManager::new(p_a.get_global_ctx(), p_a.clone());
        let mut dm_c = DirectConnectorManager::new(p_c.get_global_ctx(), p_c.clone());

        dm_a.run_as_client();
        dm_c.run_as_server();

        if !ipv6 {
            let port = if proto == "wg" { 11040 } else { 11041 };
            p_c.get_global_ctx().config.set_listeners(vec![format!(
                "{}://0.0.0.0:{}",
                proto, port
            )
            .parse()
            .unwrap()]);
        }
        let mut f = p_c.get_global_ctx().config.get_flags();
        f.enable_ipv6 = ipv6;
        p_c.get_global_ctx().config.set_flags(f);
        let mut lis_c = ListenerManager::new(p_c.get_global_ctx(), p_c.clone());
        lis_c.prepare_listeners().await.unwrap();

        lis_c.run().await.unwrap();

        wait_route_appear_with_cost(p_a.clone(), p_c.my_peer_id(), Some(1))
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn direct_connector_scheme_blacklist() {
        let p_a = create_mock_peer_manager().await;
        let data = Arc::new(DirectConnectorManagerData::new(
            p_a.get_global_ctx(),
            p_a.clone(),
        ));
        let mut ip_list = GetIpListResponse::default();
        ip_list
            .listeners
            .push("tcp://127.0.0.1:10222".parse().unwrap());

        ip_list
            .interface_ipv4s
            .push("127.0.0.1".parse::<std::net::Ipv4Addr>().unwrap().into());

        DirectConnectorManager::do_try_direct_connect_internal(data.clone(), 1, ip_list.clone())
            .await
            .unwrap();

        assert!(data
            .dst_listener_blacklist
            .contains(&DstListenerUrlBlackListItem(
                1,
                "tcp://127.0.0.1:10222".parse().unwrap()
            )));

        assert!(data
            .dst_blacklist
            .contains(&DstBlackListItem(1, ip_list.listeners[0].to_string())));
    }
}
