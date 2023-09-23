// try connect peers directly, with either its public ip or lan ip

use std::sync::Arc;

use crate::{
    common::{
        constants::{self, DIRECT_CONNECTOR_BLACKLIST_TIMEOUT_SEC},
        error::Error,
        global_ctx::ArcGlobalCtx,
        network::IPCollector,
    },
    peers::{peer_manager::PeerManager, peer_rpc::PeerRpcManager, PeerId},
};

use easytier_rpc::{peer::GetIpListResponse, PeerConnInfo};
use tokio::{task::JoinSet, time::timeout};
use tracing::Instrument;

use super::create_connector_by_url;

#[tarpc::service]
pub trait DirectConnectorRpc {
    async fn get_ip_list() -> GetIpListResponse;
}

#[async_trait::async_trait]
pub trait PeerManagerForDirectConnector {
    async fn list_peers(&self) -> Vec<PeerId>;
    async fn list_peer_conns(&self, peer_id: &PeerId) -> Option<Vec<PeerConnInfo>>;
    fn get_peer_rpc_mgr(&self) -> Arc<PeerRpcManager>;
}

#[async_trait::async_trait]
impl PeerManagerForDirectConnector for PeerManager {
    async fn list_peers(&self) -> Vec<PeerId> {
        let mut ret = vec![];

        let routes = self.list_routes().await;
        for r in routes.iter() {
            ret.push(r.peer_id.parse().unwrap());
        }

        ret
    }

    async fn list_peer_conns(&self, peer_id: &PeerId) -> Option<Vec<PeerConnInfo>> {
        self.get_peer_map().list_peer_conns(peer_id).await
    }

    fn get_peer_rpc_mgr(&self) -> Arc<PeerRpcManager> {
        self.get_peer_rpc_mgr()
    }
}

#[derive(Clone)]
struct DirectConnectorManagerRpcServer {
    // TODO: this only cache for one src peer, should make it global
    ip_list_collector: Arc<IPCollector>,
}

#[tarpc::server]
impl DirectConnectorRpc for DirectConnectorManagerRpcServer {
    async fn get_ip_list(self, _: tarpc::context::Context) -> GetIpListResponse {
        return self.ip_list_collector.collect_ip_addrs().await;
    }
}

impl DirectConnectorManagerRpcServer {
    pub fn new(ip_collector: Arc<IPCollector>) -> Self {
        Self {
            ip_list_collector: ip_collector,
        }
    }
}

#[derive(Hash, Eq, PartialEq, Clone)]
struct DstBlackListItem(PeerId, String);

struct DirectConnectorManagerData {
    global_ctx: ArcGlobalCtx,
    peer_manager: Arc<PeerManager>,
    dst_blacklist: timedmap::TimedMap<DstBlackListItem, ()>,
}

impl std::fmt::Debug for DirectConnectorManagerData {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DirectConnectorManagerData")
            .field("peer_manager", &self.peer_manager)
            .finish()
    }
}

pub struct DirectConnectorManager {
    my_node_id: uuid::Uuid,
    global_ctx: ArcGlobalCtx,
    data: Arc<DirectConnectorManagerData>,

    tasks: JoinSet<()>,
}

impl DirectConnectorManager {
    pub fn new(
        my_node_id: uuid::Uuid,
        global_ctx: ArcGlobalCtx,
        peer_manager: Arc<PeerManager>,
    ) -> Self {
        Self {
            my_node_id,
            global_ctx: global_ctx.clone(),
            data: Arc::new(DirectConnectorManagerData {
                global_ctx,
                peer_manager,
                dst_blacklist: timedmap::TimedMap::new(),
            }),
            tasks: JoinSet::new(),
        }
    }

    pub fn run(&mut self) {
        self.run_as_server();
        self.run_as_client();
    }

    pub fn run_as_server(&mut self) {
        self.data.peer_manager.get_peer_rpc_mgr().run_service(
            constants::DIRECT_CONNECTOR_SERVICE_ID,
            DirectConnectorManagerRpcServer::new(self.global_ctx.get_ip_collector()).serve(),
        );
    }

    pub fn run_as_client(&mut self) {
        let data = self.data.clone();
        let my_node_id = self.my_node_id.clone();
        self.tasks.spawn(
            async move {
                loop {
                    let peers = data.peer_manager.list_peers().await;
                    let mut tasks = JoinSet::new();
                    for peer_id in peers {
                        if peer_id == my_node_id {
                            continue;
                        }
                        tasks.spawn(Self::do_try_direct_connect(data.clone(), peer_id));
                    }

                    while let Some(task_ret) = tasks.join_next().await {
                        tracing::trace!(?task_ret, "direct connect task ret");
                    }
                    tokio::time::sleep(std::time::Duration::from_secs(5)).await;
                }
            }
            .instrument(tracing::info_span!("direct_connector_client", my_id = ?self.my_node_id)),
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
            tracing::trace!("try_connect_to_ip failed, addr in blacklist: {}", addr);
            return Err(Error::UrlInBlacklist);
        }

        let connector = create_connector_by_url(&addr, data.global_ctx.get_ip_collector()).await?;
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
                .close_peer_conn(&peer_id, &conn_id)
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
    ) {
        let ret = Self::do_try_connect_to_ip(data.clone(), dst_peer_id, addr.clone()).await;
        if let Err(e) = ret {
            if !matches!(e, Error::UrlInBlacklist) {
                tracing::info!(
                    "try_connect_to_ip failed: {:?}, peer_id: {}",
                    e,
                    dst_peer_id
                );
                data.dst_blacklist.insert(
                    DstBlackListItem(dst_peer_id.clone(), addr.clone()),
                    (),
                    std::time::Duration::from_secs(DIRECT_CONNECTOR_BLACKLIST_TIMEOUT_SEC),
                );
            }
        } else {
            log::info!("try_connect_to_ip success, peer_id: {}", dst_peer_id);
        }
    }

    #[tracing::instrument]
    async fn do_try_direct_connect(
        data: Arc<DirectConnectorManagerData>,
        dst_peer_id: PeerId,
    ) -> Result<(), Error> {
        let peer_manager = data.peer_manager.clone();
        // check if we have direct connection with dst_peer_id
        if let Some(c) = peer_manager.list_peer_conns(&dst_peer_id).await {
            // currently if we have any type of direct connection (udp or tcp), we will not try to connect
            if !c.is_empty() {
                return Ok(());
            }
        }

        log::trace!("try direct connect to peer: {}", dst_peer_id);

        let ip_list = peer_manager
            .get_peer_rpc_mgr()
            .do_client_rpc_scoped(1, dst_peer_id, |c| async {
                let client =
                    DirectConnectorRpcClient::new(tarpc::client::Config::default(), c).spawn();
                let ip_list = client.get_ip_list(tarpc::context::current()).await;
                tracing::info!(ip_list = ?ip_list, dst_peer_id = ?dst_peer_id, "got ip list");
                ip_list
            })
            .await?;

        let mut tasks = JoinSet::new();
        ip_list.interface_ipv4s.iter().for_each(|ip| {
            let addr = format!("{}://{}:{}", "tcp", ip, 11010);
            tasks.spawn(Self::try_connect_to_ip(
                data.clone(),
                dst_peer_id.clone(),
                addr,
            ));
        });

        let addr = format!("{}://{}:{}", "tcp", ip_list.public_ipv4.clone(), 11010);
        tasks.spawn(Self::try_connect_to_ip(
            data.clone(),
            dst_peer_id.clone(),
            addr,
        ));

        while let Some(ret) = tasks.join_next().await {
            if let Err(e) = ret {
                log::error!("join direct connect task failed: {:?}", e);
            }
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use crate::{
        connector::direct::DirectConnectorManager,
        instance::listeners::ListenerManager,
        peers::tests::{
            connect_peer_manager, create_mock_peer_manager, wait_route_appear,
            wait_route_appear_with_cost,
        },
        tunnels::tcp_tunnel::TcpTunnelListener,
    };

    #[tokio::test]
    async fn direct_connector_basic_test() {
        let p_a = create_mock_peer_manager().await;
        let p_b = create_mock_peer_manager().await;
        let p_c = create_mock_peer_manager().await;
        connect_peer_manager(p_a.clone(), p_b.clone()).await;
        connect_peer_manager(p_b.clone(), p_c.clone()).await;

        wait_route_appear(p_a.clone(), p_c.my_node_id())
            .await
            .unwrap();

        let mut dm_a =
            DirectConnectorManager::new(p_a.my_node_id(), p_a.get_global_ctx(), p_a.clone());
        let mut dm_c =
            DirectConnectorManager::new(p_c.my_node_id(), p_c.get_global_ctx(), p_c.clone());

        dm_a.run_as_client();
        dm_c.run_as_server();

        let mut lis_c = ListenerManager::new(
            p_c.my_node_id(),
            p_c.get_global_ctx().net_ns.clone(),
            p_c.clone(),
        );

        lis_c
            .add_listener(TcpTunnelListener::new(
                "tcp://0.0.0.0:11010".parse().unwrap(),
            ))
            .await
            .unwrap();

        lis_c.run().await.unwrap();

        wait_route_appear_with_cost(p_a.clone(), p_c.my_node_id(), Some(1))
            .await
            .unwrap();
    }
}
