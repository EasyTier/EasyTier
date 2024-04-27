use std::{collections::BTreeSet, sync::Arc};

use dashmap::{DashMap, DashSet};
use tokio::{
    sync::{broadcast::Receiver, mpsc, Mutex},
    task::JoinSet,
    time::timeout,
};

use crate::{
    common::PeerId, peers::peer_conn::PeerConnId, rpc as easytier_rpc, tunnel::TunnelConnector,
};

use crate::{
    common::{
        error::Error,
        global_ctx::{ArcGlobalCtx, GlobalCtxEvent},
        netns::NetNS,
    },
    connector::set_bind_addr_for_peer_connector,
    peers::peer_manager::PeerManager,
    rpc::{
        connector_manage_rpc_server::ConnectorManageRpc, Connector, ConnectorStatus,
        ListConnectorRequest, ManageConnectorRequest,
    },
    use_global_var,
};

use super::create_connector_by_url;

type MutexConnector = Arc<Mutex<Box<dyn TunnelConnector>>>;
type ConnectorMap = Arc<DashMap<String, MutexConnector>>;

#[derive(Debug, Clone)]
struct ReconnResult {
    dead_url: String,
    peer_id: PeerId,
    conn_id: PeerConnId,
}

struct ConnectorManagerData {
    connectors: ConnectorMap,
    reconnecting: DashSet<String>,
    peer_manager: Arc<PeerManager>,
    alive_conn_urls: Arc<Mutex<BTreeSet<String>>>,
    // user removed connector urls
    removed_conn_urls: Arc<DashSet<String>>,
    net_ns: NetNS,
    global_ctx: ArcGlobalCtx,
}

pub struct ManualConnectorManager {
    global_ctx: ArcGlobalCtx,
    data: Arc<ConnectorManagerData>,
    tasks: JoinSet<()>,
}

impl ManualConnectorManager {
    pub fn new(global_ctx: ArcGlobalCtx, peer_manager: Arc<PeerManager>) -> Self {
        let connectors = Arc::new(DashMap::new());
        let tasks = JoinSet::new();
        let event_subscriber = global_ctx.subscribe();

        let mut ret = Self {
            global_ctx: global_ctx.clone(),
            data: Arc::new(ConnectorManagerData {
                connectors,
                reconnecting: DashSet::new(),
                peer_manager,
                alive_conn_urls: Arc::new(Mutex::new(BTreeSet::new())),
                removed_conn_urls: Arc::new(DashSet::new()),
                net_ns: global_ctx.net_ns.clone(),
                global_ctx,
            }),
            tasks,
        };

        ret.tasks
            .spawn(Self::conn_mgr_routine(ret.data.clone(), event_subscriber));

        ret
    }

    pub fn add_connector<T>(&self, connector: T)
    where
        T: TunnelConnector + 'static,
    {
        log::info!("add_connector: {}", connector.remote_url());
        self.data.connectors.insert(
            connector.remote_url().into(),
            Arc::new(Mutex::new(Box::new(connector))),
        );
    }

    pub async fn add_connector_by_url(&self, url: &str) -> Result<(), Error> {
        self.add_connector(create_connector_by_url(url, &self.global_ctx).await?);
        Ok(())
    }

    pub async fn remove_connector(&self, url: &str) -> Result<(), Error> {
        log::info!("remove_connector: {}", url);
        if !self.list_connectors().await.iter().any(|x| x.url == url) {
            return Err(Error::NotFound);
        }
        self.data.removed_conn_urls.insert(url.into());
        Ok(())
    }

    pub async fn list_connectors(&self) -> Vec<Connector> {
        let conn_urls: BTreeSet<String> = self
            .data
            .connectors
            .iter()
            .map(|x| x.key().clone().into())
            .collect();

        let dead_urls: BTreeSet<String> = Self::collect_dead_conns(self.data.clone())
            .await
            .into_iter()
            .collect();

        let mut ret = Vec::new();

        for conn_url in conn_urls {
            let mut status = ConnectorStatus::Connected;
            if dead_urls.contains(&conn_url) {
                status = ConnectorStatus::Disconnected;
            }
            ret.insert(
                0,
                Connector {
                    url: conn_url,
                    status: status.into(),
                },
            );
        }

        let reconnecting_urls: BTreeSet<String> = self
            .data
            .reconnecting
            .iter()
            .map(|x| x.clone().into())
            .collect();

        for conn_url in reconnecting_urls {
            ret.insert(
                0,
                Connector {
                    url: conn_url,
                    status: ConnectorStatus::Connecting.into(),
                },
            );
        }

        ret
    }

    async fn conn_mgr_routine(
        data: Arc<ConnectorManagerData>,
        mut event_recv: Receiver<GlobalCtxEvent>,
    ) {
        log::warn!("conn_mgr_routine started");
        let mut reconn_interval = tokio::time::interval(std::time::Duration::from_millis(
            use_global_var!(MANUAL_CONNECTOR_RECONNECT_INTERVAL_MS),
        ));
        let mut reconn_tasks = JoinSet::new();
        let (reconn_result_send, mut reconn_result_recv) = mpsc::channel(100);

        loop {
            tokio::select! {
                event = event_recv.recv() => {
                    if let Ok(event) = event {
                        Self::handle_event(&event, data.clone()).await;
                    } else {
                        log::warn!("event_recv closed");
                        panic!("event_recv closed");
                    }
                }

                _ = reconn_interval.tick() => {
                    let dead_urls = Self::collect_dead_conns(data.clone()).await;
                    if dead_urls.is_empty() {
                        continue;
                    }
                    for dead_url in dead_urls {
                        let data_clone = data.clone();
                        let sender = reconn_result_send.clone();
                        let (_, connector) = data.connectors.remove(&dead_url).unwrap();
                        let insert_succ = data.reconnecting.insert(dead_url.clone());
                        assert!(insert_succ);
                        reconn_tasks.spawn(async move {
                            sender.send(Self::conn_reconnect(data_clone.clone(), dead_url, connector).await).await.unwrap();
                        });
                    }
                    log::info!("reconn_interval tick, done");
                }

                ret = reconn_result_recv.recv() => {
                    log::warn!("reconn_tasks done, out: {:?}", ret);
                    let _ = reconn_tasks.join_next().await.unwrap();
                }
            }
        }
    }

    async fn handle_event(event: &GlobalCtxEvent, data: Arc<ConnectorManagerData>) {
        match event {
            GlobalCtxEvent::PeerConnAdded(conn_info) => {
                let addr = conn_info.tunnel.as_ref().unwrap().remote_addr.clone();
                data.alive_conn_urls.lock().await.insert(addr);
                log::warn!("peer conn added: {:?}", conn_info);
            }

            GlobalCtxEvent::PeerConnRemoved(conn_info) => {
                let addr = conn_info.tunnel.as_ref().unwrap().remote_addr.clone();
                data.alive_conn_urls.lock().await.remove(&addr);
                log::warn!("peer conn removed: {:?}", conn_info);
            }

            _ => {}
        }
    }

    fn handle_remove_connector(data: Arc<ConnectorManagerData>) {
        let remove_later = DashSet::new();
        for it in data.removed_conn_urls.iter() {
            let url = it.key();
            if let Some(_) = data.connectors.remove(url) {
                log::warn!("connector: {}, removed", url);
                continue;
            } else if data.reconnecting.contains(url) {
                log::warn!("connector: {}, reconnecting, remove later.", url);
                remove_later.insert(url.clone());
                continue;
            } else {
                log::warn!("connector: {}, not found", url);
            }
        }
        data.removed_conn_urls.clear();
        for it in remove_later.iter() {
            data.removed_conn_urls.insert(it.key().clone());
        }
    }

    async fn collect_dead_conns(data: Arc<ConnectorManagerData>) -> BTreeSet<String> {
        Self::handle_remove_connector(data.clone());

        let curr_alive = data.alive_conn_urls.lock().await.clone();
        let all_urls: BTreeSet<String> = data
            .connectors
            .iter()
            .map(|x| x.key().clone().into())
            .collect();
        &all_urls - &curr_alive
    }

    async fn conn_reconnect(
        data: Arc<ConnectorManagerData>,
        dead_url: String,
        connector: MutexConnector,
    ) -> Result<ReconnResult, Error> {
        let connector = Arc::new(Mutex::new(Some(connector)));
        let net_ns = data.net_ns.clone();

        log::info!("reconnect: {}", dead_url);

        let connector_clone = connector.clone();
        let data_clone = data.clone();
        let url_clone = dead_url.clone();
        let ip_collector = data.global_ctx.get_ip_collector();
        let reconn_task = async move {
            let mut locked = connector_clone.lock().await;
            let conn = locked.as_mut().unwrap();
            // TODO: should support set v6 here, use url in connector array
            set_bind_addr_for_peer_connector(conn.lock().await.as_mut(), true, &ip_collector).await;

            data_clone
                .global_ctx
                .issue_event(GlobalCtxEvent::Connecting(
                    conn.lock().await.remote_url().clone(),
                ));

            let _g = net_ns.guard();
            log::info!("reconnect try connect... conn: {:?}", conn);
            let tunnel = conn.lock().await.connect().await?;
            log::info!("reconnect get tunnel succ: {:?}", tunnel);
            assert_eq!(
                url_clone,
                tunnel.info().unwrap().remote_addr,
                "info: {:?}",
                tunnel.info()
            );
            let (peer_id, conn_id) = data_clone.peer_manager.add_client_tunnel(tunnel).await?;
            log::info!("reconnect succ: {} {} {}", peer_id, conn_id, url_clone);
            Ok(ReconnResult {
                dead_url: url_clone,
                peer_id,
                conn_id,
            })
        };

        let ret = timeout(std::time::Duration::from_secs(1), reconn_task).await;
        log::info!("reconnect: {} done, ret: {:?}", dead_url, ret);

        if ret.is_err() || ret.as_ref().unwrap().is_err() {
            data.global_ctx.issue_event(GlobalCtxEvent::ConnectError(
                dead_url.clone(),
                format!("{:?}", ret),
            ));
        }

        let conn = connector.lock().await.take().unwrap();
        data.reconnecting.remove(&dead_url).unwrap();
        data.connectors.insert(dead_url.clone(), conn);

        ret?
    }
}

pub struct ConnectorManagerRpcService(pub Arc<ManualConnectorManager>);

#[tonic::async_trait]
impl ConnectorManageRpc for ConnectorManagerRpcService {
    async fn list_connector(
        &self,
        _request: tonic::Request<ListConnectorRequest>,
    ) -> Result<tonic::Response<easytier_rpc::ListConnectorResponse>, tonic::Status> {
        let mut ret = easytier_rpc::ListConnectorResponse::default();
        let connectors = self.0.list_connectors().await;
        ret.connectors = connectors;
        Ok(tonic::Response::new(ret))
    }

    async fn manage_connector(
        &self,
        request: tonic::Request<ManageConnectorRequest>,
    ) -> Result<tonic::Response<easytier_rpc::ManageConnectorResponse>, tonic::Status> {
        let req = request.into_inner();
        let url = url::Url::parse(&req.url)
            .map_err(|_| tonic::Status::invalid_argument("invalid url"))?;
        if req.action == easytier_rpc::ConnectorManageAction::Remove as i32 {
            self.0.remove_connector(url.path()).await.map_err(|e| {
                tonic::Status::invalid_argument(format!("remove connector failed: {:?}", e))
            })?;
            return Ok(tonic::Response::new(
                easytier_rpc::ManageConnectorResponse::default(),
            ));
        } else {
            self.0
                .add_connector_by_url(url.as_str())
                .await
                .map_err(|e| {
                    tonic::Status::invalid_argument(format!("add connector failed: {:?}", e))
                })?;
        }
        Ok(tonic::Response::new(
            easytier_rpc::ManageConnectorResponse::default(),
        ))
    }
}

#[cfg(test)]
mod tests {
    use crate::{
        peers::tests::create_mock_peer_manager,
        set_global_var,
        tunnel::{Tunnel, TunnelError},
    };

    use super::*;

    #[tokio::test]
    async fn test_reconnect_with_connecting_addr() {
        set_global_var!(MANUAL_CONNECTOR_RECONNECT_INTERVAL_MS, 1);

        let peer_mgr = create_mock_peer_manager().await;
        let mgr = ManualConnectorManager::new(peer_mgr.get_global_ctx(), peer_mgr);

        struct MockConnector {}
        #[async_trait::async_trait]
        impl TunnelConnector for MockConnector {
            fn remote_url(&self) -> url::Url {
                url::Url::parse("tcp://aa.com").unwrap()
            }
            async fn connect(&mut self) -> Result<Box<dyn Tunnel>, TunnelError> {
                tokio::time::sleep(std::time::Duration::from_millis(10)).await;
                Err(TunnelError::InvalidPacket("fake error".into()))
            }
        }

        mgr.add_connector(MockConnector {});

        tokio::time::sleep(std::time::Duration::from_secs(5)).await;
    }
}
