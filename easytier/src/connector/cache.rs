use std::sync::{Arc, Mutex, Weak};
use std::time::Duration;
use std::collections::HashSet;
use dashmap::{DashMap, DashSet};
use url::{Url, Host};

use tokio::{
    sync::{
        broadcast::{error::RecvError, Receiver},
    },
    time::Instant,
    task::JoinSet,
};

use crate::{
    common::{
        PeerId,join_joinset_background,
        global_ctx::{ArcGlobalCtx, GlobalCtxEvent}
    },
    peers::{
        peer_manager::PeerManager,
    },
    tunnel::IpVersion,
    use_global_var,
};

use super::{create_connector_by_url, set_bind_addr_for_peer_connector};

/*
    CacheConnectorManager is similar to ManualConnectorManager,
    The key difference is that its peer information does not come from config files, 
    but from established connections in the past.

    It will:
        1. Maintain a TTL queue, and periodically remove expired entries
        2. Listen to global events and add targeted connection based on predefined criteria to the queue
        3. Periodically scan conenctions in the queue and attempt to connect to it if the peer associated with it become unavailable
*/

struct CacheConnectorManagerData {
    conn_cache: Arc<DashMap<(PeerId, Url), Instant>>,
    alive_conn: Arc<DashSet<Url>>,
    peer_manager: Arc<PeerManager>,
    global_ctx: ArcGlobalCtx,
}
pub struct CacheConnectorManager {
    global_ctx: ArcGlobalCtx,
    data: Arc<CacheConnectorManagerData>,
    tasks: Arc<Mutex<JoinSet<()>>>,
}

impl CacheConnectorManager {
    pub fn new(global_ctx: ArcGlobalCtx, peer_manager: Arc<PeerManager>) -> Self {
        let event_subscriber = global_ctx.subscribe();
        let data = Arc::new( CacheConnectorManagerData {
                conn_cache: Arc::new(DashMap::new()),
                alive_conn: Arc::new(DashSet::new()),
                peer_manager: peer_manager,
                global_ctx: global_ctx.clone(),
            });
        let tasks = Arc::new(Mutex::new(JoinSet::new()));
        join_joinset_background(tasks.clone(), "CacheConnectorManager".to_owned());

        tracing::info!("Starting Cache Connector Manager");
        tasks.lock().unwrap().spawn(Self::cache_mgr_handle_event_routine(data.clone(), event_subscriber));
        tasks.lock().unwrap().spawn(Self::cache_mgr_reconnect_routine(data.clone(), Arc::downgrade(&tasks)));

        Self {
            data,
            global_ctx: global_ctx.clone(),
            tasks,
        }
    }

    async fn cache_mgr_handle_event_routine(
        data: Arc<CacheConnectorManagerData>,
        mut event_subscriber: Receiver<GlobalCtxEvent>
    ) {
        loop {
            match event_subscriber.recv().await {
                Ok(event) => {
                    Self::handle_event(&event, &data).await;
                }
                Err(RecvError::Lagged(n)) => {
                    tracing::warn!("event_recv lagged: {}, resubscribe it", n);
                    event_subscriber = event_subscriber.resubscribe();
                    data.conn_cache.clear();
                    data.alive_conn.clear();
                    continue;
                }
                Err(RecvError::Closed) => {
                    tracing::warn!("event_subscriber closed, exit");
                    break;
                }
            }
        }
    }

    async fn handle_event(
        event: &GlobalCtxEvent,
        data: &CacheConnectorManagerData,
    ) {
        let conn_cache = &data.conn_cache;
        let alive_conn = &data.alive_conn;
        let blacklist: Vec<Url> = data.global_ctx.config
                            .get_peers()
                            .iter()
                            .map(|x|x.uri.clone())
                            .collect();
        match event {
            GlobalCtxEvent::PeerConnAdded(conn_info) => {
                let conn_url = conn_info.tunnel.as_ref().unwrap().remote_addr.clone().unwrap().into();
                alive_conn.insert(conn_url);
            }
            GlobalCtxEvent::PeerConnRemoved(conn_info) => {
                if !conn_info.is_client {
                    return;
                }
                let peer_id = conn_info.peer_id;

                // convert proto::common::Url to url::Url
                let remote_addr: Url = conn_info.tunnel.as_ref().unwrap().remote_addr.clone().unwrap().into();
                alive_conn.remove(&remote_addr);

                if matches!(remote_addr.scheme(), "txt"| "srv"| "http")
                    || matches!(remote_addr.host().unwrap(), Host::Domain(_))
                    || remote_addr.port().is_none() {
                        return;
                    }

                if blacklist.contains(&remote_addr) {
                    return;
                }

                tracing::debug!("add closed url {} to cache connector manager", &remote_addr);
                conn_cache.insert((peer_id, remote_addr), Instant::now());
            }

            _ => {}
        }
    }

    async fn cache_mgr_reconnect_routine(
        data: Arc<CacheConnectorManagerData>,
        tasks: Weak<Mutex<JoinSet<()>>>,
    ) {
        let conn_cache = data.conn_cache.clone();
        let alive_conn = data.alive_conn.clone();
        let mut reconn_interval_sec = tokio::time::interval(Duration::from_secs(
            use_global_var!(CACHE_CONNECTOR_RECONNECT_INTERVAL_SEC)
        ));
        loop {
            reconn_interval_sec.tick().await;

            let now = Instant::now();
            let timeout_sec = use_global_var!(CACHE_CONNECTOR_QUEUE_TIMEOUT_SEC);
            conn_cache.retain(|_, add_time| now.duration_since(*add_time) < Duration::from_secs(timeout_sec));

            let peers = data.peer_manager.get_peer_map().list_peers_with_conn().await;
            let mut urls: HashSet<Url> = HashSet::new();
            conn_cache.iter().for_each(|entry| {
                let ((peer_id, url), _add_time) = entry.pair();
                if !peers.contains(peer_id) {
                    urls.insert(url.clone());
                };
            });

            let urls: HashSet<Url> = urls.into_iter()
                .filter(|x| !alive_conn.contains(x))
                .collect();

            let tasks = match tasks.upgrade() {
                    Some(tasks) => tasks,
                    None => break
            };
            let mut tasks = tasks.lock().unwrap();
            for url in urls.into_iter() {
                let data_clone = data.clone();
                tracing::debug!("trying to connect to {}", url.clone());

                tasks.spawn(async move {
                    let _ = Self::try_reconnect(data_clone, url).await;
                });
            }
        }
    }

    /*
        Connects to the specified address
        Input URLs are simple links like tcp://1.1.1.1:443 or udp://[240e::1]:11010 (no domain names)
        Best-effort approach - aborts immediately on any error
     */
    async fn try_reconnect(
        data: Arc<CacheConnectorManagerData>,
        dead_url: Url,
    ){
        tracing::info!("reconnect: {}", &dead_url);

        let Some(addrs) = dead_url.socket_addrs(|| None).ok() else {
            tracing::warn!("failed to resolve dead_url to socket addrs, dead_url: {}", &dead_url);
            return
        };
        if addrs.len() != 1 {
            tracing::warn!("invalid url: {:?}! mutiple socket addrs were retrieved from it", &dead_url);
            return;
        }
        tracing::info!(?addrs, ?dead_url, "get ip from url done");

        let ip_version = if addrs[0].is_ipv4() {IpVersion::V4} else {IpVersion::V6};
        let ip_collector = data.global_ctx.get_ip_collector();
        let mut connector = create_connector_by_url(&dead_url.to_string(), &data.global_ctx, ip_version).await.unwrap();

        if data.global_ctx.config.get_flags().bind_device {
            set_bind_addr_for_peer_connector(
                connector.as_mut(),
                ip_version == IpVersion::V4,
                &ip_collector,
            )
            .await;
        }

        tracing::info!("reconnect try connect... conn: {:?}", connector);
        if let Some((peer_id, conn_id)) = data
            .peer_manager
            .try_direct_connect(connector.as_mut())
            .await
            .ok() {
            tracing::info!("reconnect succ: {} {} {}", peer_id, &conn_id, &dead_url);
        }
        else {
            tracing::warn!("failed to reconnect {}", &dead_url);
        };
    }
}

#[cfg(test)]
mod tests {
    use crate::{
        peers::tests::create_mock_peer_manager,
        set_global_var,
    };

    use super::*;

    #[tokio::test]
    async fn test_cache_reconnect_to_url() {
        set_global_var!(CACHE_CONNECTOR_RECONNECT_INTERVAL_SEC, 1);
        set_global_var!(CACHE_CONNECTOR_QUEUE_TIMEOUT_SEC, 10);

        let peer_mgr = create_mock_peer_manager().await;
        let mgr = CacheConnectorManager::new(peer_mgr.get_global_ctx(), peer_mgr);

        assert_eq!(mgr.tasks.lock().unwrap().len(), 2);
        let _ = CacheConnectorManager::try_reconnect(mgr.data.clone(), Url::parse("udp://223.5.5.5:53").unwrap()).await;
        let _ = mgr.tasks.lock().unwrap().spawn(CacheConnectorManager::try_reconnect(mgr.data.clone(), Url::parse("tcp://1.1.1.1:443").unwrap()));
        assert_eq!(mgr.tasks.lock().unwrap().len(), 3);

        tokio::time::sleep(std::time::Duration::from_secs(5)).await;
    }
}
