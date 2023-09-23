use std::sync::Arc;

use crate::{
    common::{error::Error, global_ctx::tests::get_mock_global_ctx},
    peers::rip_route::BasicRoute,
    tunnels::ring_tunnel::create_ring_tunnel_pair,
};

use super::peer_manager::PeerManager;

pub async fn create_mock_peer_manager() -> Arc<PeerManager> {
    let (s, _r) = tokio::sync::mpsc::channel(1000);
    let peer_mgr = Arc::new(PeerManager::new(get_mock_global_ctx(), s));
    peer_mgr
        .set_route(BasicRoute::new(
            peer_mgr.my_node_id(),
            peer_mgr.get_global_ctx(),
        ))
        .await;
    peer_mgr.run().await.unwrap();
    peer_mgr
}

pub async fn connect_peer_manager(client: Arc<PeerManager>, server: Arc<PeerManager>) {
    let (a_ring, b_ring) = create_ring_tunnel_pair();
    let a_mgr_copy = client.clone();
    tokio::spawn(async move {
        a_mgr_copy.add_client_tunnel(a_ring).await.unwrap();
    });
    let b_mgr_copy = server.clone();
    tokio::spawn(async move {
        b_mgr_copy.add_tunnel_as_server(b_ring).await.unwrap();
    });
}

pub async fn wait_route_appear_with_cost(
    peer_mgr: Arc<PeerManager>,
    node_id: uuid::Uuid,
    cost: Option<i32>,
) -> Result<(), Error> {
    let now = std::time::Instant::now();
    while now.elapsed().as_secs() < 5 {
        let route = peer_mgr.list_routes().await;
        if route.iter().any(|r| {
            r.peer_id.clone().parse::<uuid::Uuid>().unwrap() == node_id
                && (cost.is_none() || r.cost == cost.unwrap())
        }) {
            return Ok(());
        }
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    }
    return Err(Error::NotFound);
}

pub async fn wait_route_appear(
    peer_mgr: Arc<PeerManager>,
    node_id: uuid::Uuid,
) -> Result<(), Error> {
    wait_route_appear_with_cost(peer_mgr, node_id, None).await
}
