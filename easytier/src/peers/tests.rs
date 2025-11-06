use std::sync::Arc;

use crate::{
    common::{
        error::Error,
        global_ctx::{
            tests::{get_mock_global_ctx, get_mock_global_ctx_with_network},
            NetworkIdentity,
        },
        PeerId,
    },
    tunnel::ring::create_ring_tunnel_pair,
};

use super::{
    create_packet_recv_chan,
    peer_manager::{PeerManager, RouteAlgoType},
};

pub async fn create_mock_peer_manager() -> Arc<PeerManager> {
    let (s, _r) = create_packet_recv_chan();
    let peer_mgr = Arc::new(PeerManager::new(
        RouteAlgoType::Ospf,
        get_mock_global_ctx(),
        s,
    ));
    peer_mgr.run().await.unwrap();
    peer_mgr
}

pub async fn create_mock_peer_manager_with_name(network_name: String) -> Arc<PeerManager> {
    let (s, _r) = create_packet_recv_chan();
    let g =
        get_mock_global_ctx_with_network(Some(NetworkIdentity::new(network_name, "".to_string())));
    let peer_mgr = Arc::new(PeerManager::new(RouteAlgoType::Ospf, g, s));
    peer_mgr.run().await.unwrap();
    peer_mgr
}

pub async fn connect_peer_manager(client: Arc<PeerManager>, server: Arc<PeerManager>) {
    let (a_ring, b_ring) = create_ring_tunnel_pair();
    let a_mgr_copy = client.clone();
    tokio::spawn(async move {
        a_mgr_copy.add_client_tunnel(a_ring, false).await.unwrap();
    });
    let b_mgr_copy = server.clone();
    tokio::spawn(async move {
        b_mgr_copy.add_tunnel_as_server(b_ring, true).await.unwrap();
    });
}

pub async fn wait_route_appear_with_cost(
    peer_mgr: Arc<PeerManager>,
    node_id: PeerId,
    cost: Option<i32>,
) -> Result<(), Error> {
    let now = std::time::Instant::now();
    while now.elapsed().as_secs() < 5 {
        let route = peer_mgr.list_routes().await;
        if route
            .iter()
            .any(|r| r.peer_id == node_id && (cost.is_none() || r.cost == cost.unwrap()))
        {
            return Ok(());
        }
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    }
    Err(Error::NotFound)
}

pub async fn wait_route_appear(
    peer_mgr: Arc<PeerManager>,
    target_peer: Arc<PeerManager>,
) -> Result<(), Error> {
    wait_route_appear_with_cost(peer_mgr.clone(), target_peer.my_peer_id(), None).await?;
    wait_route_appear_with_cost(target_peer, peer_mgr.my_peer_id(), None).await
}

#[tokio::test]
async fn foreign_mgr_stress_test() {
    const FOREIGN_NETWORK_COUNT: i32 = 20;
    const PEER_PER_NETWORK: i32 = 3;
    const PUBLIC_PEER_COUNT: i32 = 3;

    let mut public_peers = Vec::new();
    for _ in 0..PUBLIC_PEER_COUNT {
        public_peers.push(create_mock_peer_manager().await);
    }
    connect_peer_manager(public_peers[0].clone(), public_peers[1].clone()).await;
    connect_peer_manager(public_peers[0].clone(), public_peers[2].clone()).await;
    connect_peer_manager(public_peers[1].clone(), public_peers[2].clone()).await;

    let mut foreigns = Vec::new();

    for i in 0..FOREIGN_NETWORK_COUNT {
        let mut peers = Vec::new();

        let name = format!("foreign-network-test-{}", i);

        for _ in 0..PEER_PER_NETWORK {
            let mgr = create_mock_peer_manager_with_name(name.clone()).await;
            let public_peer_idx = rand::random::<usize>() % public_peers.len();
            connect_peer_manager(mgr.clone(), public_peers[public_peer_idx].clone()).await;
            peers.push(mgr);
        }

        foreigns.push(peers);
    }

    for _ in 0..5 {
        for i in 0..PUBLIC_PEER_COUNT {
            let p = public_peers[i as usize].clone();
            println!(
                "public peer {} routes: {:?}, global_foreign_network: {:?}, peers: {:?}",
                i,
                p.list_routes().await,
                p.list_global_foreign_network().await.foreign_networks.len(),
                p.get_peer_map().list_peers().await
            );
        }
        tokio::time::sleep(std::time::Duration::from_secs(1)).await;

        let new_peer = create_mock_peer_manager().await;
        connect_peer_manager(new_peer.clone(), public_peers[0].clone()).await;
        while let Err(e) = wait_route_appear(public_peers[1].clone(), new_peer.clone()).await {
            println!("wait route ret: {:?}", e);
        }
    }
}
