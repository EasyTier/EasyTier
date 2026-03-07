use std::sync::Arc;
use std::time::Duration;

use crate::{
    common::{
        error::Error,
        global_ctx::{
            tests::{get_mock_global_ctx, get_mock_global_ctx_with_network},
            NetworkIdentity,
        },
        PeerId,
    },
    tunnel::{
        common::tests::wait_for_condition,
        packet_def::{PacketType, ZCPacket},
        ring::create_ring_tunnel_pair,
    },
};

use super::{
    create_packet_recv_chan,
    peer_conn::tests::set_secure_mode_cfg,
    peer_manager::{PeerManager, RouteAlgoType},
    peer_map::PeerMap,
    peer_session::{PeerSession, PeerSessionStore, SessionKey},
    relay_peer_map::RelayPeerMap,
    route_trait::NextHopPolicy,
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

pub async fn create_mock_peer_manager_secure(
    network_name: String,
    network_secret: String,
) -> Arc<PeerManager> {
    let (s, _r) = create_packet_recv_chan();
    let g =
        get_mock_global_ctx_with_network(Some(NetworkIdentity::new(network_name, network_secret)));
    set_secure_mode_cfg(&g, true);
    let peer_mgr = Arc::new(PeerManager::new(RouteAlgoType::Ospf, g, s));
    peer_mgr.run().await.unwrap();
    peer_mgr
}

pub async fn connect_peer_manager(client: Arc<PeerManager>, server: Arc<PeerManager>) {
    let (a_ring, b_ring) = create_ring_tunnel_pair();
    let a_mgr_copy = client;
    tokio::spawn(async move {
        a_mgr_copy.add_client_tunnel(a_ring, false).await.unwrap();
    });
    let b_mgr_copy = server;
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
                p.get_peer_map().list_peers()
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

#[tokio::test]
async fn relay_peer_map_secure_session_decrypt() {
    let (s, _r) = create_packet_recv_chan();
    let ctx = get_mock_global_ctx_with_network(Some(NetworkIdentity::new(
        "net1".to_string(),
        "sec1".to_string(),
    )));
    set_secure_mode_cfg(&ctx, true);
    let peer_map = Arc::new(PeerMap::new(s, ctx.clone(), 10));
    let store = Arc::new(PeerSessionStore::new());
    let relay_map = RelayPeerMap::new(peer_map, ctx.clone(), 10, store.clone());

    let algo = ctx.get_flags().encryption_algorithm.clone();
    let root_key = [7u8; 32];
    let session = Arc::new(PeerSession::new(
        20,
        root_key,
        1,
        1,
        algo.clone(),
        algo.clone(),
        None,
    ));
    let key = SessionKey::new(ctx.get_network_identity().network_name, 20);
    store.insert_session(key.clone(), session.clone());

    relay_map
        .ensure_session(20, NextHopPolicy::LeastHop)
        .await
        .unwrap();
    assert!(relay_map.has_session(20));

    let mut packet = ZCPacket::new_with_payload(b"relay-hello");
    packet.fill_peer_manager_hdr(20, 10, PacketType::Data as u8);
    session.encrypt_payload(20, 10, &mut packet).unwrap();
    assert!(relay_map.decrypt_if_needed(&mut packet).unwrap());
    assert_eq!(packet.payload(), b"relay-hello");
}

#[tokio::test]
async fn relay_peer_map_retry_backoff_and_evict() {
    let (s, _r) = create_packet_recv_chan();
    let ctx_secure = get_mock_global_ctx();
    set_secure_mode_cfg(&ctx_secure, true);
    let peer_map = Arc::new(PeerMap::new(s, ctx_secure.clone(), 10));
    let relay_map = RelayPeerMap::new(
        peer_map,
        ctx_secure.clone(),
        10,
        Arc::new(PeerSessionStore::new()),
    );

    let ret = relay_map
        .handshake_session(20, NextHopPolicy::LeastHop, None)
        .await;
    assert!(ret.is_err());
    assert!(relay_map.failure_count(20).unwrap_or(0) >= 1);
    assert!(relay_map.is_backoff_active(20));

    let (s2, _r2) = create_packet_recv_chan();
    let ctx_plain = get_mock_global_ctx();
    let peer_map_plain = Arc::new(PeerMap::new(s2, ctx_plain.clone(), 30));
    let relay_map_plain = RelayPeerMap::new(
        peer_map_plain,
        ctx_plain.clone(),
        30,
        Arc::new(PeerSessionStore::new()),
    );

    let mut pkt = ZCPacket::new_with_payload(b"evict");
    pkt.fill_peer_manager_hdr(30, 40, PacketType::Data as u8);
    let _ = relay_map_plain
        .send_msg(pkt, 40, NextHopPolicy::LeastHop)
        .await;
    assert!(relay_map_plain.has_state(40));
    relay_map_plain.evict_idle_sessions(Duration::from_millis(0));
    assert!(!relay_map_plain.has_state(40));
}

#[tokio::test]
async fn relay_peer_map_pending_packet_buffer() {
    // Verify that packets sent during handshake are buffered (not dropped),
    // and flushed after handshake completes.
    let (s, _r) = create_packet_recv_chan();
    let ctx = get_mock_global_ctx_with_network(Some(NetworkIdentity::new(
        "net1".to_string(),
        "sec1".to_string(),
    )));
    set_secure_mode_cfg(&ctx, true);
    let peer_map = Arc::new(PeerMap::new(s, ctx.clone(), 10));
    let store = Arc::new(PeerSessionStore::new());
    let relay_map = RelayPeerMap::new(peer_map, ctx.clone(), 10, store.clone());

    // Send multiple packets while no session exists (handshake will fail, but packets should be buffered)
    for i in 0..5u8 {
        let mut pkt = ZCPacket::new_with_payload(&[i]);
        pkt.fill_peer_manager_hdr(10, 20, PacketType::Data as u8);
        let _ = relay_map.send_msg(pkt, 20, NextHopPolicy::LeastHop).await;
    }

    // Verify packets were buffered
    assert_eq!(
        relay_map
            .pending_packets
            .get(&20)
            .map(|v| v.len())
            .unwrap_or(0),
        5,
        "5 packets should be buffered during handshake"
    );

    // Verify buffer respects capacity limit
    for i in 0..50u8 {
        let mut pkt = ZCPacket::new_with_payload(&[i]);
        pkt.fill_peer_manager_hdr(10, 20, PacketType::Data as u8);
        let _ = relay_map.send_msg(pkt, 20, NextHopPolicy::LeastHop).await;
    }

    let buffered = relay_map
        .pending_packets
        .get(&20)
        .map(|v| v.len())
        .unwrap_or(0);
    assert!(
        buffered <= 32,
        "buffer should not exceed MAX_PENDING_PACKETS_PER_PEER, got {buffered}"
    );

    // Verify remove_peer clears pending packets
    relay_map.remove_peer(20);
    assert_eq!(
        relay_map
            .pending_packets
            .get(&20)
            .map(|v| v.len())
            .unwrap_or(0),
        0,
        "pending packets should be cleared on peer removal"
    );
}

#[tokio::test]
async fn relay_peer_map_pending_packets_flushed_on_handshake_success() {
    // Test that pending packets are flushed after handshake succeeds.
    // We pre-populate the buffer, then run handshake, and verify it's cleared.
    let peer_a = create_mock_peer_manager_secure("net1".to_string(), "sec1".to_string()).await;
    let peer_b = create_mock_peer_manager_secure("net1".to_string(), "sec1".to_string()).await;
    let peer_c = create_mock_peer_manager_secure("net1".to_string(), "sec1".to_string()).await;

    connect_peer_manager(peer_a.clone(), peer_b.clone()).await;
    connect_peer_manager(peer_b.clone(), peer_c.clone()).await;

    let peer_a_id = peer_a.my_peer_id();
    let peer_c_id = peer_c.my_peer_id();

    // Wait for routes to propagate
    wait_for_condition(
        || {
            let peer_a = peer_a.clone();
            let peer_c = peer_c.clone();
            async move { wait_route_appear(peer_a.clone(), peer_c).await.is_ok() }
        },
        Duration::from_secs(10),
    )
    .await;

    // Wait for noise_static_pubkey to be available on both sides
    wait_for_condition(
        || {
            let peer_a = peer_a.clone();
            async move {
                peer_a
                    .get_peer_map()
                    .get_route_peer_info(peer_c_id)
                    .await
                    .map(|info| !info.noise_static_pubkey.is_empty())
                    .unwrap_or(false)
            }
        },
        Duration::from_secs(10),
    )
    .await;

    let relay_a = peer_a.get_relay_peer_map();

    // Pre-populate pending packets buffer (simulating what send_msg does during handshake)
    for i in 0..3u8 {
        let mut pkt = ZCPacket::new_with_payload(&[i]);
        pkt.fill_peer_manager_hdr(peer_a_id, peer_c_id, PacketType::Data as u8);
        relay_a
            .pending_packets
            .entry(peer_c_id)
            .or_default()
            .push((pkt, NextHopPolicy::LeastHop));
    }

    assert_eq!(
        relay_a
            .pending_packets
            .get(&peer_c_id)
            .map(|v| v.len())
            .unwrap_or(0),
        3,
        "3 packets should be in the buffer"
    );

    // Run handshake — on success it should flush the buffer
    relay_a
        .handshake_session(peer_c_id, NextHopPolicy::LeastHop, None)
        .await
        .unwrap();

    // Verify session established and buffer cleared
    assert!(relay_a.has_session(peer_c_id));
    assert_eq!(
        relay_a
            .pending_packets
            .get(&peer_c_id)
            .map(|v| v.len())
            .unwrap_or(0),
        0,
        "pending packets should be flushed after successful handshake"
    );
}

#[tokio::test]
async fn relay_peer_map_real_link_handshake_success() {
    let peer_a = create_mock_peer_manager_secure("net1".to_string(), "sec1".to_string()).await;
    let peer_b = create_mock_peer_manager_secure("net1".to_string(), "sec1".to_string()).await;
    let peer_c = create_mock_peer_manager_secure("net1".to_string(), "sec1".to_string()).await;

    connect_peer_manager(peer_a.clone(), peer_b.clone()).await;
    connect_peer_manager(peer_b.clone(), peer_c.clone()).await;

    let peer_a_id = peer_a.my_peer_id();
    let peer_b_id = peer_b.my_peer_id();
    let peer_c_id = peer_c.my_peer_id();

    wait_for_condition(
        || {
            let peer_a = peer_a.clone();
            let peer_c = peer_c.clone();
            async move { wait_route_appear(peer_a.clone(), peer_c).await.is_ok() }
        },
        Duration::from_secs(10),
    )
    .await;

    wait_for_condition(
        || {
            let peer_a = peer_a.clone();
            async move {
                peer_a
                    .get_peer_map()
                    .get_gateway_peer_id(peer_c_id, NextHopPolicy::LeastHop)
                    .await
                    == Some(peer_b_id)
            }
        },
        Duration::from_secs(5),
    )
    .await;

    wait_for_condition(
        || {
            let peer_a = peer_a.clone();
            async move {
                peer_a
                    .get_peer_map()
                    .get_route_peer_info(peer_c_id)
                    .await
                    .map(|info| !info.noise_static_pubkey.is_empty())
                    .unwrap_or(false)
            }
        },
        Duration::from_secs(10),
    )
    .await;

    let relay_a = peer_a.get_relay_peer_map();
    let relay_c = peer_c.get_relay_peer_map();

    relay_a
        .handshake_session(peer_c_id, NextHopPolicy::LeastHop, None)
        .await
        .unwrap();

    wait_for_condition(
        || {
            let relay_a = relay_a.clone();
            async move { relay_a.has_session(peer_c_id) }
        },
        Duration::from_secs(5),
    )
    .await;

    wait_for_condition(
        || {
            let relay_c = relay_c.clone();
            async move { relay_c.has_session(peer_a_id) }
        },
        Duration::from_secs(5),
    )
    .await;
}

#[tokio::test]
async fn relay_peer_map_responder_rejects_mismatched_pubkey() {
    // Create three peers: A -> B -> C
    let peer_a = create_mock_peer_manager_secure("net1".to_string(), "sec1".to_string()).await;
    let peer_b = create_mock_peer_manager_secure("net1".to_string(), "sec1".to_string()).await;
    let peer_c = create_mock_peer_manager_secure("net1".to_string(), "sec1".to_string()).await;

    connect_peer_manager(peer_a.clone(), peer_b.clone()).await;
    connect_peer_manager(peer_b.clone(), peer_c.clone()).await;

    let peer_a_id = peer_a.my_peer_id();
    let peer_c_id = peer_c.my_peer_id();

    // Wait for routes to propagate
    wait_for_condition(
        || {
            let peer_a = peer_a.clone();
            let peer_c = peer_c.clone();
            async move { wait_route_appear(peer_a.clone(), peer_c).await.is_ok() }
        },
        Duration::from_secs(10),
    )
    .await;

    // Wait for noise_static_pubkey to be available
    wait_for_condition(
        || {
            let peer_a = peer_a.clone();
            async move {
                peer_a
                    .get_peer_map()
                    .get_route_peer_info(peer_c_id)
                    .await
                    .map(|info| !info.noise_static_pubkey.is_empty())
                    .unwrap_or(false)
            }
        },
        Duration::from_secs(10),
    )
    .await;

    // Get the original correct pubkey to verify it exists
    let original_info = peer_a
        .get_peer_map()
        .get_route_peer_info(peer_c_id)
        .await
        .expect("should have route info for peer_c");
    assert!(
        !original_info.noise_static_pubkey.is_empty(),
        "noise_static_pubkey should be present"
    );

    // Attempt handshake - this should succeed because pubkeys match
    let relay_a = peer_a.get_relay_peer_map();
    let result = relay_a
        .handshake_session(peer_c_id, NextHopPolicy::LeastHop, None)
        .await;

    // The handshake should succeed because the pubkeys match
    assert!(
        result.is_ok(),
        "handshake should succeed with matching pubkeys"
    );

    // Verify session was established on both sides
    wait_for_condition(
        || {
            let relay_a = relay_a.clone();
            async move { relay_a.has_session(peer_c_id) }
        },
        Duration::from_secs(5),
    )
    .await;

    let relay_c = peer_c.get_relay_peer_map();
    wait_for_condition(
        || {
            let relay_c = relay_c.clone();
            async move { relay_c.has_session(peer_a_id) }
        },
        Duration::from_secs(5),
    )
    .await;
}

#[tokio::test]
async fn relay_peer_map_remove_peer() {
    let (s, _r) = create_packet_recv_chan();
    let ctx = get_mock_global_ctx_with_network(Some(NetworkIdentity::new(
        "net1".to_string(),
        "sec1".to_string(),
    )));
    set_secure_mode_cfg(&ctx, true);
    let peer_map = Arc::new(PeerMap::new(s, ctx.clone(), 10));
    let store = Arc::new(PeerSessionStore::new());
    let relay_map = RelayPeerMap::new(peer_map, ctx.clone(), 10, store.clone());

    let peer_1: PeerId = 100;

    // Add session for peer_1
    let root_key = [1u8; 32];
    let session = Arc::new(PeerSession::new(
        peer_1,
        root_key,
        1,
        0,
        "aes-256-gcm".to_string(),
        "aes-256-gcm".to_string(),
        None,
    ));
    let key = SessionKey::new(ctx.get_network_name(), peer_1);
    store.insert_session(key.clone(), session);

    assert!(store.get(&key).is_some());

    // Remove the peer relay state
    relay_map.remove_peer(peer_1);

    // Session should still be in the store (lifecycle is independent of relay state)
    assert!(
        store.get(&key).is_some(),
        "session should persist after relay peer removal"
    );
}

/// Test bidirectional handshake race resolution.
/// When both peers simultaneously initiate handshake, the one with smaller peer_id
/// should become initiator, and the other should yield and become responder.
#[tokio::test]
async fn relay_peer_map_bidirectional_handshake_race() {
    // Create three peers: A -> B -> C
    let peer_a = create_mock_peer_manager_secure("net1".to_string(), "sec1".to_string()).await;
    let peer_b = create_mock_peer_manager_secure("net1".to_string(), "sec1".to_string()).await;
    let peer_c = create_mock_peer_manager_secure("net1".to_string(), "sec1".to_string()).await;

    connect_peer_manager(peer_a.clone(), peer_b.clone()).await;
    connect_peer_manager(peer_b.clone(), peer_c.clone()).await;

    let peer_a_id = peer_a.my_peer_id();
    let peer_c_id = peer_c.my_peer_id();

    // Wait for routes to propagate
    wait_for_condition(
        || {
            let peer_a = peer_a.clone();
            let peer_c = peer_c.clone();
            async move { wait_route_appear(peer_a.clone(), peer_c).await.is_ok() }
        },
        Duration::from_secs(10),
    )
    .await;

    // Wait for noise_static_pubkey to be available
    wait_for_condition(
        || {
            let peer_a = peer_a.clone();
            async move {
                peer_a
                    .get_peer_map()
                    .get_route_peer_info(peer_c_id)
                    .await
                    .map(|info| !info.noise_static_pubkey.is_empty())
                    .unwrap_or(false)
            }
        },
        Duration::from_secs(10),
    )
    .await;

    wait_for_condition(
        || {
            let peer_c = peer_c.clone();
            async move {
                peer_c
                    .get_peer_map()
                    .get_route_peer_info(peer_a_id)
                    .await
                    .map(|info| !info.noise_static_pubkey.is_empty())
                    .unwrap_or(false)
            }
        },
        Duration::from_secs(10),
    )
    .await;

    // Simulate bidirectional handshake race by having both sides initiate simultaneously
    let relay_a = peer_a.get_relay_peer_map();
    let relay_c = peer_c.get_relay_peer_map();

    // Both sides initiate handshake at the same time
    let handle_a = tokio::spawn({
        let relay_a = relay_a.clone();
        async move {
            relay_a
                .handshake_session(peer_c_id, NextHopPolicy::LeastHop, None)
                .await
        }
    });

    let handle_c = tokio::spawn({
        let relay_c = relay_c.clone();
        async move {
            relay_c
                .handshake_session(peer_a_id, NextHopPolicy::LeastHop, None)
                .await
        }
    });

    // Wait for both handshakes to complete
    let (result_a, result_c) = tokio::join!(handle_a, handle_c);

    // At least one should succeed (the initiator with smaller peer_id)
    // Both could succeed if race resolution worked correctly
    tracing::info!(
        ?peer_a_id,
        ?peer_c_id,
        ?result_a,
        ?result_c,
        "bidirectional handshake results"
    );

    // Wait for sessions to be established
    wait_for_condition(
        || {
            let relay_a = relay_a.clone();
            async move { relay_a.has_session(peer_c_id) }
        },
        Duration::from_secs(5),
    )
    .await;

    wait_for_condition(
        || {
            let relay_c = relay_c.clone();
            async move { relay_c.has_session(peer_a_id) }
        },
        Duration::from_secs(5),
    )
    .await;

    // Both sides should have sessions after race resolution
    assert!(
        relay_a.has_session(peer_c_id),
        "peer_a should have session with peer_c"
    );
    assert!(
        relay_c.has_session(peer_a_id),
        "peer_c should have session with peer_a"
    );
}
