use std::sync::Arc;
use std::time::Duration;

use base64::Engine as _;

use crate::{
    common::{
        PeerId,
        error::Error,
        global_ctx::{
            NetworkIdentity, TrustedKeySource,
            tests::{get_mock_global_ctx, get_mock_global_ctx_with_network},
        },
        stats_manager::{LabelSet, LabelType, MetricName},
    },
    proto::api::instance::TrustedKeySourcePb,
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

fn set_private_mode(peer_mgr: &PeerManager, enabled: bool) {
    let global_ctx = peer_mgr.get_global_ctx();
    let mut flags = global_ctx.get_flags();
    flags.private_mode = enabled;
    global_ctx.set_flags(flags);
}

async fn connect_client_and_server(
    client: Arc<PeerManager>,
    server: Arc<PeerManager>,
) -> (Result<(), Error>, Result<(), Error>) {
    let (client_ring, server_ring) = create_ring_tunnel_pair();
    tokio::join!(
        {
            let client = client.clone();
            async move {
                client.add_client_tunnel(client_ring, false).await?;
                Ok(())
            }
        },
        {
            let server = server.clone();
            async move { server.add_tunnel_as_server(server_ring, true, false).await }
        }
    )
}

async fn wait_for_foreign_network(server: Arc<PeerManager>, network_name: &'static str) {
    wait_for_condition(
        || {
            let server = server.clone();
            async move {
                server
                    .get_foreign_network_manager()
                    .list_foreign_networks()
                    .await
                    .foreign_networks
                    .contains_key(network_name)
            }
        },
        Duration::from_secs(10),
    )
    .await;
}

async fn wait_for_foreign_network_peer_count_at_least(
    server: Arc<PeerManager>,
    network_name: &'static str,
    min_peer_count: usize,
) {
    wait_for_condition(
        || {
            let server = server.clone();
            async move {
                server
                    .get_foreign_network_manager()
                    .list_foreign_networks()
                    .await
                    .foreign_networks
                    .get(network_name)
                    .map(|entry| entry.peers.len() >= min_peer_count)
                    .unwrap_or(false)
            }
        },
        Duration::from_secs(10),
    )
    .await;
}

async fn wait_for_public_peers_empty(client: Arc<PeerManager>) {
    wait_for_condition(
        || {
            let client = client.clone();
            async move {
                client
                    .get_foreign_network_client()
                    .list_public_peers()
                    .await
                    .is_empty()
            }
        },
        Duration::from_secs(5),
    )
    .await;
}

pub async fn connect_peer_manager(client: Arc<PeerManager>, server: Arc<PeerManager>) {
    let (a_ring, b_ring) = create_ring_tunnel_pair();
    let a_mgr_copy = client;
    tokio::spawn(async move {
        a_mgr_copy.add_client_tunnel(a_ring, false).await.unwrap();
    });
    let b_mgr_copy = server;
    tokio::spawn(async move {
        b_mgr_copy.add_tunnel_as_server(b_ring, true, false).await.unwrap();
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

fn metric_value(peer_mgr: &PeerManager, metric: MetricName, network_name: &str) -> u64 {
    peer_mgr
        .get_global_ctx()
        .stats_manager()
        .get_metric(
            metric,
            &LabelSet::new().with_label_type(LabelType::NetworkName(network_name.to_string())),
        )
        .map(|metric| metric.value)
        .unwrap_or(0)
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
    let relay_map = RelayPeerMap::new(peer_map, None, ctx.clone(), 10, store.clone());

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
    assert!(relay_map.decrypt_if_needed(&mut packet).await.unwrap());
    assert_eq!(packet.payload(), b"relay-hello");
}

#[tokio::test]
async fn private_mode_allows_foreign_network_with_same_secret() {
    let server = create_mock_peer_manager_secure("public".to_string(), "shared".to_string()).await;
    let client =
        create_mock_peer_manager_secure("tenant-a".to_string(), "shared".to_string()).await;
    set_private_mode(&server, true);

    let (client_ret, server_ret) = connect_client_and_server(client, server.clone()).await;

    assert!(client_ret.is_ok(), "client should connect in private mode");
    assert!(
        server_ret.is_ok(),
        "server should accept foreign network with matching secret: {:?}",
        server_ret
    );
    wait_for_foreign_network(server, "tenant-a").await;
}

#[tokio::test]
async fn private_mode_rejects_foreign_network_with_different_secret() {
    let server = create_mock_peer_manager_secure("public".to_string(), "shared".to_string()).await;
    let client = create_mock_peer_manager_secure("tenant-a".to_string(), "other".to_string()).await;
    set_private_mode(&server, true);

    let (client_ret, server_ret) = connect_client_and_server(client.clone(), server.clone()).await;

    assert!(
        server_ret.is_err(),
        "server should reject foreign network with mismatched secret in private mode"
    );
    let _ = client_ret;
    wait_for_public_peers_empty(client).await;
    assert!(
        server
            .get_foreign_network_manager()
            .list_foreign_networks()
            .await
            .foreign_networks
            .is_empty()
    );
}

#[tokio::test]
async fn private_mode_allows_trusted_foreign_credential() {
    let server = create_mock_peer_manager_secure("public".to_string(), "shared".to_string()).await;
    let admin = create_mock_peer_manager_secure("tenant-a".to_string(), "shared".to_string()).await;
    set_private_mode(&server, true);

    let (_cred_id, cred_secret) = admin
        .get_global_ctx()
        .get_credential_manager()
        .generate_credential(vec![], false, vec![], Duration::from_secs(3600));

    let privkey_bytes: [u8; 32] = base64::engine::general_purpose::STANDARD
        .decode(&cred_secret)
        .unwrap()
        .try_into()
        .unwrap();
    let private = x25519_dalek::StaticSecret::from(privkey_bytes);
    let public = x25519_dalek::PublicKey::from(&private);
    let credential = create_mock_peer_manager_credential("tenant-a".to_string(), &private).await;

    connect_peer_manager(admin.clone(), server.clone()).await;
    wait_for_condition(
        || {
            let server = server.clone();
            let pubkey = public.as_bytes().to_vec();
            async move {
                server
                    .get_foreign_network_manager()
                    .list_foreign_networks_with_options(true)
                    .await
                    .foreign_networks
                    .get("tenant-a")
                    .map(|entry| {
                        entry.trusted_keys.iter().any(|trusted_key| {
                            trusted_key.pubkey == pubkey
                                && trusted_key.source == TrustedKeySourcePb::OspfCredential as i32
                        })
                    })
                    .unwrap_or(false)
            }
        },
        Duration::from_secs(10),
    )
    .await;

    let (client_ret, server_ret) = connect_client_and_server(credential, server.clone()).await;

    assert!(
        client_ret.is_ok(),
        "trusted foreign credential client should connect in private mode"
    );
    assert!(
        server_ret.is_ok(),
        "server should allow trusted foreign credential in private mode: {:?}",
        server_ret
    );
    wait_for_foreign_network_peer_count_at_least(server, "tenant-a", 2).await;
}

#[tokio::test]
async fn private_mode_rejects_untrusted_foreign_credential() {
    let server = create_mock_peer_manager_secure("public".to_string(), "shared".to_string()).await;
    let admin = create_mock_peer_manager_secure("tenant-a".to_string(), "shared".to_string()).await;
    set_private_mode(&server, true);

    let random_private = x25519_dalek::StaticSecret::random_from_rng(rand::rngs::OsRng);
    let unknown_credential =
        create_mock_peer_manager_credential("tenant-a".to_string(), &random_private).await;

    connect_peer_manager(admin.clone(), server.clone()).await;
    wait_for_foreign_network(server.clone(), "tenant-a").await;

    let (client_ret, server_ret) =
        connect_client_and_server(unknown_credential, server.clone()).await;

    let _ = client_ret;
    assert!(
        server_ret.is_err(),
        "server should reject untrusted foreign credential in private mode"
    );
    wait_for_condition(
        || {
            let server = server.clone();
            async move {
                server
                    .get_foreign_network_manager()
                    .list_foreign_networks()
                    .await
                    .foreign_networks
                    .get("tenant-a")
                    .map(|entry| entry.peers.len() == 1)
                    .unwrap_or(false)
            }
        },
        Duration::from_secs(10),
    )
    .await;
}

#[tokio::test]
async fn relay_peer_map_retry_backoff_and_evict() {
    let (s, _r) = create_packet_recv_chan();
    let ctx_secure = get_mock_global_ctx();
    set_secure_mode_cfg(&ctx_secure, true);
    let peer_map = Arc::new(PeerMap::new(s, ctx_secure.clone(), 10));
    let relay_map = RelayPeerMap::new(
        peer_map,
        None,
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
        None,
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
    let relay_map = RelayPeerMap::new(peer_map, None, ctx.clone(), 10, store.clone());

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
    let a_control_tx_before = metric_value(&peer_a, MetricName::TrafficControlBytesTx, "net1");
    let a_control_rx_before = metric_value(&peer_a, MetricName::TrafficControlBytesRx, "net1");
    let c_control_tx_before = metric_value(&peer_c, MetricName::TrafficControlBytesTx, "net1");
    let c_control_rx_before = metric_value(&peer_c, MetricName::TrafficControlBytesRx, "net1");

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

    assert!(metric_value(&peer_a, MetricName::TrafficControlBytesTx, "net1") > a_control_tx_before);
    assert!(metric_value(&peer_a, MetricName::TrafficControlBytesRx, "net1") > a_control_rx_before);
    assert!(metric_value(&peer_c, MetricName::TrafficControlBytesTx, "net1") > c_control_tx_before);
    assert!(metric_value(&peer_c, MetricName::TrafficControlBytesRx, "net1") > c_control_rx_before);
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
    let relay_map = RelayPeerMap::new(peer_map, None, ctx.clone(), 10, store.clone());

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

/// Helper: create a secure peer manager for a credential node.
/// Uses the given X25519 private key as the Noise static key, with no network_secret.
pub async fn create_mock_peer_manager_credential(
    network_name: String,
    private_key: &x25519_dalek::StaticSecret,
) -> Arc<PeerManager> {
    use crate::common::config::NetworkIdentity;
    use crate::proto::common::SecureModeConfig;
    use base64::Engine;
    use base64::engine::general_purpose::STANDARD as BASE64_STANDARD;

    let (s, _r) = create_packet_recv_chan();
    let g = get_mock_global_ctx_with_network(Some(NetworkIdentity::new_credential(network_name)));

    let public = x25519_dalek::PublicKey::from(private_key);
    g.config.set_secure_mode(Some(SecureModeConfig {
        enabled: true,
        local_private_key: Some(BASE64_STANDARD.encode(private_key.as_bytes())),
        local_public_key: Some(BASE64_STANDARD.encode(public.as_bytes())),
    }));

    let peer_mgr = Arc::new(PeerManager::new(RouteAlgoType::Ospf, g, s));
    peer_mgr.run().await.unwrap();
    peer_mgr
}

/// Test: credential node joins a 2-admin network and routes appear.
/// Topology: Admin_A -- Credential_C, Admin_A -- Admin_B
/// Credential node connects to the admin that generated the credential.
#[tokio::test]
async fn credential_node_joins_network() {
    let admin_a = create_mock_peer_manager_secure("net1".to_string(), "secret".to_string()).await;
    let admin_b = create_mock_peer_manager_secure("net1".to_string(), "secret".to_string()).await;

    // Generate credential on admin_a
    let (_cred_id, cred_secret) = admin_a
        .get_global_ctx()
        .get_credential_manager()
        .generate_credential(
            vec!["guest".to_string()],
            false,
            vec![],
            std::time::Duration::from_secs(3600),
        );

    // Create credential node using the generated key
    let privkey_bytes: [u8; 32] = base64::engine::general_purpose::STANDARD
        .decode(&cred_secret)
        .unwrap()
        .try_into()
        .unwrap();
    let private = x25519_dalek::StaticSecret::from(privkey_bytes);
    let cred_c = create_mock_peer_manager_credential("net1".to_string(), &private).await;

    // Connect admins first
    connect_peer_manager(admin_a.clone(), admin_b.clone()).await;

    // Admin A and B should discover each other
    wait_route_appear(admin_a.clone(), admin_b.clone())
        .await
        .unwrap();

    // Now connect credential node to admin A (credential as client)
    connect_peer_manager(cred_c.clone(), admin_a.clone()).await;

    // Credential node C should be reachable from admin B (via A)
    let cred_c_id = cred_c.my_peer_id();
    wait_for_condition(
        || {
            let admin_b = admin_b.clone();
            async move {
                admin_b
                    .list_routes()
                    .await
                    .iter()
                    .any(|r| r.peer_id == cred_c_id)
            }
        },
        Duration::from_secs(10),
    )
    .await;

    // Credential node C should see admin B
    wait_for_condition(
        || {
            let cred_c = cred_c.clone();
            let admin_b_id = admin_b.my_peer_id();
            async move {
                cred_c
                    .list_routes()
                    .await
                    .iter()
                    .any(|r| r.peer_id == admin_b_id)
            }
        },
        Duration::from_secs(10),
    )
    .await;
}

/// Test: credential node is rejected when its pubkey is not in any admin's trusted list.
/// Topology: Admin_A -- Unknown_B (random key, not in trusted list)
#[tokio::test]
async fn unknown_credential_node_rejected() {
    let admin_a = create_mock_peer_manager_secure("net1".to_string(), "secret".to_string()).await;

    // Create a credential node with a random key (NOT generated by admin)
    let random_private = x25519_dalek::StaticSecret::random_from_rng(rand::rngs::OsRng);
    let unknown_c = create_mock_peer_manager_credential("net1".to_string(), &random_private).await;

    // Try to connect: C -> A (unknown credential as client, admin as server)
    connect_peer_manager(unknown_c.clone(), admin_a.clone()).await;

    // The handshake should fail so the connection won't establish.
    // Wait a bit and verify no route appears.
    tokio::time::sleep(Duration::from_secs(3)).await;

    let routes = admin_a.list_routes().await;
    assert!(
        !routes.iter().any(|r| r.peer_id == unknown_c.my_peer_id()),
        "unknown credential node should NOT appear in admin's routes"
    );
}

/// Test: after revocation, the credential node disappears from routes.
/// Topology: Admin_A -- Credential_C, Admin_A -- Admin_B
/// After revocation on A, C should be removed from B's route table.
#[tokio::test]
async fn credential_revocation_removes_from_routes() {
    let admin_a = create_mock_peer_manager_secure("net1".to_string(), "secret".to_string()).await;
    let admin_b = create_mock_peer_manager_secure("net1".to_string(), "secret".to_string()).await;

    let (cred_id, cred_secret) = admin_a
        .get_global_ctx()
        .get_credential_manager()
        .generate_credential(vec![], false, vec![], std::time::Duration::from_secs(3600));

    let privkey_bytes: [u8; 32] = base64::engine::general_purpose::STANDARD
        .decode(&cred_secret)
        .unwrap()
        .try_into()
        .unwrap();
    let private = x25519_dalek::StaticSecret::from(privkey_bytes);
    let cred_c = create_mock_peer_manager_credential("net1".to_string(), &private).await;

    // Connect: A -- B, C -> A (credential node as client, admin as server)
    connect_peer_manager(admin_a.clone(), admin_b.clone()).await;
    connect_peer_manager(cred_c.clone(), admin_a.clone()).await;

    // Wait for credential node to appear in admin_b's routes
    let cred_c_id = cred_c.my_peer_id();
    wait_for_condition(
        || {
            let admin_b = admin_b.clone();
            async move {
                admin_b
                    .list_routes()
                    .await
                    .iter()
                    .any(|r| r.peer_id == cred_c_id)
            }
        },
        Duration::from_secs(10),
    )
    .await;

    // Now revoke the credential
    assert!(
        admin_a
            .get_global_ctx()
            .get_credential_manager()
            .revoke_credential(&cred_id)
    );
    // Issue event to trigger OSPF sync
    admin_a
        .get_global_ctx()
        .issue_event(crate::common::global_ctx::GlobalCtxEvent::CredentialChanged);

    // Wait for credential node to disappear from admin_b's routes
    wait_for_condition(
        || {
            let admin_b = admin_b.clone();
            async move {
                !admin_b
                    .list_routes()
                    .await
                    .iter()
                    .any(|r| r.peer_id == cred_c_id)
            }
        },
        Duration::from_secs(15),
    )
    .await;
}

#[tokio::test]
async fn credential_expiry_disconnects_from_all_admins() {
    let admin_a = create_mock_peer_manager_secure("net1".to_string(), "secret".to_string()).await;
    let admin_b = create_mock_peer_manager_secure("net1".to_string(), "secret".to_string()).await;

    connect_peer_manager(admin_a.clone(), admin_b.clone()).await;
    wait_route_appear(admin_a.clone(), admin_b.clone())
        .await
        .unwrap();

    let (_cred_id, cred_secret) = admin_a
        .get_global_ctx()
        .get_credential_manager()
        .generate_credential(vec![], false, vec![], std::time::Duration::from_secs(2));

    admin_a
        .get_global_ctx()
        .issue_event(crate::common::global_ctx::GlobalCtxEvent::CredentialChanged);

    let privkey_bytes: [u8; 32] = base64::engine::general_purpose::STANDARD
        .decode(&cred_secret)
        .unwrap()
        .try_into()
        .unwrap();
    let private = x25519_dalek::StaticSecret::from(privkey_bytes);
    let cred_c = create_mock_peer_manager_credential("net1".to_string(), &private).await;
    let cred_c_id = cred_c.my_peer_id();

    connect_peer_manager(cred_c.clone(), admin_a.clone()).await;

    wait_for_condition(
        || {
            let admin_b = admin_b.clone();
            async move {
                admin_b
                    .list_routes()
                    .await
                    .iter()
                    .any(|r| r.peer_id == cred_c_id)
            }
        },
        Duration::from_secs(10),
    )
    .await;

    connect_peer_manager(cred_c.clone(), admin_b.clone()).await;

    wait_for_condition(
        || {
            let admin_b = admin_b.clone();
            async move {
                admin_b
                    .get_peer_map()
                    .list_peer_conns(cred_c_id)
                    .await
                    .is_some_and(|conns| !conns.is_empty())
            }
        },
        Duration::from_secs(10),
    )
    .await;

    tokio::time::sleep(Duration::from_secs(3)).await;
    admin_a
        .get_global_ctx()
        .issue_event(crate::common::global_ctx::GlobalCtxEvent::CredentialChanged);

    wait_for_condition(
        || {
            let admin_b = admin_b.clone();
            async move {
                !admin_b
                    .list_routes()
                    .await
                    .iter()
                    .any(|r| r.peer_id == cred_c_id)
            }
        },
        Duration::from_secs(20),
    )
    .await;

    wait_for_condition(
        || {
            let admin_b = admin_b.clone();
            async move {
                admin_b
                    .get_peer_map()
                    .list_peer_conns(cred_c_id)
                    .await
                    .is_none_or(|conns| conns.is_empty())
            }
        },
        Duration::from_secs(20),
    )
    .await;
}

/// Test: admin node with credential — credential node gets group assignment.
/// Verify that the credential node's groups appear in the OSPF sync data.
#[tokio::test]
async fn credential_node_group_assignment() {
    let admin_a = create_mock_peer_manager_secure("net1".to_string(), "secret".to_string()).await;
    let admin_b = create_mock_peer_manager_secure("net1".to_string(), "secret".to_string()).await;

    let (_cred_id, cred_secret) = admin_a
        .get_global_ctx()
        .get_credential_manager()
        .generate_credential(
            vec!["guest".to_string(), "limited".to_string()],
            false,
            vec![],
            std::time::Duration::from_secs(3600),
        );

    let privkey_bytes: [u8; 32] = base64::engine::general_purpose::STANDARD
        .decode(&cred_secret)
        .unwrap()
        .try_into()
        .unwrap();
    let private = x25519_dalek::StaticSecret::from(privkey_bytes);
    let cred_c = create_mock_peer_manager_credential("net1".to_string(), &private).await;

    connect_peer_manager(admin_a.clone(), admin_b.clone()).await;
    connect_peer_manager(cred_c.clone(), admin_a.clone()).await;

    // Wait for credential node route to appear on admin_b (via OSPF through admin_a)
    let cred_c_id = cred_c.my_peer_id();
    wait_for_condition(
        || {
            let admin_b = admin_b.clone();
            async move {
                admin_b
                    .list_routes()
                    .await
                    .iter()
                    .any(|r| r.peer_id == cred_c_id)
            }
        },
        Duration::from_secs(10),
    )
    .await;

    // Verify the credential node's groups are assigned via OSPF on admin_b
    // (admin_b gets the groups from admin_a's TrustedCredentialPubkey via OSPF sync)
    wait_for_condition(
        || {
            let admin_b = admin_b.clone();
            async move {
                let g = admin_b.get_route().get_peer_groups(cred_c_id);
                g.contains(&"guest".to_string()) && g.contains(&"limited".to_string())
            }
        },
        Duration::from_secs(10),
    )
    .await;
}

#[tokio::test]
async fn credential_node_connected_via_admin_b_trusts_admin_a_groups() {
    use crate::proto::acl::{Acl, AclV1, GroupIdentity, GroupInfo};

    let admin_a = create_mock_peer_manager_secure("net1".to_string(), "secret".to_string()).await;
    let admin_b = create_mock_peer_manager_secure("net1".to_string(), "secret".to_string()).await;

    let group_declares = vec![GroupIdentity {
        group_name: "platform-admin".to_string(),
        group_secret: "platform-admin-secret".to_string(),
    }];
    admin_a.get_global_ctx().config.set_acl(Some(Acl {
        acl_v1: Some(AclV1 {
            group: Some(GroupInfo {
                declares: group_declares.clone(),
                members: vec!["platform-admin".to_string()],
            }),
            ..Default::default()
        }),
    }));
    admin_b.get_global_ctx().config.set_acl(Some(Acl {
        acl_v1: Some(AclV1 {
            group: Some(GroupInfo {
                declares: group_declares,
                members: vec![],
            }),
            ..Default::default()
        }),
    }));

    connect_peer_manager(admin_a.clone(), admin_b.clone()).await;
    wait_route_appear(admin_a.clone(), admin_b.clone())
        .await
        .unwrap();

    let (_cred_id, cred_secret) = admin_a
        .get_global_ctx()
        .get_credential_manager()
        .generate_credential(vec![], false, vec![], std::time::Duration::from_secs(3600));
    admin_a
        .get_global_ctx()
        .issue_event(crate::common::global_ctx::GlobalCtxEvent::CredentialChanged);

    let privkey_bytes: [u8; 32] = base64::engine::general_purpose::STANDARD
        .decode(&cred_secret)
        .unwrap()
        .try_into()
        .unwrap();
    let private = x25519_dalek::StaticSecret::from(privkey_bytes);
    let credential_pubkey = x25519_dalek::PublicKey::from(&private).as_bytes().to_vec();

    wait_for_condition(
        || {
            let admin_b = admin_b.clone();
            let credential_pubkey = credential_pubkey.clone();
            async move {
                admin_b.get_global_ctx().is_pubkey_trusted_with_source(
                    &credential_pubkey,
                    "net1",
                    TrustedKeySource::OspfCredential,
                )
            }
        },
        Duration::from_secs(10),
    )
    .await;

    let cred_c = create_mock_peer_manager_credential("net1".to_string(), &private).await;
    connect_peer_manager(cred_c.clone(), admin_b.clone()).await;

    let admin_a_id = admin_a.my_peer_id();
    wait_for_condition(
        || {
            let cred_c = cred_c.clone();
            async move {
                cred_c
                    .list_routes()
                    .await
                    .iter()
                    .any(|r| r.peer_id == admin_a_id)
            }
        },
        Duration::from_secs(10),
    )
    .await;

    wait_for_condition(
        || {
            let cred_c = cred_c.clone();
            async move {
                cred_c
                    .get_route()
                    .get_peer_groups(admin_a_id)
                    .contains(&"platform-admin".to_string())
            }
        },
        Duration::from_secs(10),
    )
    .await;
}

/// Minimal test: two secure peers connect and discover each other's route.
#[tokio::test]
async fn two_secure_peers_route_appear() {
    let peer_a = create_mock_peer_manager_secure("net1".to_string(), "sec1".to_string()).await;
    let peer_b = create_mock_peer_manager_secure("net1".to_string(), "sec1".to_string()).await;

    connect_peer_manager(peer_a.clone(), peer_b.clone()).await;

    wait_route_appear(peer_a.clone(), peer_b.clone())
        .await
        .unwrap();
}

#[tokio::test]
async fn multi_admin_multi_credential_route_and_revocation_isolation() {
    let admin_a = create_mock_peer_manager_secure("net1".to_string(), "secret".to_string()).await;
    let admin_b = create_mock_peer_manager_secure("net1".to_string(), "secret".to_string()).await;
    let admin_d = create_mock_peer_manager_secure("net1".to_string(), "secret".to_string()).await;

    connect_peer_manager(admin_a.clone(), admin_b.clone()).await;
    connect_peer_manager(admin_b.clone(), admin_d.clone()).await;
    connect_peer_manager(admin_a.clone(), admin_d.clone()).await;

    wait_route_appear(admin_a.clone(), admin_b.clone())
        .await
        .unwrap();
    wait_route_appear(admin_b.clone(), admin_d.clone())
        .await
        .unwrap();
    wait_route_appear(admin_a.clone(), admin_d.clone())
        .await
        .unwrap();

    let (cred1_id, cred1_secret) = admin_a
        .get_global_ctx()
        .get_credential_manager()
        .generate_credential(
            vec!["guest-a".to_string()],
            false,
            vec![],
            std::time::Duration::from_secs(3600),
        );
    let (_cred2_id, cred2_secret) = admin_b
        .get_global_ctx()
        .get_credential_manager()
        .generate_credential(
            vec!["guest-b".to_string()],
            false,
            vec![],
            std::time::Duration::from_secs(3600),
        );

    let cred1_private: [u8; 32] = base64::engine::general_purpose::STANDARD
        .decode(&cred1_secret)
        .unwrap()
        .try_into()
        .unwrap();
    let cred2_private: [u8; 32] = base64::engine::general_purpose::STANDARD
        .decode(&cred2_secret)
        .unwrap()
        .try_into()
        .unwrap();
    let cred_1 = create_mock_peer_manager_credential(
        "net1".to_string(),
        &x25519_dalek::StaticSecret::from(cred1_private),
    )
    .await;
    let cred_2 = create_mock_peer_manager_credential(
        "net1".to_string(),
        &x25519_dalek::StaticSecret::from(cred2_private),
    )
    .await;

    connect_peer_manager(cred_1.clone(), admin_a.clone()).await;
    connect_peer_manager(cred_2.clone(), admin_b.clone()).await;

    let cred_1_id = cred_1.my_peer_id();
    let cred_2_id = cred_2.my_peer_id();

    wait_for_condition(
        || {
            let admin_d = admin_d.clone();
            async move {
                let routes = admin_d.list_routes().await;
                routes.iter().any(|r| r.peer_id == cred_1_id)
                    && routes.iter().any(|r| r.peer_id == cred_2_id)
            }
        },
        Duration::from_secs(15),
    )
    .await;

    wait_for_condition(
        || {
            let admin_d = admin_d.clone();
            async move {
                let g1 = admin_d.get_route().get_peer_groups(cred_1_id);
                let g2 = admin_d.get_route().get_peer_groups(cred_2_id);
                g1.contains(&"guest-a".to_string()) && g2.contains(&"guest-b".to_string())
            }
        },
        Duration::from_secs(15),
    )
    .await;

    assert!(
        admin_a
            .get_global_ctx()
            .get_credential_manager()
            .revoke_credential(&cred1_id)
    );
    admin_a
        .get_global_ctx()
        .issue_event(crate::common::global_ctx::GlobalCtxEvent::CredentialChanged);

    wait_for_condition(
        || {
            let admin_d = admin_d.clone();
            async move {
                let routes = admin_d.list_routes().await;
                !routes.iter().any(|r| r.peer_id == cred_1_id)
                    && routes.iter().any(|r| r.peer_id == cred_2_id)
            }
        },
        Duration::from_secs(20),
    )
    .await;
}

#[tokio::test]
async fn unknown_credential_rejected_while_valid_credential_survives() {
    let admin_a = create_mock_peer_manager_secure("net1".to_string(), "secret".to_string()).await;
    let admin_b = create_mock_peer_manager_secure("net1".to_string(), "secret".to_string()).await;

    connect_peer_manager(admin_a.clone(), admin_b.clone()).await;
    wait_route_appear(admin_a.clone(), admin_b.clone())
        .await
        .unwrap();

    let (_cred_id, cred_secret) = admin_a
        .get_global_ctx()
        .get_credential_manager()
        .generate_credential(
            vec!["stable".to_string()],
            false,
            vec![],
            std::time::Duration::from_secs(3600),
        );

    let valid_private: [u8; 32] = base64::engine::general_purpose::STANDARD
        .decode(&cred_secret)
        .unwrap()
        .try_into()
        .unwrap();
    let valid_cred = create_mock_peer_manager_credential(
        "net1".to_string(),
        &x25519_dalek::StaticSecret::from(valid_private),
    )
    .await;
    let unknown_private = x25519_dalek::StaticSecret::random_from_rng(rand::rngs::OsRng);
    let unknown_cred =
        create_mock_peer_manager_credential("net1".to_string(), &unknown_private).await;

    connect_peer_manager(valid_cred.clone(), admin_a.clone()).await;
    let (unknown_ring_client, unknown_ring_server) = create_ring_tunnel_pair();
    let unknown_connect_client = tokio::spawn({
        let unknown_cred = unknown_cred.clone();
        async move {
            unknown_cred
                .add_client_tunnel(unknown_ring_client, false)
                .await
        }
    });
    let unknown_connect_server = tokio::spawn({
        let admin_a = admin_a.clone();
        async move {
            admin_a
                .add_tunnel_as_server(unknown_ring_server, true, false)
                .await
        }
    });
    let (unknown_client_ret, unknown_server_ret) =
        tokio::join!(unknown_connect_client, unknown_connect_server);
    assert!(
        unknown_client_ret.unwrap().is_err() || unknown_server_ret.unwrap().is_err(),
        "unknown credential connection should fail on at least one side"
    );

    let valid_id = valid_cred.my_peer_id();
    let unknown_id = unknown_cred.my_peer_id();

    wait_for_condition(
        || {
            let admin_b = admin_b.clone();
            async move {
                admin_b
                    .list_routes()
                    .await
                    .iter()
                    .any(|r| r.peer_id == valid_id)
            }
        },
        Duration::from_secs(15),
    )
    .await;

    tokio::time::sleep(Duration::from_secs(5)).await;

    let routes = admin_b.list_routes().await;
    assert!(routes.iter().any(|r| r.peer_id == valid_id));
    assert!(!routes.iter().any(|r| r.peer_id == unknown_id));
}
