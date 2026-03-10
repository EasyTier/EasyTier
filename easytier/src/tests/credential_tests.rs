//! Credential system integration tests
//!
//! These tests verify the credential-based authentication system where:
//! - Admin nodes hold network_secret and can generate credentials
//! - Credential nodes use X25519 keypairs to authenticate without network_secret
//! - Credentials can be revoked and propagate across the network

use std::time::Duration;

use crate::{
    common::{
        config::{ConfigLoader, NetworkIdentity, TomlConfigLoader},
        global_ctx::GlobalCtxEvent,
    },
    instance::instance::Instance,
    tests::three_node::{generate_secure_mode_config, generate_secure_mode_config_with_key},
    tunnel::{common::tests::wait_for_condition, tcp::TcpTunnelConnector},
};

use super::{add_ns_to_bridge, create_netns, del_netns, drop_insts, ping_test};

use rstest::rstest;

/// Prepare network namespaces for credential tests
/// Topology:
///   br_a (10.1.1.0/24): ns_adm (10.1.1.1), ns_c1 (10.1.1.2), ns_c2 (10.1.1.3), ns_c3 (10.1.1.4)
///   br_b (10.1.2.0/24): ns_adm2 (10.1.2.1) - for multi-admin tests
/// Note: Using short names (max 15 chars for veth interfaces)
pub fn prepare_credential_network() {
    // Clean up any existing namespaces
    for ns in ["ns_adm", "ns_c1", "ns_c2", "ns_c3", "ns_adm2"] {
        del_netns(ns);
    }

    // Create bridge br_a for admin and credentials
    let _ = std::process::Command::new("ip")
        .args(["link", "del", "br_a"])
        .output();
    let _ = std::process::Command::new("brctl")
        .args(["delbr", "br_a"])
        .output();
    let _ = std::process::Command::new("brctl")
        .args(["addbr", "br_a"])
        .output()
        .expect("Failed to create br_a");
    let _ = std::process::Command::new("ip")
        .args(["link", "set", "br_a", "up"])
        .output();

    // Create namespaces and add to bridge
    create_netns("ns_adm", "10.1.1.1/24", "fd11::1/64");
    add_ns_to_bridge("br_a", "ns_adm");

    create_netns("ns_c1", "10.1.1.2/24", "fd11::2/64");
    add_ns_to_bridge("br_a", "ns_c1");

    create_netns("ns_c2", "10.1.1.3/24", "fd11::3/64");
    add_ns_to_bridge("br_a", "ns_c2");

    // Create ns_c3 for relay tests (needs 4 nodes)
    create_netns("ns_c3", "10.1.1.4/24", "fd11::4/64");
    add_ns_to_bridge("br_a", "ns_c3");

    // Create bridge br_b for second admin (multi-admin tests)
    let _ = std::process::Command::new("ip")
        .args(["link", "del", "br_b"])
        .output();
    let _ = std::process::Command::new("brctl")
        .args(["delbr", "br_b"])
        .output();
    let _ = std::process::Command::new("brctl")
        .args(["addbr", "br_b"])
        .output()
        .expect("Failed to create br_b");
    let _ = std::process::Command::new("ip")
        .args(["link", "set", "br_b", "up"])
        .output();

    create_netns("ns_adm2", "10.1.2.1/24", "fd12::1/64");
    add_ns_to_bridge("br_b", "ns_adm2");
}

/// Helper: Create credential node config with generated credential
async fn create_credential_config(
    admin_inst: &Instance,
    inst_name: &str,
    ns: Option<&str>,
    ipv4: &str,
    ipv6: &str,
) -> TomlConfigLoader {
    use base64::Engine as _;

    // Generate credential on admin
    let (_cred_id, cred_secret) = admin_inst
        .get_global_ctx()
        .get_credential_manager()
        .generate_credential(vec![], false, vec![], Duration::from_secs(3600));

    // Decode private key
    let privkey_bytes: [u8; 32] = base64::prelude::BASE64_STANDARD
        .decode(&cred_secret)
        .unwrap()
        .try_into()
        .unwrap();
    let private = x25519_dalek::StaticSecret::from(privkey_bytes);

    // Create config
    let config = TomlConfigLoader::default();
    config.set_inst_name(inst_name.to_owned());
    config.set_netns(ns.map(|s| s.to_owned()));
    config.set_ipv4(Some(ipv4.parse().unwrap()));
    config.set_ipv6(Some(ipv6.parse().unwrap()));
    config.set_listeners(vec![]);
    config.set_network_identity(NetworkIdentity::new_credential(
        admin_inst
            .get_global_ctx()
            .get_network_identity()
            .network_name
            .clone(),
    ));
    config.set_secure_mode(Some(generate_secure_mode_config_with_key(&private)));

    config
}

/// Helper: Create admin node config
fn create_admin_config(
    inst_name: &str,
    ns: Option<&str>,
    ipv4: &str,
    ipv6: &str,
) -> TomlConfigLoader {
    let config = TomlConfigLoader::default();
    config.set_inst_name(inst_name.to_owned());
    config.set_netns(ns.map(|s| s.to_owned()));
    config.set_ipv4(Some(ipv4.parse().unwrap()));
    config.set_ipv6(Some(ipv6.parse().unwrap()));
    config.set_listeners(vec![
        "tcp://0.0.0.0:11010".parse().unwrap(),
        "udp://0.0.0.0:11010".parse().unwrap(),
    ]);
    config.set_network_identity(NetworkIdentity::new(
        "test_network".to_string(),
        "test_secret".to_string(),
    ));
    config.set_secure_mode(Some(generate_secure_mode_config()));

    config
}

fn create_shared_config(
    inst_name: &str,
    ns: Option<&str>,
    ipv4: &str,
    ipv6: &str,
) -> TomlConfigLoader {
    let config = TomlConfigLoader::default();
    config.set_inst_name(inst_name.to_owned());
    config.set_netns(ns.map(|s| s.to_owned()));
    config.set_ipv4(Some(ipv4.parse().unwrap()));
    config.set_ipv6(Some(ipv6.parse().unwrap()));
    config.set_listeners(vec![
        "tcp://0.0.0.0:11010".parse().unwrap(),
        "udp://0.0.0.0:11010".parse().unwrap(),
    ]);
    config.set_network_identity(NetworkIdentity::new(
        "shared_network".to_string(),
        "".to_string(),
    ));
    config.set_secure_mode(Some(generate_secure_mode_config()));
    config
}

/// Test 1: Basic credential node connectivity
/// Topology: Admin ← Credential
/// Verifies that a credential node can connect to an admin node and appears in routes
#[tokio::test]
#[serial_test::serial]
async fn credential_basic_connectivity() {
    prepare_credential_network();

    // Create admin node
    let admin_config = create_admin_config("admin", Some("ns_adm"), "10.144.144.1", "fd00::1/64");
    let mut admin_inst = Instance::new(admin_config);
    admin_inst.run().await.unwrap();

    // Create credential node
    let cred_config = create_credential_config(
        &admin_inst,
        "cred",
        Some("ns_c1"),
        "10.144.144.2",
        "fd00::2/64",
    )
    .await;
    let mut cred_inst = Instance::new(cred_config);
    cred_inst.run().await.unwrap();

    // Credential connects to admin
    cred_inst
        .get_conn_manager()
        .add_connector(TcpTunnelConnector::new(
            "tcp://10.1.1.1:11010".parse().unwrap(),
        ));

    let cred_peer_id = cred_inst.peer_id();
    let admin_peer_id = admin_inst.peer_id();
    println!(
        "Admin peer_id: {}, Credential peer_id: {}",
        admin_peer_id, cred_peer_id
    );

    // Wait a bit for connection attempt
    tokio::time::sleep(Duration::from_secs(2)).await;

    // Check peers and connections
    let admin_peers = admin_inst.get_peer_manager().get_peer_map().list_peers();
    let cred_peers = cred_inst.get_peer_manager().get_peer_map().list_peers();
    println!("Admin peers: {:?}", admin_peers);
    println!("Credential peers: {:?}", cred_peers);

    // Wait for credential to appear in admin's route table
    wait_for_condition(
        || async {
            let routes = admin_inst.get_peer_manager().list_routes().await;
            let cred_routes = cred_inst.get_peer_manager().list_routes().await;
            let admin_peers = admin_inst.get_peer_manager().get_peer_map().list_peers();
            let cred_peers = cred_inst.get_peer_manager().get_peer_map().list_peers();
            println!(
                "Admin peers: {:?}, routes: {:?}",
                admin_peers,
                routes
                    .iter()
                    .map(|r| (r.peer_id, r.ipv4_addr))
                    .collect::<Vec<_>>()
            );
            println!(
                "Credential peers: {:?}, routes: {:?}",
                cred_peers,
                cred_routes
                    .iter()
                    .map(|r| (r.peer_id, r.ipv4_addr))
                    .collect::<Vec<_>>()
            );
            routes.iter().any(|r| r.peer_id == cred_peer_id)
        },
        Duration::from_secs(10),
    )
    .await;

    // Verify connectivity
    wait_for_condition(
        || async { ping_test("ns_adm", "10.144.144.2", None).await },
        Duration::from_secs(10),
    )
    .await;

    wait_for_condition(
        || async { ping_test("ns_c1", "10.144.144.1", None).await },
        Duration::from_secs(10),
    )
    .await;

    drop_insts(vec![admin_inst, cred_inst]).await;
}

/// Test 5-6: Credential relay capability with allow_relay parameter
/// Topology: Admin ← Credential_A, Admin ← Credential_B, Admin ← Credential_C(listener, allow_relay)
/// Verifies routing behavior based on allow_relay flag:
/// - allow_relay=true: A→B route goes through C (cost 2 via C)
/// - allow_relay=false: A→B route goes through Admin (cost 2 via Admin)
#[rstest]
#[case(true)]
#[case(false)]
#[tokio::test]
#[serial_test::serial]
async fn credential_relay_capability(#[case] allow_relay: bool) {
    use crate::peers::route_trait::NextHopPolicy;

    prepare_credential_network();

    // Create admin node
    let admin_config = create_admin_config("admin", Some("ns_adm"), "10.144.144.1", "fd00::1/64");
    let mut admin_inst = Instance::new(admin_config);
    let mut ff = admin_inst.get_global_ctx().get_feature_flags();
    // if cred c allow relay, we set admin inst avoid relay (if other same-cost path available, admin will not relay data)
    ff.avoid_relay_data = allow_relay;
    admin_inst.get_global_ctx().set_feature_flags(ff);
    admin_inst.run().await.unwrap();

    let admin_peer_id = admin_inst.peer_id();

    // Generate credentials for A, B, C
    // C has configurable allow_relay
    let (_cred_a_id, cred_a_secret) = admin_inst
        .get_global_ctx()
        .get_credential_manager()
        .generate_credential(vec![], false, vec![], Duration::from_secs(3600));

    let (_cred_b_id, cred_b_secret) = admin_inst
        .get_global_ctx()
        .get_credential_manager()
        .generate_credential(vec![], false, vec![], Duration::from_secs(3600));

    let (_cred_c_id, cred_c_secret) = admin_inst
        .get_global_ctx()
        .get_credential_manager()
        .generate_credential(vec![], allow_relay, vec![], Duration::from_secs(3600));

    // Create credential A on ns_c1
    let cred_a_config = {
        use base64::Engine as _;
        let privkey_bytes: [u8; 32] = base64::prelude::BASE64_STANDARD
            .decode(&cred_a_secret)
            .unwrap()
            .try_into()
            .unwrap();
        let private = x25519_dalek::StaticSecret::from(privkey_bytes);
        let config = TomlConfigLoader::default();
        config.set_inst_name("cred_a".to_string());
        config.set_netns(Some("ns_c1".to_string()));
        config.set_ipv4(Some("10.144.144.2".parse().unwrap()));
        config.set_ipv6(Some("fd00::2/64".parse().unwrap()));
        config.set_network_identity(NetworkIdentity::new_credential(
            admin_inst
                .get_global_ctx()
                .get_network_identity()
                .network_name
                .clone(),
        ));
        config.set_secure_mode(Some(generate_secure_mode_config_with_key(&private)));
        config
    };
    let mut cred_a_inst = Instance::new(cred_a_config);
    cred_a_inst.run().await.unwrap();

    // Create credential B on ns_c2
    let cred_b_config = {
        use base64::Engine as _;
        let privkey_bytes: [u8; 32] = base64::prelude::BASE64_STANDARD
            .decode(&cred_b_secret)
            .unwrap()
            .try_into()
            .unwrap();
        let private = x25519_dalek::StaticSecret::from(privkey_bytes);
        let config = TomlConfigLoader::default();
        config.set_inst_name("cred_b".to_string());
        config.set_netns(Some("ns_c2".to_string()));
        config.set_ipv4(Some("10.144.144.3".parse().unwrap()));
        config.set_ipv6(Some("fd00::3/64".parse().unwrap()));
        config.set_network_identity(NetworkIdentity::new_credential(
            admin_inst
                .get_global_ctx()
                .get_network_identity()
                .network_name
                .clone(),
        ));
        config.set_secure_mode(Some(generate_secure_mode_config_with_key(&private)));
        config
    };
    let mut cred_b_inst = Instance::new(cred_b_config);
    cred_b_inst.run().await.unwrap();

    // Create credential C on ns_c3 WITH listener (so A and B can connect to it)
    let cred_c_config = {
        use base64::Engine as _;
        let privkey_bytes: [u8; 32] = base64::prelude::BASE64_STANDARD
            .decode(&cred_c_secret)
            .unwrap()
            .try_into()
            .unwrap();
        let private = x25519_dalek::StaticSecret::from(privkey_bytes);
        let config = TomlConfigLoader::default();
        config.set_inst_name("cred_c".to_string());
        config.set_netns(Some("ns_c3".to_string()));
        config.set_ipv4(Some("10.144.144.4".parse().unwrap()));
        config.set_ipv6(Some("fd00::4/64".parse().unwrap()));
        // C has listener so A and B can connect to it
        config.set_listeners(vec!["tcp://0.0.0.0:11020".parse().unwrap()]);
        config.set_network_identity(NetworkIdentity::new_credential(
            admin_inst
                .get_global_ctx()
                .get_network_identity()
                .network_name
                .clone(),
        ));
        config.set_secure_mode(Some(generate_secure_mode_config_with_key(&private)));
        config
    };
    let mut cred_c_inst = Instance::new(cred_c_config);
    cred_c_inst.run().await.unwrap();

    let cred_a_peer_id = cred_a_inst.peer_id();
    let cred_b_peer_id = cred_b_inst.peer_id();
    let cred_c_peer_id = cred_c_inst.peer_id();

    // All credentials connect to admin
    cred_a_inst
        .get_conn_manager()
        .add_connector(TcpTunnelConnector::new(
            "tcp://10.1.1.1:11010".parse().unwrap(),
        ));
    cred_b_inst
        .get_conn_manager()
        .add_connector(TcpTunnelConnector::new(
            "tcp://10.1.1.1:11010".parse().unwrap(),
        ));
    cred_c_inst
        .get_conn_manager()
        .add_connector(TcpTunnelConnector::new(
            "tcp://10.1.1.1:11010".parse().unwrap(),
        ));

    // A and B also connect to C (simulating P2P discovery and connection)
    // C is on ns_c3 with IP 10.1.1.4, listener on port 11020
    cred_a_inst
        .get_conn_manager()
        .add_connector(TcpTunnelConnector::new(
            "tcp://10.1.1.4:11020".parse().unwrap(),
        ));
    cred_b_inst
        .get_conn_manager()
        .add_connector(TcpTunnelConnector::new(
            "tcp://10.1.1.4:11020".parse().unwrap(),
        ));
    // print all peer ids
    println!("Admin peer id: {:?}", admin_peer_id);
    println!("Cred A peer id: {:?}", cred_a_peer_id);
    println!("Cred B peer id: {:?}", cred_b_peer_id);
    println!("Cred C peer id: {:?}", cred_c_peer_id);

    // Wait for all nodes to appear in admin's route table
    wait_for_condition(
        || async {
            let routes = admin_inst.get_peer_manager().list_routes().await;
            let has_a = routes.iter().any(|r| r.peer_id == cred_a_peer_id);
            let has_b = routes.iter().any(|r| r.peer_id == cred_b_peer_id);
            let has_c = routes.iter().any(|r| r.peer_id == cred_c_peer_id);
            println!("Admin routes: a={}, b={}, c={}", has_a, has_b, has_c);
            has_a && has_b && has_c
        },
        Duration::from_secs(30),
    )
    .await;

    // Wait for P2P connections to establish
    wait_for_condition(
        || async {
            let peers_a = cred_a_inst.get_peer_manager().get_peer_map().list_peers();
            let peers_b = cred_b_inst.get_peer_manager().get_peer_map().list_peers();
            let peers_c = cred_c_inst.get_peer_manager().get_peer_map().list_peers();

            let a_connected_c = peers_a.contains(&cred_c_peer_id);
            let b_connected_c = peers_b.contains(&cred_c_peer_id);
            let c_connected_a = peers_c.contains(&cred_a_peer_id);
            let c_connected_b = peers_c.contains(&cred_b_peer_id);

            println!(
                "P2P: A->C={}, B->C={}, C->A={}, C->B={}, allow_relay={}",
                a_connected_c, b_connected_c, c_connected_a, c_connected_b, allow_relay
            );

            if allow_relay {
                a_connected_c && b_connected_c && c_connected_a && c_connected_b
            } else {
                a_connected_c && b_connected_c
            }
        },
        Duration::from_secs(30),
    )
    .await;

    // Wait for routes to propagate
    wait_for_condition(
        || async {
            let routes_a = cred_a_inst.get_peer_manager().list_routes().await;
            let a_sees_b = routes_a.iter().any(|r| r.peer_id == cred_b_peer_id);
            let cost_a_to_b = routes_a
                .iter()
                .find(|r| r.peer_id == cred_b_peer_id)
                .map(|r| r.cost);

            println!("Routes: a_sees_b={} (cost={:?})", a_sees_b, cost_a_to_b);
            a_sees_b
        },
        Duration::from_secs(15),
    )
    .await;

    wait_for_condition(
        || async {
            let next_hop_a_to_b = cred_a_inst
                .get_peer_manager()
                .get_route()
                .get_next_hop_with_policy(cred_b_peer_id, NextHopPolicy::LeastCost)
                .await;
            println!(
                "Next hop convergence A->B={:?} (admin={}, c={}), allow_relay={}",
                next_hop_a_to_b, admin_peer_id, cred_c_peer_id, allow_relay
            );
            if allow_relay {
                next_hop_a_to_b == Some(cred_c_peer_id)
            } else {
                next_hop_a_to_b == Some(admin_peer_id)
            }
        },
        Duration::from_secs(20),
    )
    .await;

    // wait 5s, make sure the routes are stable
    tokio::time::sleep(Duration::from_secs(5)).await;

    // Verify next hop from A to B based on allow_relay flag
    let next_hop_a_to_b = cred_a_inst
        .get_peer_manager()
        .get_route()
        .get_next_hop_with_policy(cred_b_peer_id, NextHopPolicy::LeastCost)
        .await;

    println!(
        "Next hop A->B={:?} (admin={}, c={}), allow_relay={}",
        next_hop_a_to_b, admin_peer_id, cred_c_peer_id, allow_relay
    );

    // When C has allow_relay=false, route should go through Admin
    // When C has allow_relay=true, route may go through C or Admin depending on routing algorithm
    if !allow_relay {
        assert_eq!(
            next_hop_a_to_b,
            Some(admin_peer_id),
            "Route from A to B should go through admin when allow_relay=false"
        );
    } else {
        assert_eq!(
            next_hop_a_to_b,
            Some(cred_c_peer_id),
            "Route from A to B should go through C when allow_relay=true"
        );
    }

    // Cleanup
    drop_insts(vec![admin_inst, cred_a_inst, cred_b_inst, cred_c_inst]).await;
}

/// Test 2: Two credential nodes connect to same admin
/// Topology: Admin ← Credential_A, Admin ← Credential_B
/// Verifies that multiple credential nodes can connect to the same admin
#[tokio::test]
#[serial_test::serial]
async fn credential_two_credentials_communicate_tcp() {
    prepare_credential_network();

    // Create admin node
    let admin_config = create_admin_config("admin", Some("ns_adm"), "10.144.144.1", "fd00::1/64");
    let mut admin_inst = Instance::new(admin_config);
    admin_inst.run().await.unwrap();

    // Create credential1 on ns_c1
    let cred1_config = create_credential_config(
        &admin_inst,
        "cred1",
        Some("ns_c1"),
        "10.144.144.2",
        "fd00::2/64",
    )
    .await;
    let mut cred1_inst = Instance::new(cred1_config);
    cred1_inst.run().await.unwrap();

    // Create credential2 on ns_c2
    let cred2_config = create_credential_config(
        &admin_inst,
        "cred2",
        Some("ns_c2"),
        "10.144.144.3",
        "fd00::3/64",
    )
    .await;
    let mut cred2_inst = Instance::new(cred2_config);
    cred2_inst.run().await.unwrap();

    // Both credentials connect to admin
    cred1_inst
        .get_conn_manager()
        .add_connector(TcpTunnelConnector::new(
            "tcp://10.1.1.1:11010".parse().unwrap(),
        ));
    cred2_inst
        .get_conn_manager()
        .add_connector(TcpTunnelConnector::new(
            "tcp://10.1.1.1:11010".parse().unwrap(),
        ));

    let cred1_peer_id = cred1_inst.peer_id();
    let cred2_peer_id = cred2_inst.peer_id();

    // Wait for both credentials to appear in admin's route table
    wait_for_condition(
        || async {
            let routes = admin_inst.get_peer_manager().list_routes().await;
            routes.iter().any(|r| r.peer_id == cred1_peer_id)
                && routes.iter().any(|r| r.peer_id == cred2_peer_id)
        },
        Duration::from_secs(10),
    )
    .await;

    // Verify admin can ping both credentials
    wait_for_condition(
        || async { ping_test("ns_adm", "10.144.144.2", None).await },
        Duration::from_secs(10),
    )
    .await;

    wait_for_condition(
        || async { ping_test("ns_adm", "10.144.144.3", None).await },
        Duration::from_secs(10),
    )
    .await;

    drop_insts(vec![admin_inst, cred1_inst, cred2_inst]).await;
}

/// Test 3: Credential revocation removes credential from route table
/// Topology: Admin ← Credential
/// Verifies that when credential is revoked, it's removed from admin's route table
#[tokio::test]
#[serial_test::serial]
async fn credential_revocation_propagates() {
    prepare_credential_network();

    // Create admin on ns_adm (10.1.1.1)
    let admin_config = create_admin_config("admin", Some("ns_adm"), "10.144.144.1", "fd00::1/64");
    let mut admin_inst = Instance::new(admin_config);
    admin_inst.run().await.unwrap();

    // Generate credential on admin
    let (cred_id, cred_secret) = admin_inst
        .get_global_ctx()
        .get_credential_manager()
        .generate_credential(vec![], false, vec![], Duration::from_secs(3600));

    // Create credential node
    let cred_config = {
        use base64::Engine as _;
        let privkey_bytes: [u8; 32] = base64::prelude::BASE64_STANDARD
            .decode(&cred_secret)
            .unwrap()
            .try_into()
            .unwrap();
        let private = x25519_dalek::StaticSecret::from(privkey_bytes);

        let config = TomlConfigLoader::default();
        config.set_inst_name("cred".to_string());
        config.set_netns(Some("ns_c1".to_string()));
        config.set_ipv4(Some("10.144.144.2".parse().unwrap()));
        config.set_ipv6(Some("fd00::2/64".parse().unwrap()));
        config.set_listeners(vec![]);
        config.set_network_identity(NetworkIdentity::new_credential(
            admin_inst
                .get_global_ctx()
                .get_network_identity()
                .network_name
                .clone(),
        ));
        config.set_secure_mode(Some(generate_secure_mode_config_with_key(&private)));
        config
    };

    let mut cred_inst = Instance::new(cred_config);
    cred_inst.run().await.unwrap();

    // Credential connects to admin
    cred_inst
        .get_conn_manager()
        .add_connector(TcpTunnelConnector::new(
            "tcp://10.1.1.1:11010".parse().unwrap(),
        ));

    let cred_peer_id = cred_inst.peer_id();

    // Wait for credential to appear in admin's route table
    wait_for_condition(
        || async {
            admin_inst
                .get_peer_manager()
                .list_routes()
                .await
                .iter()
                .any(|r| r.peer_id == cred_peer_id)
        },
        Duration::from_secs(10),
    )
    .await;

    // Verify connectivity before revocation
    wait_for_condition(
        || async { ping_test("ns_adm", "10.144.144.2", None).await },
        Duration::from_secs(10),
    )
    .await;

    // Revoke the credential
    assert!(
        admin_inst
            .get_global_ctx()
            .get_credential_manager()
            .revoke_credential(&cred_id),
        "Credential should be revoked successfully"
    );

    // Trigger OSPF sync
    admin_inst
        .get_global_ctx()
        .issue_event(GlobalCtxEvent::CredentialChanged);

    // Wait for credential to disappear from admin's route table
    wait_for_condition(
        || async {
            !admin_inst
                .get_peer_manager()
                .list_routes()
                .await
                .iter()
                .any(|r| r.peer_id == cred_peer_id)
        },
        Duration::from_secs(15),
    )
    .await;

    wait_for_condition(
        || async { !ping_test("ns_adm", "10.144.144.2", None).await },
        Duration::from_secs(10),
    )
    .await;

    wait_for_condition(
        || async { !ping_test("ns_c1", "10.144.144.1", None).await },
        Duration::from_secs(10),
    )
    .await;

    drop_insts(vec![admin_inst, cred_inst]).await;
}

/// Test 4: Unknown credential (not in trusted list) is rejected
/// Topology: Admin
/// Verifies that credential nodes with unknown/random keys cannot connect
#[tokio::test]
#[serial_test::serial]
async fn credential_unknown_rejected() {
    prepare_credential_network();

    // Create admin node
    let admin_config = create_admin_config("admin", Some("ns_adm"), "10.144.144.1", "fd00::1/64");
    let mut admin_inst = Instance::new(admin_config);
    admin_inst.run().await.unwrap();

    // Create credential node with random key (not generated by admin)
    let random_private = x25519_dalek::StaticSecret::random_from_rng(rand::rngs::OsRng);
    let cred_config = {
        let config = TomlConfigLoader::default();
        config.set_inst_name("cred".to_string());
        config.set_netns(Some("ns_c1".to_string()));
        config.set_ipv4(Some("10.144.144.2".parse().unwrap()));
        config.set_ipv6(Some("fd00::2/64".parse().unwrap()));
        config.set_listeners(vec![]);
        config.set_network_identity(NetworkIdentity::new_credential(
            admin_inst
                .get_global_ctx()
                .get_network_identity()
                .network_name
                .clone(),
        ));
        config.set_secure_mode(Some(generate_secure_mode_config_with_key(&random_private)));
        config
    };

    let mut cred_inst = Instance::new(cred_config);
    cred_inst.run().await.unwrap();

    // Attempt to connect to admin
    cred_inst
        .get_conn_manager()
        .add_connector(TcpTunnelConnector::new(
            "tcp://10.1.1.1:11010".parse().unwrap(),
        ));

    let cred_peer_id = cred_inst.peer_id();

    // Wait a bit for connection attempt
    tokio::time::sleep(Duration::from_secs(5)).await;

    // Verify credential does NOT appear in admin's route table
    let routes = admin_inst.get_peer_manager().list_routes().await;
    assert!(
        !routes.iter().any(|r| r.peer_id == cred_peer_id),
        "Unknown credential node should NOT appear in admin's route table"
    );

    // Verify no connectivity
    let ping_result = ping_test("ns_adm", "10.144.144.2", None).await;
    assert!(
        !ping_result,
        "Should NOT be able to ping unknown credential node"
    );

    drop_insts(vec![admin_inst, cred_inst]).await;
}

#[rstest::rstest]
#[tokio::test]
#[serial_test::serial]
async fn credential_admin_shared_admin_credential_connectivity(
    #[values(true, false)] connect_to_admin: bool,
) {
    prepare_credential_network();

    // 10.1.1.1
    let admin_a_config =
        create_admin_config("admin_a", Some("ns_adm"), "10.144.144.1", "fd00::1/64");
    let mut admin_a_inst = Instance::new(admin_a_config);
    admin_a_inst.run().await.unwrap();

    // 10.1.1.2
    let shared_b_config =
        create_shared_config("shared_b", Some("ns_c1"), "10.144.144.2", "fd00::2/64");
    let mut shared_b_inst = Instance::new(shared_b_config);
    shared_b_inst.run().await.unwrap();

    // 10.1.1.4
    let admin_c_config =
        create_admin_config("admin_c", Some("ns_c3"), "10.144.144.4", "fd00::4/64");
    let mut admin_c_inst = Instance::new(admin_c_config);
    admin_c_inst.run().await.unwrap();

    admin_a_inst
        .get_conn_manager()
        .add_connector(TcpTunnelConnector::new(
            "tcp://10.1.1.2:11010".parse().unwrap(),
        ));
    admin_c_inst
        .get_conn_manager()
        .add_connector(TcpTunnelConnector::new(
            "tcp://10.1.1.2:11010".parse().unwrap(),
        ));

    // print all peer ids
    println!("admin_a_peer_id: {:?}", admin_a_inst.peer_id());
    println!("shared_b_peer_id: {:?}", shared_b_inst.peer_id());
    println!("admin_c_peer_id: {:?}", admin_c_inst.peer_id());

    let admin_c_peer_id = admin_c_inst.peer_id();
    wait_for_condition(
        || async {
            let a_routes = admin_a_inst.get_peer_manager().list_routes().await;
            let c_routes = admin_c_inst.get_peer_manager().list_routes().await;
            println!(
                "bootstrap routes: a={:?} c={:?}",
                a_routes.iter().map(|r| r.peer_id).collect::<Vec<_>>(),
                c_routes.iter().map(|r| r.peer_id).collect::<Vec<_>>()
            );
            a_routes.iter().any(|r| r.peer_id == admin_c_peer_id)
                || c_routes.iter().any(|r| r.peer_id == admin_a_inst.peer_id())
        },
        Duration::from_secs(3),
    )
    .await;

    let cred_d_config = create_credential_config(
        &admin_a_inst,
        "cred_d",
        Some("ns_c2"),
        "10.144.144.5",
        "fd00::5/64",
    )
    .await;
    admin_a_inst
        .get_global_ctx()
        .issue_event(GlobalCtxEvent::CredentialChanged);

    let mut cred_d_inst = Instance::new(cred_d_config);
    cred_d_inst.run().await.unwrap();
    let cred_d_peer_id = cred_d_inst.peer_id();

    cred_d_inst
        .get_conn_manager()
        .add_connector(TcpTunnelConnector::new(if !connect_to_admin {
            // connect to shared node
            "tcp://10.1.1.2:11010".parse().unwrap()
        } else {
            // connect to admin node
            "tcp://10.1.1.4:11010".parse().unwrap()
        }));
    // print all peer ids
    println!("cred_d_peer_id: {:?}", cred_d_peer_id);

    wait_for_condition(
        || async {
            admin_c_inst
                .get_peer_manager()
                .list_routes()
                .await
                .iter()
                .any(|r| r.peer_id == cred_d_peer_id)
        },
        Duration::from_secs(60),
    )
    .await;

    wait_for_condition(
        || async { ping_test("ns_c3", "10.144.144.5", None).await },
        Duration::from_secs(15),
    )
    .await;

    wait_for_condition(
        || async { ping_test("ns_adm", "10.144.144.5", None).await },
        Duration::from_secs(15),
    )
    .await;

    wait_for_condition(
        || async { ping_test("ns_c2", "10.144.144.4", None).await },
        Duration::from_secs(15),
    )
    .await;

    drop_insts(vec![admin_a_inst, shared_b_inst, admin_c_inst, cred_d_inst]).await;
}
