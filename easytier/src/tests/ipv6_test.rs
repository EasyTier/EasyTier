use std::net::Ipv6Addr;

use crate::{
    common::config::{ConfigLoader, TomlConfigLoader},
    common::global_ctx::tests::get_mock_global_ctx,
    peers::peer_manager::RouteAlgoType,
    proto::peer_rpc::RoutePeerInfo,
};

#[tokio::test]
async fn test_ipv6_config_support() {
    let config = TomlConfigLoader::default();

    // Test IPv6 configuration setting and getting
    let ipv6_cidr = "fd00::1/64".parse().unwrap();
    config.set_ipv6(Some(ipv6_cidr));

    assert_eq!(config.get_ipv6(), Some(ipv6_cidr));
}

#[tokio::test]
async fn test_global_ctx_ipv6() {
    let global_ctx = get_mock_global_ctx();

    // Test setting and getting IPv6 from global context
    let ipv6_cidr = "fd00::1/64".parse().unwrap();
    global_ctx.set_ipv6(Some(ipv6_cidr));

    assert_eq!(global_ctx.get_ipv6(), Some(ipv6_cidr));
}

#[tokio::test]
async fn test_route_peer_info_ipv6() {
    let global_ctx = get_mock_global_ctx();

    // Set IPv6 address in global context
    let ipv6_cidr = "fd00::1/64".parse().unwrap();
    global_ctx.set_ipv6(Some(ipv6_cidr));

    // Create RoutePeerInfo with IPv6 support
    let peer_info = RoutePeerInfo::new();
    let updated_info = peer_info.update_self(123, 456, &global_ctx);

    // Verify IPv6 address is included
    assert!(updated_info.ipv6_addr.is_some());
    let ipv6_addr: Ipv6Addr = updated_info.ipv6_addr.unwrap().address.unwrap().into();
    assert_eq!(ipv6_addr, ipv6_cidr.address());
}

#[tokio::test]
async fn test_peer_manager_ipv6() {
    let global_ctx = get_mock_global_ctx();
    let (packet_sender, _packet_receiver) = tokio::sync::mpsc::channel(100);
    let peer_mgr = crate::peers::peer_manager::PeerManager::new(
        RouteAlgoType::Ospf,
        global_ctx.clone(),
        packet_sender,
    );

    // Test IPv6 address lookup for unknown address
    let ipv6_addr = Ipv6Addr::new(0xfd00, 0, 0, 0, 0, 0, 0, 2);
    let (peers, _is_self) = peer_mgr.get_msg_dst_peer_ipv6(&ipv6_addr).await;

    // Should return empty peers list for unknown IPv6
    assert!(peers.is_empty());
}
