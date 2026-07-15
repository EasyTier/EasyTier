use std::net::Ipv6Addr;

use crate::{
    common::config::{ConfigLoader, TomlConfigLoader},
    common::global_ctx::tests::get_mock_global_ctx,
};
use easytier_core::peers::{
    peer_manager::RouteAlgoType, peer_ospf_route::new_updated_self_route_peer_info,
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
    let config =
        crate::instance::config::runtime_peer_manager_config(&global_ctx, RouteAlgoType::Ospf);
    let (_, peer_context) = crate::instance::config::build_core_peer_context(&global_ctx, &config);
    let updated_info = new_updated_self_route_peer_info(123, 456, peer_context.as_ref(), None);

    // Verify IPv6 address is included
    assert!(updated_info.ipv6_addr.is_some());
    let ipv6_addr: Ipv6Addr = updated_info.ipv6_addr.unwrap().address.unwrap().into();
    assert_eq!(ipv6_addr, ipv6_cidr.address());
}
