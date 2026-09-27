use crate::{
    common::config::{ConfigLoader, TomlConfigLoader},
    common::global_ctx::tests::get_mock_global_ctx,
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
async fn native_peer_config_normalizes_ipv6_route() {
    let global_ctx = get_mock_global_ctx();

    // Set IPv6 address in global context
    let ipv6_cidr = "fd00::1/64".parse().unwrap();
    global_ctx.set_ipv6(Some(ipv6_cidr));

    let config = crate::instance::config::test_instance_config(&global_ctx);
    let ipv6 = config.parsed().ipv6.unwrap();

    assert_eq!(ipv6, ipv6_cidr);
}
