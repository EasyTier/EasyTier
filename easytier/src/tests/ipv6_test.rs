use easytier_core::config::{InstanceConfig, InstanceConfigRaw};

use crate::common::global_ctx::tests::get_mock_global_ctx_with_config;

#[tokio::test]
async fn test_ipv6_config_support() {
    let mut raw = InstanceConfigRaw::default();

    // Test IPv6 configuration setting and getting
    let ipv6_cidr = "fd00::1/64".parse().unwrap();
    raw.ipv6 = Some(ipv6_cidr);

    assert_eq!(raw.ipv6, Some(ipv6_cidr));
}

#[tokio::test]
async fn test_global_ctx_ipv6() {
    let mut raw = InstanceConfigRaw::default();
    let ipv6_cidr = "fd00::1/64".parse().unwrap();
    raw.ipv6 = Some(ipv6_cidr);
    let config = InstanceConfig::try_from(raw).unwrap();
    let global_ctx = get_mock_global_ctx_with_config(config);

    assert_eq!(global_ctx.get_ipv6(), Some(ipv6_cidr));
}

#[tokio::test]
async fn native_peer_config_normalizes_ipv6_route() {
    let mut raw = InstanceConfigRaw::default();
    let ipv6_cidr = "fd00::1/64".parse().unwrap();
    raw.ipv6 = Some(ipv6_cidr);
    let config = InstanceConfig::try_from(raw).unwrap();
    let global_ctx = get_mock_global_ctx_with_config(config);

    let config = crate::instance::config::test_instance_config(&global_ctx);
    let ipv6 = config.parsed().ipv6.unwrap();

    assert_eq!(ipv6, ipv6_cidr);
}
