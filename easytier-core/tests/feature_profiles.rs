#![cfg(all(
    feature = "test-utils",
    feature = "proxy-cidr-monitor",
    not(feature = "wrapped-transport")
))]

use easytier_core::{config::toml::TomlConfig, instance::CoreInstanceConfig};

#[test]
fn manual_routes_require_cidr_monitor_not_wrapped_transport() {
    let toml = TomlConfig::new_from_str(
        r#"
        instance_name = "manual-routes-cidr-monitor"
        routes = ["192.0.2.0/24"]
        "#,
    )
    .unwrap();
    let config = CoreInstanceConfig::from_toml(&toml).unwrap();

    config.validate_build_capabilities_for_test().unwrap();
}
