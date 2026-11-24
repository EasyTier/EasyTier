#![cfg(all(feature = "proxy-cidr-monitor", not(feature = "wrapped-transport")))]

use easytier_core::{config::toml::TomlConfig, instance::CoreInstanceConfig};

#[test]
fn manual_routes_require_cidr_monitor_not_wrapped_transport() {
    let toml = TomlConfig::new_from_str(
        r#"
        instance_name = "manual-routes-cidr-monitor"
        routes = ["192.0.2.0/24"]
        [flags]
        enable_encryption = false
        "#,
    )
    .unwrap();
    let config = CoreInstanceConfig::from_toml(&toml).unwrap();

    config.validate_build_capabilities().unwrap();
}

#[cfg(not(any(
    feature = "aes-gcm",
    feature = "openssl-crypto",
    feature = "ring-crypto",
    all(target_os = "wasi", feature = "wasi-crypto-offload"),
)))]
#[test]
fn unavailable_aes_is_rejected_before_startup() {
    let toml = TomlConfig::new_from_str(
        "[flags]\nenable_encryption = true\nencryption_algorithm = 'aes-gcm'",
    )
    .unwrap();
    let config = CoreInstanceConfig::from_toml(&toml).unwrap();
    assert_eq!(
        config
            .validate_build_capabilities()
            .unwrap_err()
            .to_string(),
        "encryption algorithm is unavailable in this build: aes-gcm"
    );
}
