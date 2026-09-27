//! Portable conversion between the shared TOML model and management schema.

use easytier_proto::api::manage::NetworkConfig;

use super::toml::TomlConfig;

pub use super::api_input::network_config_from_raw;

pub fn network_config_from_toml(config: &TomlConfig) -> NetworkConfig {
    network_config_from_raw(&config.raw())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{
        api_input::NetworkConfigExt,
        toml::{ConfigLoader as _, ManagedCredentialConfig},
    };
    use easytier_proto::api::manage;

    #[test]
    fn exporting_and_importing_secure_default_network_preserves_identity() {
        for input in [
            "[secure_mode]\nenabled = true",
            "[network_identity]\nnetwork_name = 'default'\n[secure_mode]\nenabled = true",
        ] {
            let config = TomlConfig::new_from_str(input).unwrap();
            let secret = config.get_network_identity().network_secret;
            for exported in [
                network_config_from_toml(&config),
                NetworkConfig::new_from_config(&config).unwrap(),
            ] {
                assert_eq!(exported.network_secret, secret);
                let imported = exported.gen_config().unwrap();
                assert_eq!(
                    imported.snapshot().unwrap().network_identity.network_secret,
                    secret
                );
                let restored = TomlConfig::new_from_str(&imported.dump()).unwrap();
                assert_eq!(restored.get_network_identity().network_secret, secret);
            }
        }
    }

    #[test]
    fn includes_managed_credentials() {
        let config = TomlConfig::default();
        config.set_managed_credentials(vec![ManagedCredentialConfig {
            credential_id: "managed-a".to_owned(),
            credential_secret: "credential-secret".to_owned(),
            groups: vec!["ops".to_owned()],
            allow_relay: true,
            allowed_proxy_cidrs: vec!["10.0.0.0/24".to_owned()],
            expiry_unix: 2_000_000_000,
            reusable: false,
        }]);

        let projected = network_config_from_toml(&config);

        assert_eq!(
            projected.managed_credentials,
            vec![manage::ManagedCredentialConfig {
                credential_id: "managed-a".to_owned(),
                credential_secret: "credential-secret".to_owned(),
                groups: vec!["ops".to_owned()],
                allow_relay: true,
                allowed_proxy_cidrs: vec!["10.0.0.0/24".to_owned()],
                expiry_unix: 2_000_000_000,
                reusable: Some(false),
            }]
        );
    }

    #[test]
    fn host_ignored_config_preserved_across_serialize_and_reload() {
        let input = r#"
hostname = "node-a"
[[proxy_network]]
cidr = "10.20.0.0/16"
"#;
        let toml = TomlConfig::new_from_str(input).unwrap();
        let initial_instance_config = toml.snapshot().unwrap();
        let host = crate::instance::CoreInstanceHostConfig {
            ignore_unsupported_config: true,
            proxy_enabled: false,
            ..Default::default()
        };
        let prepared =
            crate::instance::prepare_instance_config(initial_instance_config, &host).unwrap();
        assert!(prepared.parsed().proxy_network.is_empty());
        assert_eq!(prepared.raw().proxy_network.as_ref().unwrap().len(), 1);

        let mut raw = prepared.raw().clone();
        raw.hostname = Some("node-b".to_owned());

        let serialized = crate::config::serialize_raw_to_toml(&raw).unwrap();
        let reloaded = TomlConfig::new_from_str(&serialized).unwrap();
        assert_eq!(reloaded.get_hostname(), "node-b");
        assert_eq!(reloaded.raw().proxy_network.as_ref().unwrap().len(), 1);

        let exported = network_config_from_raw(&reloaded.raw());
        assert_eq!(exported.proxy_cidrs.len(), 1);
        assert_eq!(exported.proxy_cidrs[0], "10.20.0.0/16");
    }

    #[test]
    fn secure_mode_default_admin_identity_preserved_across_raw_edit_and_reload() {
        let input = "[secure_mode]\nenabled = true\n";
        let toml = TomlConfig::new_from_str(input).unwrap();
        let initial_instance_config = toml.snapshot().unwrap();
        let host = crate::instance::CoreInstanceHostConfig::default();
        let prepared =
            crate::instance::prepare_instance_config(initial_instance_config, &host).unwrap();

        assert_eq!(
            prepared.parsed().network_identity.network_secret.as_deref(),
            Some("")
        );

        let mut raw = prepared.raw().clone();
        raw.hostname = Some("admin-node".to_owned());

        let serialized = crate::config::serialize_raw_to_toml(&raw).unwrap();
        let reloaded = TomlConfig::new_from_str(&serialized).unwrap();
        let reloaded_snapshot = reloaded.snapshot().unwrap();
        assert_eq!(reloaded.get_hostname(), "admin-node");
        assert_eq!(
            reloaded_snapshot.network_identity.network_secret.as_deref(),
            Some("")
        );

        let exported = network_config_from_raw(&reloaded.raw());
        assert_eq!(exported.network_name.as_deref(), Some("default"));
        assert_eq!(exported.network_secret.as_deref(), Some(""));
    }

    #[test]
    fn management_export_preserves_raw_configuration_intent() {
        let input = r#"
hostname = "worker"
[[proxy_network]]
cidr = "192.168.1.0/24"
"#;
        let toml = TomlConfig::new_from_str(input).unwrap();
        let initial = toml.snapshot().unwrap();
        let host = crate::instance::CoreInstanceHostConfig {
            ignore_unsupported_config: true,
            proxy_enabled: false,
            ..Default::default()
        };
        let prepared = crate::instance::prepare_instance_config(initial, &host).unwrap();

        assert!(prepared.parsed().proxy_network.is_empty());

        let exported = network_config_from_raw(prepared.raw());
        assert_eq!(exported.proxy_cidrs.len(), 1);
        assert_eq!(exported.proxy_cidrs[0], "192.168.1.0/24");
    }
}
