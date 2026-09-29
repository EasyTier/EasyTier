//! Portable conversion between the shared TOML model and management schema.


pub use super::api_input::network_config_from_raw;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{
        InstanceConfigRaw,
        api_input::NetworkConfigExt,
        toml::ManagedCredentialConfig,
    };
    use easytier_proto::api::manage;

    #[test]
    fn exporting_and_importing_secure_default_network_preserves_identity() {
        for input in [
            "[secure_mode]\nenabled = true",
            "[network_identity]\nnetwork_name = 'default'\n[secure_mode]\nenabled = true",
        ] {
            let config = crate::config::parse_instance_config("test", input).unwrap();
            let secret = config.parsed().network_identity.network_secret.clone();
            let exported = network_config_from_raw(config.raw());
            assert_eq!(exported.network_secret, secret);
            let imported = exported.gen_config().unwrap();
            assert_eq!(
                imported.parsed().network_identity.network_secret,
                secret
            );
            let restored = crate::config::parse_instance_config(
                "restored",
                &crate::config::serialize_raw_to_toml(imported.raw()).unwrap(),
            )
            .unwrap();
            assert_eq!(restored.parsed().network_identity.network_secret, secret);
        }
    }

    #[test]
    fn includes_managed_credentials() {
        let mut raw = InstanceConfigRaw::default();
        raw.set_managed_credentials(vec![ManagedCredentialConfig {
            credential_id: "managed-a".to_owned(),
            credential_secret: "credential-secret".to_owned(),
            groups: vec!["ops".to_owned()],
            allow_relay: true,
            allowed_proxy_cidrs: vec!["10.0.0.0/24".to_owned()],
            expiry_unix: 2_000_000_000,
            reusable: false,
        }]);

        let projected = network_config_from_raw(&raw);

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
        let initial_instance_config = crate::config::parse_instance_config("test", input).unwrap();
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
        let reloaded = crate::config::parse_instance_config("reloaded", &serialized).unwrap();
        assert_eq!(reloaded.parsed().hostname, "node-b");
        assert_eq!(reloaded.raw().proxy_network.as_ref().unwrap().len(), 1);

        let exported = network_config_from_raw(&reloaded.raw());
        assert_eq!(exported.proxy_cidrs.len(), 1);
        assert_eq!(exported.proxy_cidrs[0], "10.20.0.0/16");
    }

    #[test]
    fn secure_mode_default_admin_identity_preserved_across_raw_edit_and_reload() {
        let input = "[secure_mode]\nenabled = true\n";
        let initial_instance_config = crate::config::parse_instance_config("test", input).unwrap();
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
        let reloaded = crate::config::parse_instance_config("reloaded", &serialized).unwrap();
        assert_eq!(reloaded.parsed().hostname, "admin-node");
        assert_eq!(
            reloaded.parsed().network_identity.network_secret.as_deref(),
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
        let initial = crate::config::parse_instance_config("test", input).unwrap();
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
