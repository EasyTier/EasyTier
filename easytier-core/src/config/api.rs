//! Portable conversion between the shared TOML model and management schema.

use easytier_proto::api::manage::NetworkConfig;

use super::{api_input::network_config_from_loader, toml::TomlConfig};

pub fn network_config_from_toml(config: &TomlConfig) -> NetworkConfig {
    network_config_from_loader(config)
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
}
