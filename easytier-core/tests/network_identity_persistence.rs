#![cfg(feature = "config-write")]

use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64_STANDARD};
use easytier_core::{
    config::{
        normalize_secure_mode_config,
        toml::{ConfigLoader, ManagedCredentialConfig, NetworkIdentity, TomlConfig},
    },
    instance::CoreInstanceConfig,
};
use easytier_proto::common::SecureModeConfig;

fn secure_mode(enabled: bool) -> SecureModeConfig {
    normalize_secure_mode_config(SecureModeConfig {
        enabled,
        local_private_key: Some(BASE64_STANDARD.encode([7u8; 32])),
        ..Default::default()
    })
    .unwrap()
}

fn managed_credential() -> ManagedCredentialConfig {
    ManagedCredentialConfig {
        credential_id: "managed-member".to_owned(),
        credential_secret: BASE64_STANDARD.encode([8u8; 32]),
        groups: vec!["operators".to_owned()],
        allow_relay: true,
        allowed_proxy_cidrs: vec!["10.90.0.0/24".to_owned()],
        expiry_unix: 2_000_000_000,
        reusable: false,
    }
}

#[test]
fn shared_secret_identity_survives_toml_reload_with_or_without_secure_mode() {
    for enabled in [false, true] {
        for secret in ["", "network-password"] {
            let config = TomlConfig::default();
            let identity = NetworkIdentity::new("secure-network".to_owned(), secret.to_owned());
            config.set_network_identity(identity.clone());
            config.set_secure_mode(Some(secure_mode(enabled)));

            let dumped = config.dump();
            assert_eq!(
                dumped.contains("authentication = \"shared_secret\""),
                enabled && secret.is_empty()
            );
            let restored = TomlConfig::new_from_str(&dumped).unwrap();
            let restored_identity = restored.get_network_identity();
            assert_eq!(restored_identity.network_secret.as_deref(), Some(secret));
            assert_eq!(
                restored_identity.network_secret_digest,
                identity.network_secret_digest
            );
            assert_eq!(restored.get_secure_mode(), config.get_secure_mode());
            assert_eq!(restored.dump(), dumped);
        }
    }
}

#[test]
fn legacy_secure_credentials_keep_missing_and_empty_secret_semantics() {
    for secret in ["", "network_secret = \"\""] {
        let config = TomlConfig::new_from_str(&format!(
            "[network_identity]\nnetwork_name = \"credential-network\"\n{secret}\n\
             [secure_mode]\nenabled = true\n"
        ))
        .unwrap();
        let dumped = config.dump();
        assert!(!dumped.contains("network_secret"));
        assert!(!dumped.contains("authentication"));
        let restored = TomlConfig::new_from_str(&dumped).unwrap();
        assert_eq!(restored.get_network_identity().network_secret, None);
        assert_eq!(restored.get_network_identity().network_secret_digest, None);
        assert_eq!(restored.get_secure_mode(), config.get_secure_mode());
    }
}

#[test]
fn passwordless_secure_admin_retains_managed_grants_after_reload() {
    let config = TomlConfig::default();
    config.set_network_identity(NetworkIdentity::new(
        "secure-network".to_owned(),
        String::new(),
    ));
    config.set_secure_mode(Some(secure_mode(true)));
    config.set_managed_credentials(vec![managed_credential()]);

    let expected = CoreInstanceConfig::from_toml(&config).unwrap();
    let restored = TomlConfig::new_from_str(&config.dump()).unwrap();
    let actual = CoreInstanceConfig::from_toml(&restored).unwrap();
    assert_eq!(actual.managed_credentials, expected.managed_credentials);
    assert_eq!(
        actual.peer.snapshot.runtime.network_identity,
        expected.peer.snapshot.runtime.network_identity
    );
    assert_eq!(
        actual.peer.snapshot.runtime.secure_mode,
        expected.peer.snapshot.runtime.secure_mode
    );
}

#[test]
fn explicit_credential_identity_survives_reload_without_secure_mode() {
    let config = TomlConfig::default();
    config.set_network_identity(NetworkIdentity::new_credential(
        "credential-network".to_owned(),
    ));
    let dumped = config.dump();
    assert!(dumped.contains("authentication = \"credential\""));
    let restored = TomlConfig::new_from_str(&dumped).unwrap();
    assert_eq!(restored.get_network_identity().network_secret, None);
    assert_eq!(restored.get_network_identity().network_secret_digest, None);
}

#[cfg(any(feature = "web-client", feature = "browser-config"))]
mod api {
    use easytier_core::config::api_input::{NetworkConfig, NetworkConfigExt, NetworkingMethod};
    use easytier_proto::api::manage;

    use super::*;

    #[test]
    fn secure_admin_identity_and_grants_survive_api_and_toml_round_trips() {
        for secret in [
            None,
            Some(String::new()),
            Some("network-password".to_owned()),
        ] {
            let credential = managed_credential();
            let input = NetworkConfig {
                network_name: Some("secure-network".to_owned()),
                network_secret: secret.clone(),
                networking_method: Some(NetworkingMethod::Standalone as i32),
                secure_mode: Some(SecureModeConfig {
                    enabled: true,
                    ..Default::default()
                }),
                managed_credentials: vec![manage::ManagedCredentialConfig {
                    credential_id: credential.credential_id,
                    credential_secret: credential.credential_secret,
                    groups: credential.groups,
                    allow_relay: credential.allow_relay,
                    allowed_proxy_cidrs: credential.allowed_proxy_cidrs,
                    expiry_unix: credential.expiry_unix,
                    reusable: Some(credential.reusable),
                }],
                ..Default::default()
            };
            let config = input.gen_config().unwrap();
            let expected = CoreInstanceConfig::from_toml(&config).unwrap();
            let restored = TomlConfig::new_from_str(&config.dump()).unwrap();
            let actual = CoreInstanceConfig::from_toml(&restored).unwrap();
            assert_eq!(
                restored.get_network_identity().network_secret,
                Some(secret.unwrap_or_default())
            );
            assert_eq!(
                restored.get_network_identity().network_secret_digest,
                config.get_network_identity().network_secret_digest
            );
            assert_eq!(restored.get_secure_mode(), config.get_secure_mode());
            assert_eq!(actual.managed_credentials, expected.managed_credentials);

            let output = NetworkConfig::new_from_config(&restored).unwrap();
            assert_eq!(
                output.network_secret,
                restored.get_network_identity().network_secret
            );
            assert_eq!(output.managed_credentials, input.managed_credentials);
            assert_eq!(output.secure_mode, config.get_secure_mode());
        }
    }

    #[test]
    fn secure_credential_identity_retains_keypair_through_api_and_toml() {
        let input = NetworkConfig {
            network_name: Some("secure-network".to_owned()),
            network_secret: None,
            networking_method: Some(NetworkingMethod::Standalone as i32),
            secure_mode: Some(secure_mode(true)),
            ..Default::default()
        };
        let config = input.gen_config().unwrap();
        let restored = TomlConfig::new_from_str(&config.dump()).unwrap();
        assert_eq!(restored.get_network_identity().network_secret, None);
        assert_eq!(restored.get_network_identity().network_secret_digest, None);
        assert_eq!(restored.get_secure_mode(), input.secure_mode);
        assert!(restored.get_managed_credentials().is_empty());
        CoreInstanceConfig::from_toml(&restored).unwrap();

        let output = NetworkConfig::new_from_config(&restored).unwrap();
        assert_eq!(output.network_secret, None);
        assert_eq!(output.secure_mode, input.secure_mode);
        let regenerated = output.gen_config().unwrap();
        assert_eq!(regenerated.get_network_identity().network_secret, None);
        assert_eq!(regenerated.get_secure_mode(), input.secure_mode);
    }
}
