//! Static configuration schema plus the live runtime configuration store.

#[cfg(feature = "web-client")]
pub mod api;
#[cfg(any(feature = "web-client", feature = "browser-config"))]
pub mod api_input;
pub mod base;
#[cfg(all(
    feature = "browser-config",
    target_arch = "wasm32",
    target_os = "unknown"
))]
mod browser;
mod encryption;
pub mod gateway;
pub mod instance;
pub mod peers;
pub mod runtime;
pub mod toml;

pub use base::ConfigBase;
pub use encryption::EncryptionAlgorithm;
pub use instance::{InstanceConfig, InstanceConfigParsed, InstanceConfigRaw};
pub use runtime::InstanceConfigStore;
pub use toml::{ProxyNetworkConfig, serialize_raw_to_toml, serialize_raw_to_toml_redacted};

pub(crate) const DEFAULT_UDP_STUN_SERVERS: &[&str] = &[
    "txt:stun.easytier.cn",
    "stun.miwifi.com",
    "stun.chat.bilibili.com",
    "stun.hitv.com",
];
pub(crate) const DEFAULT_TCP_STUN_SERVERS: &[&str] = &[
    "stun.hot-chilli.net",
    "stun.fitauto.ru",
    "fwa.lifesizecloud.com",
    "global.turn.twilio.com",
    "turn.cloudflare.com",
    "stun.voip.blackberry.com",
    "stun.radiojar.com",
];
pub(crate) const DEFAULT_UDP_V6_STUN_SERVERS: &[&str] = &["txt:stun-v6.easytier.cn"];

pub(crate) fn default_stun_servers(servers: &[&str]) -> Vec<String> {
    servers.iter().map(ToString::to_string).collect()
}

use std::{
    collections::{BTreeSet, hash_map::DefaultHasher},
    hash::{Hash, Hasher},
};

use anyhow::Context as _;
use base64::{Engine as _, prelude::BASE64_STANDARD};
use easytier_proto::common as common_pb;
use serde::{Deserialize, Serialize};
use url::Url;

pub type PeerId = u32;

pub type NetworkSecretDigest = [u8; 32];

/// Host capabilities used by the portable mapped-listener validation rule.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct MappedListenerPolicy {
    implicit_port_schemes: BTreeSet<String>,
}

impl MappedListenerPolicy {
    pub fn new<I, S>(implicit_port_schemes: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        Self {
            implicit_port_schemes: implicit_port_schemes
                .into_iter()
                .map(Into::into)
                .map(|scheme: String| scheme.to_ascii_lowercase())
                .collect(),
        }
    }

    pub fn validate(&self, url: &Url) -> anyhow::Result<()> {
        if url.port().is_none() && !self.implicit_port_schemes.contains(url.scheme()) {
            anyhow::bail!("mapped listener port is missing: {}", url);
        }

        Ok(())
    }

    pub fn parse_urls(&self, mapped_listeners: &[String]) -> anyhow::Result<Vec<Url>> {
        mapped_listeners
            .iter()
            .map(|value| {
                let url: Url = value
                    .parse()
                    .with_context(|| format!("mapped listener is not a valid url: {}", value))?;
                self.validate(&url)?;
                Ok(url)
            })
            .collect()
    }
}

/// Completes and validates the portable secure-mode key configuration.
pub fn normalize_secure_mode_config(
    mut config: common_pb::SecureModeConfig,
) -> anyhow::Result<common_pb::SecureModeConfig> {
    if !config.enabled {
        return Ok(config);
    }

    let private_key = if config.local_private_key.is_none() {
        let private = x25519_dalek::StaticSecret::random_from_rng(rand::rngs::OsRng);
        config.local_private_key = Some(BASE64_STANDARD.encode(private.as_bytes()));
        private
    } else {
        config.private_key()?
    };
    let generated_public_key = x25519_dalek::PublicKey::from(&private_key);
    let generated_public_key = BASE64_STANDARD.encode(generated_public_key.as_bytes());

    match config.local_public_key.as_ref() {
        None => config.local_public_key = Some(generated_public_key),
        Some(configured_public_key) => {
            config.public_key()?;
            if configured_public_key != &generated_public_key {
                anyhow::bail!(
                    "local public key {} does not match generated public key {}",
                    configured_public_key,
                    generated_public_key
                );
            }
        }
    }

    Ok(config)
}

pub(crate) fn default_network_secret() -> Option<String> {
    Some(String::new())
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkIdentity {
    pub network_name: String,
    #[serde(default = "default_network_secret")]
    pub network_secret: Option<String>,
    #[serde(skip)]
    pub network_secret_digest: Option<NetworkSecretDigest>,
}

impl NetworkIdentity {
    pub fn new(network_name: String, network_secret: String) -> Self {
        Self {
            network_secret_digest: Some(network_secret_digest(&network_name, &network_secret)),
            network_name,
            network_secret: Some(network_secret),
        }
    }

    pub fn new_credential(network_name: String) -> Self {
        Self {
            network_name,
            network_secret: None,
            network_secret_digest: None,
        }
    }

    pub fn secret_digest(&self) -> Option<NetworkSecretDigest> {
        if self.network_secret_digest.is_some() {
            self.network_secret_digest
        } else if let Some(network_secret) = &self.network_secret {
            let mut network_secret_digest = [0u8; 32];
            generate_digest_from_str(
                &self.network_name,
                network_secret,
                &mut network_secret_digest,
            );
            Some(network_secret_digest)
        } else {
            None
        }
    }

    pub fn with_secret_digest(mut self) -> Self {
        self.network_secret_digest = self.secret_digest();
        self
    }
}

#[derive(Eq, PartialEq, Hash)]
struct NetworkIdentityWithOnlyDigest {
    network_name: String,
    network_secret_digest: Option<NetworkSecretDigest>,
}

fn generate_digest_from_str(str1: &str, str2: &str, digest: &mut [u8]) {
    let mut hasher = DefaultHasher::new();
    hasher.write(str1.as_bytes());
    hasher.write(str2.as_bytes());

    assert_eq!(digest.len() % 8, 0, "digest length must be multiple of 8");

    let shard_count = digest.len() / 8;
    for i in 0..shard_count {
        digest[i * 8..(i + 1) * 8].copy_from_slice(&hasher.finish().to_be_bytes());
        hasher.write(&digest[..(i + 1) * 8]);
    }
}

fn network_secret_digest(network_name: &str, network_secret: &str) -> NetworkSecretDigest {
    let mut digest = [0u8; 32];
    generate_digest_from_str(network_name, network_secret, &mut digest);
    digest
}

impl From<NetworkIdentity> for NetworkIdentityWithOnlyDigest {
    fn from(identity: NetworkIdentity) -> Self {
        Self {
            network_secret_digest: identity.secret_digest(),
            network_name: identity.network_name,
        }
    }
}

impl PartialEq for NetworkIdentity {
    fn eq(&self, other: &Self) -> bool {
        let self_with_digest = NetworkIdentityWithOnlyDigest::from(self.clone());
        let other_with_digest = NetworkIdentityWithOnlyDigest::from(other.clone());
        self_with_digest == other_with_digest
    }
}

impl Eq for NetworkIdentity {}

impl Hash for NetworkIdentity {
    fn hash<H: Hasher>(&self, state: &mut H) {
        let self_with_digest = NetworkIdentityWithOnlyDigest::from(self.clone());
        self_with_digest.hash(state);
    }
}

impl Default for NetworkIdentity {
    fn default() -> Self {
        Self::new("default".to_string(), "".to_string())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct P2pPolicyFlags {
    pub disable_udp_hole_punching: bool,
    pub disable_sym_hole_punching: bool,
    pub disable_upnp: bool,
    pub lazy_p2p: bool,
    pub disable_p2p: bool,
    pub need_p2p: bool,
}

#[cfg(test)]
mod tests {
    use super::*;
    use base64::prelude::BASE64_STANDARD;
    use x25519_dalek::{PublicKey, StaticSecret};

    fn digest(network_name: &str, network_secret: &str) -> NetworkSecretDigest {
        let mut digest = [0u8; 32];
        generate_digest_from_str(network_name, network_secret, &mut digest);
        digest
    }

    #[test]
    fn network_identity_matches_secret_to_digest_identity() {
        let local = NetworkIdentity {
            network_name: "net".to_string(),
            network_secret: Some("secret".to_string()),
            network_secret_digest: None,
        };
        let remote = NetworkIdentity {
            network_name: "net".to_string(),
            network_secret: None,
            network_secret_digest: Some(digest("net", "secret")),
        };

        assert_eq!(local, remote);
    }

    #[test]
    fn network_identity_rejects_different_digest() {
        let local = NetworkIdentity {
            network_name: "net".to_string(),
            network_secret: Some("secret".to_string()),
            network_secret_digest: None,
        };
        let remote = NetworkIdentity {
            network_name: "net".to_string(),
            network_secret: None,
            network_secret_digest: Some(digest("net", "other")),
        };

        assert_ne!(local, remote);
    }

    #[test]
    fn network_identity_equal_values_have_equal_hash() {
        let local = NetworkIdentity {
            network_name: "net".to_string(),
            network_secret: Some("secret".to_string()),
            network_secret_digest: None,
        };
        let remote = NetworkIdentity {
            network_name: "net".to_string(),
            network_secret: None,
            network_secret_digest: Some(digest("net", "secret")),
        };
        let mut local_hasher = DefaultHasher::new();
        let mut remote_hasher = DefaultHasher::new();

        local.hash(&mut local_hasher);
        remote.hash(&mut remote_hasher);

        assert_eq!(local_hasher.finish(), remote_hasher.finish());
    }

    #[test]
    fn network_identity_derives_digest_from_plaintext_secret() {
        let identity = NetworkIdentity {
            network_name: "net".to_string(),
            network_secret: Some("secret".to_string()),
            network_secret_digest: None,
        };

        assert_eq!(identity.secret_digest(), Some(digest("net", "secret")));
    }

    #[test]
    fn network_identity_default_matches_native_default_network() {
        assert_eq!(
            NetworkIdentity::default(),
            NetworkIdentity::new("default".to_string(), "".to_string())
        );
    }

    #[test]
    fn mapped_listener_policy_uses_explicit_host_capabilities() {
        let policy = MappedListenerPolicy::new(["tcp", "ws", "wss"]);
        let parsed = policy
            .parse_urls(&[
                "tcp://127.0.0.1".to_string(),
                "ws://example.com".to_string(),
                "wss://example.com/path".to_string(),
                "ring://peer-id:1000".to_string(),
            ])
            .unwrap();

        assert_eq!(parsed.len(), 4);
        assert_eq!(parsed[0].scheme(), "tcp");
        assert_eq!(parsed[1].scheme(), "ws");
        assert_eq!(parsed[2].scheme(), "wss");
        assert_eq!(parsed[3].port(), Some(1000));

        let error = policy
            .parse_urls(&["ring://peer-id".to_string()])
            .unwrap_err();
        assert!(
            error
                .to_string()
                .contains("mapped listener port is missing")
        );
    }

    #[test]
    fn secure_mode_normalization_generates_missing_key_pair() {
        let normalized = normalize_secure_mode_config(common_pb::SecureModeConfig {
            enabled: true,
            local_private_key: None,
            local_public_key: None,
        })
        .unwrap();

        let private_key = normalized.private_key().unwrap();
        let public_key = normalized.public_key().unwrap();
        assert_eq!(public_key, PublicKey::from(&private_key));
    }

    #[test]
    fn secure_mode_normalization_preserves_existing_key_configuration() {
        let private_key = StaticSecret::from([7; 32]);
        let public_key = PublicKey::from(&private_key);
        let config = common_pb::SecureModeConfig {
            enabled: true,
            local_private_key: Some(BASE64_STANDARD.encode(private_key.as_bytes())),
            local_public_key: Some(BASE64_STANDARD.encode(public_key.as_bytes())),
        };

        assert_eq!(
            normalize_secure_mode_config(config.clone()).unwrap(),
            config
        );
    }

    #[test]
    fn secure_mode_normalization_rejects_mismatched_public_key() {
        let private_key = StaticSecret::from([7; 32]);
        let other_public_key = PublicKey::from(&StaticSecret::from([9; 32]));
        let error = normalize_secure_mode_config(common_pb::SecureModeConfig {
            enabled: true,
            local_private_key: Some(BASE64_STANDARD.encode(private_key.as_bytes())),
            local_public_key: Some(BASE64_STANDARD.encode(other_public_key.as_bytes())),
        })
        .unwrap_err()
        .to_string();

        assert!(
            error.contains("does not match generated public key"),
            "{error}"
        );
    }

    #[test]
    fn disabled_secure_mode_does_not_validate_keys() {
        let config = common_pb::SecureModeConfig {
            enabled: false,
            local_private_key: Some("not-base64".to_string()),
            local_public_key: Some("not-base64".to_string()),
        };

        assert_eq!(
            normalize_secure_mode_config(config.clone()).unwrap(),
            config
        );
    }
}
