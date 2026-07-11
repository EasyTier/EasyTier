use std::{collections::hash_map::DefaultHasher, hash::Hasher};

use x25519_dalek::{PublicKey, StaticSecret};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum WgType {
    InternalUse,
    ExternalUse,
}

#[derive(Clone)]
pub struct WgConfig {
    my_secret_key: StaticSecret,
    my_public_key: PublicKey,
    peer_secret_key: StaticSecret,
    peer_public_key: PublicKey,
    wg_type: WgType,
}

impl WgConfig {
    pub fn new_from_network_identity(network_name: &str, network_secret: &str) -> Self {
        let mut secret = [0u8; 32];
        generate_digest_from_str(network_name, network_secret, &mut secret);
        Self::new_internal(secret, secret)
    }

    pub fn new_for_portal(server_key_seed: &str, client_key_seed: &str) -> Self {
        let server_cfg = Self::new_from_network_identity("server", server_key_seed);
        let client_cfg = Self::new_from_network_identity("client", client_key_seed);
        Self {
            my_secret_key: server_cfg.my_secret_key,
            my_public_key: server_cfg.my_public_key,
            peer_secret_key: client_cfg.my_secret_key,
            peer_public_key: client_cfg.my_public_key,
            wg_type: WgType::ExternalUse,
        }
    }

    pub fn new_internal(my_secret_key: [u8; 32], peer_secret_key: [u8; 32]) -> Self {
        let my_secret_key = StaticSecret::from(my_secret_key);
        let my_public_key = PublicKey::from(&my_secret_key);
        let peer_secret_key = StaticSecret::from(peer_secret_key);
        let peer_public_key = PublicKey::from(&peer_secret_key);
        Self {
            my_secret_key,
            my_public_key,
            peer_secret_key,
            peer_public_key,
            wg_type: WgType::InternalUse,
        }
    }

    pub fn my_secret_key(&self) -> &[u8] {
        self.my_secret_key.as_bytes()
    }

    pub fn peer_secret_key(&self) -> &[u8] {
        self.peer_secret_key.as_bytes()
    }

    pub fn my_public_key(&self) -> &[u8] {
        self.my_public_key.as_bytes()
    }

    pub fn peer_public_key(&self) -> &[u8] {
        self.peer_public_key.as_bytes()
    }

    pub fn is_internal(&self) -> bool {
        self.wg_type == WgType::InternalUse
    }
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn network_identity_produces_matching_internal_key_pairs() {
        let config = WgConfig::new_from_network_identity("network", "secret");

        assert!(config.is_internal());
        assert_eq!(config.my_secret_key(), config.peer_secret_key());
        assert_eq!(config.my_public_key(), config.peer_public_key());
        assert_eq!(
            PublicKey::from(&StaticSecret::from(
                <[u8; 32]>::try_from(config.my_secret_key()).unwrap()
            ))
            .as_bytes(),
            config.my_public_key()
        );
    }

    #[test]
    fn portal_uses_distinct_external_key_pairs() {
        let config = WgConfig::new_for_portal("server-seed", "client-seed");

        assert!(!config.is_internal());
        assert_ne!(config.my_secret_key(), config.peer_secret_key());
        assert_ne!(config.my_public_key(), config.peer_public_key());
    }
}
