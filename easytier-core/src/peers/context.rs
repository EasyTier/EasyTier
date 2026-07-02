use std::{
    collections::hash_map::DefaultHasher,
    hash::{Hash, Hasher},
    sync::Arc,
};

use async_trait::async_trait;
use easytier_proto::common::{FlagsInConfig, SecureModeConfig, TunnelInfo};
use hmac::{Hmac, Mac};
use sha2::Sha256;

use crate::config::PeerId;

pub type NetworkSecretDigest = [u8; 32];
pub const SECRET_PROOF_PREFIX: &[u8] = b"easytier secret proof";

#[derive(Debug, Clone)]
pub struct NetworkIdentity {
    pub network_name: String,
    pub network_secret: Option<String>,
    pub network_secret_digest: Option<NetworkSecretDigest>,
}

impl NetworkIdentity {
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
        Self {
            network_name: "default".to_string(),
            network_secret: None,
            network_secret_digest: Some([0u8; 32]),
        }
    }
}

#[async_trait]
pub trait ByteLimiter: Send + Sync {
    async fn consume(&self, bytes: u64);
}

#[async_trait]
impl ByteLimiter for () {
    async fn consume(&self, _bytes: u64) {}
}

pub type ArcByteLimiter = Arc<dyn ByteLimiter>;

#[derive(Debug, Clone)]
pub enum PeerEvent {
    PeerAdded(PeerId),
    PeerRemoved(PeerId),
    PeerConnAdded(easytier_proto::core_peer::peer::PeerConnInfo),
    PeerConnRemoved(easytier_proto::core_peer::peer::PeerConnInfo),
}

pub trait PeerContext: Send + Sync {
    fn network_identity(&self) -> NetworkIdentity;

    fn network_name(&self) -> String {
        self.network_identity().network_name
    }

    fn flags(&self) -> FlagsInConfig {
        FlagsInConfig::default()
    }

    fn secure_mode(&self) -> Option<SecureModeConfig> {
        None
    }

    fn pinned_remote_static_pubkey(&self, _tunnel_info: Option<&TunnelInfo>) -> Option<String> {
        None
    }

    fn secret_proof(&self, _challenge: &[u8]) -> Option<Hmac<Sha256>> {
        None
    }

    fn secret_digest(&self, network_identity: &NetworkIdentity) -> Vec<u8> {
        network_identity
            .secret_digest()
            .unwrap_or_default()
            .to_vec()
    }

    fn is_pubkey_trusted(&self, _pubkey: &[u8], _network_name: &str) -> bool {
        false
    }

    fn record_control_tx(&self, _network_name: &str, _bytes: u64) {}

    fn record_control_rx(&self, _network_name: &str, _bytes: u64) {}

    fn recv_limiter(
        &self,
        _network_name: &str,
        _is_foreign_network: bool,
    ) -> Option<ArcByteLimiter> {
        None
    }

    fn issue_event(&self, _event: PeerEvent) {}
}

pub type ArcPeerContext = Arc<dyn PeerContext>;

#[derive(Debug, Clone)]
pub struct NoopPeerContext {
    network_identity: NetworkIdentity,
    flags: FlagsInConfig,
    secure_mode: Option<SecureModeConfig>,
}

impl NoopPeerContext {
    pub fn new(network_identity: NetworkIdentity) -> Self {
        Self {
            network_identity,
            flags: FlagsInConfig::default(),
            secure_mode: None,
        }
    }

    pub fn with_flags(mut self, flags: FlagsInConfig) -> Self {
        self.flags = flags;
        self
    }

    pub fn with_secure_mode(mut self, secure_mode: Option<SecureModeConfig>) -> Self {
        self.secure_mode = secure_mode;
        self
    }
}

impl Default for NoopPeerContext {
    fn default() -> Self {
        Self::new(NetworkIdentity::default())
    }
}

pub fn secret_proof_from_secret(secret: &str, challenge: &[u8]) -> Option<Hmac<Sha256>> {
    let mut mac = Hmac::<Sha256>::new_from_slice(secret.as_bytes()).ok()?;
    mac.update(SECRET_PROOF_PREFIX);
    mac.update(challenge);
    Some(mac)
}

impl PeerContext for NoopPeerContext {
    fn network_identity(&self) -> NetworkIdentity {
        self.network_identity.clone()
    }

    fn flags(&self) -> FlagsInConfig {
        self.flags.clone()
    }

    fn secure_mode(&self) -> Option<SecureModeConfig> {
        self.secure_mode.clone()
    }

    fn secret_proof(&self, challenge: &[u8]) -> Option<Hmac<Sha256>> {
        let secret = self.network_identity.network_secret.as_ref()?;
        secret_proof_from_secret(secret, challenge)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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
    fn noop_peer_context_uses_runtime_secret_proof_prefix() {
        let context = NoopPeerContext::new(NetworkIdentity {
            network_name: "net".to_string(),
            network_secret: Some("secret".to_string()),
            network_secret_digest: None,
        });

        let proof = context
            .secret_proof(b"challenge")
            .unwrap()
            .finalize()
            .into_bytes()
            .to_vec();
        let expected = secret_proof_from_secret("secret", b"challenge")
            .unwrap()
            .finalize()
            .into_bytes()
            .to_vec();

        assert_eq!(proof, expected);
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
}
