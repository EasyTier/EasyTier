//! Test-only peer-context fakes shared by peer-domain unit tests
//! (`peers::tests`, `peers::route::peer_ospf_route::tests`, and
//! `context::tests`). Kept out of `context.rs` so the context unit tests and
//! their consumers share one definition.

use easytier_proto::common::{Flags, SecureModeConfig};
use hmac::Hmac;
use sha2::Sha256;

use crate::peers::context::{NetworkIdentity, PeerContext, secret_proof_from_secret};

#[derive(Debug, Clone)]
pub(crate) struct NoopPeerContext {
    network_identity: NetworkIdentity,
    flags: Flags,
    secure_mode: Option<SecureModeConfig>,
}

impl NoopPeerContext {
    pub(crate) fn new(network_identity: NetworkIdentity) -> Self {
        Self {
            network_identity,
            flags: Flags::default(),
            secure_mode: None,
        }
    }

    pub(crate) fn with_secure_mode(mut self, secure_mode: SecureModeConfig) -> Self {
        self.flags.encryption_algorithm = "aes-gcm".to_owned();
        self.secure_mode = Some(secure_mode);
        self
    }

    pub(crate) fn with_flags(mut self, flags: Flags) -> Self {
        self.flags = flags;
        self
    }
}

impl Default for NoopPeerContext {
    fn default() -> Self {
        Self::new(NetworkIdentity::default())
    }
}

impl PeerContext for NoopPeerContext {
    fn network_identity(&self) -> NetworkIdentity {
        self.network_identity.clone()
    }

    fn flags(&self) -> Flags {
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
