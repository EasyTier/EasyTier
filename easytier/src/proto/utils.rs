use prost::Message;
use sha2::{Digest, Sha256};

/// Generates a stable digest strictly within the lifecycle of the current process.
///
/// ⚠️ WARNING:
/// - This digest is ONLY guaranteed to be deterministic within a **single process and the exact same binary build**.
pub trait TransientDigest: Message {
    fn digest(&self) -> [u8; 32]
    where
        Self: Sized,
    {
        let buf = self.encode_to_vec();
        let mut hasher = Sha256::new();
        hasher.update(buf);
        hasher.finalize().into()
    }
}

impl<S: Message> TransientDigest for S {}
