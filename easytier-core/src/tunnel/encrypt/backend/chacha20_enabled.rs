use std::sync::Arc;

use super::{Encryptor, chacha20::ChaCha20Cipher};

pub(super) const AVAILABLE: bool = true;

pub(super) fn new(key: [u8; 32]) -> Arc<dyn Encryptor> {
    Arc::new(ChaCha20Cipher::new(key))
}
