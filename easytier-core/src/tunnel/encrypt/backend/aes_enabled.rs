use std::sync::Arc;

use super::{Encryptor, aes_gcm::AesGcmCipher};

pub(super) const AVAILABLE: bool = true;

pub(super) fn new_128(key: [u8; 16]) -> Arc<dyn Encryptor> {
    Arc::new(AesGcmCipher::new_128(key))
}

pub(super) fn new_256(key: [u8; 32]) -> Arc<dyn Encryptor> {
    Arc::new(AesGcmCipher::new_256(key))
}
