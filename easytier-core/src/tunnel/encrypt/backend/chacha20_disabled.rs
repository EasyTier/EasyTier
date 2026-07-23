use std::sync::Arc;

use super::Encryptor;

pub(super) const AVAILABLE: bool = false;

pub(super) fn new(_key: [u8; 32]) -> Arc<dyn Encryptor> {
    super::unavailable_encryptor("chacha20")
}
