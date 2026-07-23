use std::sync::Arc;

use super::Encryptor;

pub(super) const AVAILABLE: bool = false;

pub(super) fn new_128(_key: [u8; 16]) -> Arc<dyn Encryptor> {
    super::unavailable_encryptor("aes-gcm")
}

pub(super) fn new_256(_key: [u8; 32]) -> Arc<dyn Encryptor> {
    super::unavailable_encryptor("aes-256-gcm")
}
