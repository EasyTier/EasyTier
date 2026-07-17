use crate::packet::ZCPacket;
use std::{collections::hash_map::DefaultHasher, hash::Hasher, sync::Arc};

#[cfg(feature = "aes-gcm")]
pub mod aes_gcm;
#[cfg(feature = "chacha20")]
pub mod chacha20;

pub mod xor;

#[derive(thiserror::Error, Debug)]
pub enum Error {
    #[error("packet is too short. len: {0}")]
    #[cfg(any(feature = "aes-gcm", feature = "chacha20"))]
    PacketTooShort(usize),
    #[error("decryption failed")]
    DecryptionFailed,
    #[error("encryption failed")]
    #[cfg(any(feature = "aes-gcm", feature = "chacha20"))]
    EncryptionFailed,
}

pub trait Encryptor: Send + Sync + 'static {
    fn decrypt(&self, zc_packet: &mut ZCPacket) -> Result<(), Error>;
    fn encrypt(&self, zc_packet: &mut ZCPacket) -> Result<(), Error>;
    fn encrypt_with_nonce(
        &self,
        zc_packet: &mut ZCPacket,
        _nonce: Option<&[u8]>,
    ) -> Result<(), Error> {
        self.encrypt(zc_packet)
    }
}

pub struct NullCipher;

pub fn derive_key_128(secret: &str) -> [u8; 16] {
    let mut key = [0u8; 16];
    let mut hasher = DefaultHasher::new();
    hasher.write(secret.as_bytes());
    key[0..8].copy_from_slice(&hasher.finish().to_be_bytes());
    hasher.write(&key[0..8]);
    key[8..16].copy_from_slice(&hasher.finish().to_be_bytes());
    hasher.write(&key);
    key
}

pub fn derive_key_256(secret: &str) -> [u8; 32] {
    let mut key = [0u8; 32];
    let mut hasher = DefaultHasher::new();
    hasher.write(secret.as_bytes());
    hasher.write(b"easytier-256bit-key");
    for i in 0..4 {
        let chunk_start = i * 8;
        let chunk_end = chunk_start + 8;
        hasher.write(&key[0..chunk_start]);
        hasher.write(&[i as u8]);
        key[chunk_start..chunk_end].copy_from_slice(&hasher.finish().to_be_bytes());
    }
    key
}

impl Encryptor for NullCipher {
    fn decrypt(&self, zc_packet: &mut ZCPacket) -> Result<(), Error> {
        let pm_header = zc_packet.peer_manager_header().unwrap();
        if pm_header.is_encrypted() {
            Err(Error::DecryptionFailed)
        } else {
            Ok(())
        }
    }

    fn encrypt(&self, _zc_packet: &mut ZCPacket) -> Result<(), Error> {
        Ok(())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum EncryptionAlgorithm {
    Xor,
    #[cfg(feature = "aes-gcm")]
    AesGcm,
    #[cfg(feature = "aes-gcm")]
    Aes256Gcm,
    #[cfg(feature = "chacha20")]
    ChaCha20,
}

impl Default for EncryptionAlgorithm {
    fn default() -> Self {
        #[cfg(feature = "aes-gcm")]
        {
            Self::AesGcm
        }
        #[cfg(not(feature = "aes-gcm"))]
        {
            Self::Xor
        }
    }
}

impl TryFrom<&str> for EncryptionAlgorithm {
    type Error = ();

    fn try_from(value: &str) -> Result<Self, Self::Error> {
        match value.to_ascii_lowercase().as_str() {
            "xor" => Ok(Self::Xor),
            #[cfg(feature = "aes-gcm")]
            "aes-gcm" => Ok(Self::AesGcm),
            #[cfg(feature = "aes-gcm")]
            "aes-256-gcm" => Ok(Self::Aes256Gcm),
            #[cfg(feature = "chacha20")]
            "chacha20" | "chacha20-poly1305" => Ok(Self::ChaCha20),
            _ => Err(()),
        }
    }
}

/// Create an encryptor based on the algorithm name
pub fn create_encryptor(
    algorithm: &str,
    key_128: [u8; 16],
    #[allow(unused_variables)] key_256: [u8; 32],
) -> Arc<dyn Encryptor> {
    let algorithm = EncryptionAlgorithm::try_from(algorithm).unwrap_or_default();

    match algorithm {
        EncryptionAlgorithm::Xor => Arc::new(xor::XorCipher::new(&key_128)),

        #[cfg(feature = "aes-gcm")]
        EncryptionAlgorithm::AesGcm => Arc::new(aes_gcm::AesGcmCipher::new_128(key_128)),

        #[cfg(feature = "aes-gcm")]
        EncryptionAlgorithm::Aes256Gcm => Arc::new(aes_gcm::AesGcmCipher::new_256(key_256)),

        #[cfg(feature = "chacha20")]
        EncryptionAlgorithm::ChaCha20 => Arc::new(chacha20::ChaCha20Cipher::new(key_256)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn network_secret_key_derivation_is_stable() {
        assert_eq!(
            derive_key_128("secret"),
            [
                86, 90, 25, 219, 78, 240, 193, 33, 168, 172, 88, 14, 218, 248, 78, 166,
            ]
        );
        assert_eq!(
            derive_key_256("secret"),
            [
                199, 205, 248, 94, 194, 101, 97, 138, 79, 69, 167, 248, 140, 5, 165, 163, 192, 139,
                166, 217, 166, 152, 28, 230, 146, 109, 150, 196, 66, 242, 231, 140,
            ]
        );
    }
}
