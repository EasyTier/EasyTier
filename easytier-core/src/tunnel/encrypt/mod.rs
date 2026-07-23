use crate::{config::EncryptionAlgorithm, packet::ZCPacket};
use std::{collections::hash_map::DefaultHasher, hash::Hasher, sync::Arc};

#[cfg(feature = "aes-gcm")]
pub mod aes_gcm;
#[cfg(feature = "chacha20")]
pub mod chacha20;

#[cfg(feature = "aes-gcm")]
#[path = "backend/aes_enabled.rs"]
mod aes_backend;
#[cfg(not(feature = "aes-gcm"))]
#[path = "backend/aes_disabled.rs"]
mod aes_backend;
#[cfg(feature = "chacha20")]
#[path = "backend/chacha20_enabled.rs"]
mod chacha20_backend;
#[cfg(not(feature = "chacha20"))]
#[path = "backend/chacha20_disabled.rs"]
mod chacha20_backend;

pub mod xor;

// The disabled backends keep the same error Interface as the AEAD backends.
#[allow(dead_code)]
#[derive(thiserror::Error, Debug)]
pub enum Error {
    #[error("packet is too short. len: {0}")]
    PacketTooShort(usize),
    #[error("decryption failed")]
    DecryptionFailed,
    #[error("encryption failed")]
    EncryptionFailed,
    #[error("invalid encryption algorithm: {0}")]
    InvalidAlgorithm(String),
    #[error("encryption algorithm is unavailable in this build: {0}")]
    AlgorithmUnavailable(String),
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

struct UnsupportedCipher {
    algorithm: String,
    unavailable: bool,
}

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

impl UnsupportedCipher {
    fn error(&self) -> Error {
        if self.unavailable {
            Error::AlgorithmUnavailable(self.algorithm.clone())
        } else {
            Error::InvalidAlgorithm(self.algorithm.clone())
        }
    }
}

impl Encryptor for UnsupportedCipher {
    fn decrypt(&self, _zc_packet: &mut ZCPacket) -> Result<(), Error> {
        Err(self.error())
    }

    fn encrypt(&self, _zc_packet: &mut ZCPacket) -> Result<(), Error> {
        Err(self.error())
    }
}

fn invalid_encryptor(algorithm: &str) -> Arc<dyn Encryptor> {
    Arc::new(UnsupportedCipher {
        algorithm: algorithm.to_owned(),
        unavailable: false,
    })
}

#[allow(dead_code)] // Selected disabled backends call this in reduced profiles.
fn unavailable_encryptor(algorithm: &str) -> Arc<dyn Encryptor> {
    Arc::new(UnsupportedCipher {
        algorithm: algorithm.to_owned(),
        unavailable: true,
    })
}

fn algorithm_is_available(algorithm: EncryptionAlgorithm) -> bool {
    match algorithm {
        EncryptionAlgorithm::Xor => true,
        EncryptionAlgorithm::AesGcm | EncryptionAlgorithm::Aes256Gcm => aes_backend::AVAILABLE,
        EncryptionAlgorithm::ChaCha20 => chacha20_backend::AVAILABLE,
    }
}

pub(crate) fn validate_algorithm(algorithm: &str) -> Result<(), Error> {
    let parsed = algorithm
        .parse::<EncryptionAlgorithm>()
        .map_err(|()| Error::InvalidAlgorithm(algorithm.to_owned()))?;
    if algorithm_is_available(parsed) {
        Ok(())
    } else {
        Err(Error::AlgorithmUnavailable(parsed.to_string()))
    }
}

pub(super) fn effective_algorithm_uses_xor(algorithm: &str) -> bool {
    algorithm.parse() == Ok(EncryptionAlgorithm::Xor)
}

/// Create an encryptor based on the algorithm name.
///
/// Callers that accept user configuration validate it during construction.
/// Protocol paths remain infallible here and receive an encryptor that returns
/// an explicit error if a peer names an invalid or unavailable algorithm.
pub fn create_encryptor(
    algorithm: &str,
    key_128: [u8; 16],
    key_256: [u8; 32],
) -> Arc<dyn Encryptor> {
    let Ok(algorithm) = algorithm.parse::<EncryptionAlgorithm>() else {
        return invalid_encryptor(algorithm);
    };

    match algorithm {
        EncryptionAlgorithm::Xor => Arc::new(xor::XorCipher::new(&key_128)),
        EncryptionAlgorithm::AesGcm => aes_backend::new_128(key_128),
        EncryptionAlgorithm::Aes256Gcm => aes_backend::new_256(key_256),
        EncryptionAlgorithm::ChaCha20 => chacha20_backend::new(key_256),
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

    #[test]
    fn effective_algorithm_only_reports_explicit_xor() {
        assert!(effective_algorithm_uses_xor("xor"));
        assert!(!effective_algorithm_uses_xor(""));
        assert!(!effective_algorithm_uses_xor("unsupported"));
        assert!(!effective_algorithm_uses_xor("aes-gcm"));
    }

    #[cfg(not(feature = "aes-gcm"))]
    #[test]
    fn unavailable_aes_is_known_but_rejected() {
        assert_eq!(
            validate_algorithm("aes-gcm").unwrap_err().to_string(),
            "encryption algorithm is unavailable in this build: aes-gcm"
        );
    }

    #[cfg(feature = "aes-gcm")]
    #[test]
    fn compiled_aes_is_available() {
        validate_algorithm("aes-gcm").unwrap();
        validate_algorithm("aes-256-gcm").unwrap();
    }

    #[cfg(not(feature = "chacha20"))]
    #[test]
    fn unavailable_chacha20_is_known_but_rejected() {
        assert_eq!(
            validate_algorithm("chacha20-poly1305")
                .unwrap_err()
                .to_string(),
            "encryption algorithm is unavailable in this build: chacha20"
        );
    }

    #[cfg(feature = "chacha20")]
    #[test]
    fn compiled_chacha20_is_available() {
        validate_algorithm("chacha20").unwrap();
    }

    #[test]
    fn invalid_algorithm_is_rejected() {
        assert_eq!(
            validate_algorithm("rot13").unwrap_err().to_string(),
            "invalid encryption algorithm: rot13"
        );
    }
}
