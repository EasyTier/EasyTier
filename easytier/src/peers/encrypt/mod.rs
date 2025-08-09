use std::sync::Arc;

use crate::{common::config::EncryptionAlgorithm, tunnel::packet_def::ZCPacket};

#[cfg(feature = "wireguard")]
pub mod ring_aes_gcm;

#[cfg(feature = "wireguard")]
pub mod ring_chacha20;

#[cfg(feature = "aes-gcm")]
pub mod aes_gcm;

#[cfg(feature = "openssl-crypto")]
pub mod openssl_cipher;

pub mod xor_cipher;

#[derive(thiserror::Error, Debug)]
pub enum Error {
    #[error("packet is too short. len: {0}")]
    PacketTooShort(usize),
    #[error("decryption failed")]
    DecryptionFailed,
    #[error("encryption failed")]
    EncryptionFailed,
    #[error("invalid tag. tag: {0:?}")]
    InvalidTag(Vec<u8>),
}

pub trait Encryptor: Send + Sync + 'static {
    fn encrypt(&self, zc_packet: &mut ZCPacket) -> Result<(), Error>;
    fn decrypt(&self, zc_packet: &mut ZCPacket) -> Result<(), Error>;
}

pub struct NullCipher;

impl Encryptor for NullCipher {
    fn encrypt(&self, _zc_packet: &mut ZCPacket) -> Result<(), Error> {
        Ok(())
    }

    fn decrypt(&self, zc_packet: &mut ZCPacket) -> Result<(), Error> {
        let pm_header = zc_packet.peer_manager_header().unwrap();
        if pm_header.is_encrypted() {
            Err(Error::DecryptionFailed)
        } else {
            Ok(())
        }
    }
}

/// Create an encryptor based on the algorithm name
pub fn create_encryptor(
    algorithm: &str,
    key_128: [u8; 16],
    key_256: [u8; 32],
) -> Arc<dyn Encryptor> {
    let algorithm = match EncryptionAlgorithm::try_from(algorithm) {
        Ok(algorithm) => algorithm,
        Err(_) => {
            eprintln!(
                "Unknown encryption algorithm: {}, falling back to default AES-GCM",
                algorithm
            );
            EncryptionAlgorithm::AesGcm
        }
    };
    match algorithm {
        EncryptionAlgorithm::AesGcm => {
            #[cfg(feature = "wireguard")]
            {
                Arc::new(ring_aes_gcm::AesGcmCipher::new_128(key_128))
            }
            #[cfg(all(feature = "aes-gcm", not(feature = "wireguard")))]
            {
                Arc::new(aes_gcm::AesGcmCipher::new_128(key_128))
            }
            #[cfg(all(not(feature = "wireguard"), not(feature = "aes-gcm")))]
            {
                compile_error!(
                    "wireguard or aes-gcm feature must be enabled for default encryption"
                );
            }
        }

        EncryptionAlgorithm::Aes256Gcm => {
            #[cfg(feature = "wireguard")]
            {
                Arc::new(ring_aes_gcm::AesGcmCipher::new_256(key_256))
            }
            #[cfg(all(feature = "aes-gcm", not(feature = "wireguard")))]
            {
                Arc::new(aes_gcm::AesGcmCipher::new_256(key_256))
            }
        }

        EncryptionAlgorithm::Xor => Arc::new(xor_cipher::XorCipher::new(&key_128)),

        #[cfg(feature = "wireguard")]
        EncryptionAlgorithm::ChaCha20 => Arc::new(ring_chacha20::RingChaCha20Cipher::new(key_256)),

        #[cfg(feature = "openssl-crypto")]
        EncryptionAlgorithm::OpensslAesGcm => {
            Arc::new(openssl_cipher::OpenSslCipher::new_aes128_gcm(key_128))
        }

        #[cfg(feature = "openssl-crypto")]
        EncryptionAlgorithm::OpensslAes256Gcm => {
            Arc::new(openssl_cipher::OpenSslCipher::new_aes256_gcm(key_256))
        }

        #[cfg(feature = "openssl-crypto")]
        EncryptionAlgorithm::OpensslChacha20 => {
            Arc::new(openssl_cipher::OpenSslCipher::new_chacha20(key_256))
        }
    }
}
