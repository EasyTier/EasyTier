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
    fn encrypt_with_nonce(
        &self,
        zc_packet: &mut ZCPacket,
        _nonce: Option<&[u8]>,
    ) -> Result<(), Error> {
        self.encrypt(zc_packet)
    }
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
            let default = EncryptionAlgorithm::default();
            eprintln!(
                "Unknown encryption algorithm: {}, falling back to default {}",
                algorithm, default
            );
            default
        }
    };
    match algorithm {
        EncryptionAlgorithm::Xor => Arc::new(xor_cipher::XorCipher::new(&key_128)),

        #[cfg(any(feature = "aes-gcm", feature = "wireguard"))]
        EncryptionAlgorithm::AesGcm => {
            #[cfg(feature = "wireguard")]
            {
                Arc::new(ring_aes_gcm::AesGcmCipher::new_128(key_128))
            }
            #[cfg(all(feature = "aes-gcm", not(feature = "wireguard")))]
            {
                Arc::new(aes_gcm::AesGcmCipher::new_128(key_128))
            }
        }

        #[cfg(any(feature = "aes-gcm", feature = "wireguard"))]
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
        EncryptionAlgorithm::OpensslChaCha20 => {
            Arc::new(openssl_cipher::OpenSslCipher::new_chacha20(key_256))
        }
    }
}
