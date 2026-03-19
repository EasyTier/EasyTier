use crate::{
    common::{config::EncryptionAlgorithm, log},
    tunnel::packet_def::ZCPacket,
};
use cfg_if::cfg_if;
use std::sync::Arc;

#[cfg(feature = "wireguard")]
pub mod ring;

#[cfg(feature = "aes-gcm")]
pub mod aes_gcm;

#[cfg(feature = "openssl-crypto")]
pub mod openssl;

pub mod xor;

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
            log::warn!(
                "Unknown encryption algorithm: {}, falling back to default {}",
                algorithm,
                default
            );
            default
        }
    };
    match algorithm {
        EncryptionAlgorithm::Xor => Arc::new(xor::XorCipher::new(&key_128)),

        #[cfg(any(feature = "aes-gcm", feature = "wireguard"))]
        EncryptionAlgorithm::AesGcm => {
            cfg_if! {
                if #[cfg(feature = "wireguard")] {
                    Arc::new(ring::RingCipher::new_128(key_128))
                } else {
                    Arc::new(aes_gcm::AesGcmCipher::new_128(key_128))
                }
            }
        }

        #[cfg(any(feature = "aes-gcm", feature = "wireguard"))]
        EncryptionAlgorithm::Aes256Gcm => {
            cfg_if! {
                if #[cfg(feature = "wireguard")] {
                    Arc::new(ring::RingCipher::new_256(key_256))
                } else {
                    Arc::new(aes_gcm::AesGcmCipher::new_256(key_256))
                }
            }
        }

        #[cfg(feature = "wireguard")]
        EncryptionAlgorithm::ChaCha20 => Arc::new(ring::RingCipher::new_chacha20(key_256)),

        #[cfg(feature = "openssl-crypto")]
        EncryptionAlgorithm::OpenSslAesGcm => {
            Arc::new(openssl::OpenSslCipher::new_aes128_gcm(key_128))
        }

        #[cfg(feature = "openssl-crypto")]
        EncryptionAlgorithm::OpenSslAes256Gcm => {
            Arc::new(openssl::OpenSslCipher::new_aes256_gcm(key_256))
        }

        #[cfg(feature = "openssl-crypto")]
        EncryptionAlgorithm::OpenSslChaCha20 => {
            Arc::new(openssl::OpenSslCipher::new_chacha20(key_256))
        }
    }
}
