use crate::tunnel::packet_def::ZCPacket;

pub mod ring_aes_gcm;

#[derive(thiserror::Error, Debug)]
pub enum Error {
    #[error("packet is not encrypted")]
    NotEcrypted,
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

    fn decrypt(&self, _zc_packet: &mut ZCPacket) -> Result<(), Error> {
        Ok(())
    }
}
