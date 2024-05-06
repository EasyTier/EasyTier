use crate::tunnel::packet_def::ZCPacket;

#[cfg(feature = "wireguard")]
pub mod ring_aes_gcm;

#[cfg(feature = "aes-gcm")]
pub mod aes_gcm;

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
            return Err(Error::DecryptionFailed);
        } else {
            Ok(())
        }
    }
}
