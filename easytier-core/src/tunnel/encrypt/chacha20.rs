use chacha20poly1305::{AeadCore, AeadInPlace, ChaCha20Poly1305, Key, KeyInit};
use rand::rngs::OsRng;
use zerocopy::{AsBytes, FromBytes};

use crate::packet::{StandardAeadTail, ZCPacket};

use super::{Encryptor, Error};

#[derive(Clone)]
pub struct ChaCha20Cipher {
    cipher: Box<ChaCha20Poly1305>,
}

impl ChaCha20Cipher {
    pub fn new(key: [u8; 32]) -> Self {
        let key: &Key = &key.into();
        Self {
            cipher: Box::new(ChaCha20Poly1305::new(key)),
        }
    }
}

impl Encryptor for ChaCha20Cipher {
    fn decrypt(&self, zc_packet: &mut ZCPacket) -> Result<(), Error> {
        let pm_header = zc_packet.peer_manager_header().unwrap();
        if !pm_header.is_encrypted() {
            return Ok(());
        }

        let payload_len = zc_packet.payload().len();
        if payload_len < StandardAeadTail::SIZE {
            return Err(Error::PacketTooShort(zc_packet.payload().len()));
        }

        let text_len = payload_len - StandardAeadTail::SIZE;

        let tail = StandardAeadTail::ref_from_suffix(zc_packet.payload())
            .unwrap()
            .clone();

        let nonce = tail.nonce.into();
        let tag = tail.tag.into();

        self.cipher
            .decrypt_in_place_detached(&nonce, &[], &mut zc_packet.mut_payload()[..text_len], &tag)
            .map_err(|_| Error::DecryptionFailed)?;

        let pm_header = zc_packet.mut_peer_manager_header().unwrap();
        pm_header.set_encrypted(false);
        let old_len = zc_packet.buf_len();
        zc_packet
            .mut_inner()
            .truncate(old_len - StandardAeadTail::SIZE);
        Ok(())
    }

    fn encrypt(&self, zc_packet: &mut ZCPacket) -> Result<(), Error> {
        self.encrypt_with_nonce(zc_packet, None)
    }

    fn encrypt_with_nonce(
        &self,
        zc_packet: &mut ZCPacket,
        nonce: Option<&[u8]>,
    ) -> Result<(), Error> {
        let pm_header = zc_packet.peer_manager_header().unwrap();
        if pm_header.is_encrypted() {
            tracing::warn!(?zc_packet, "packet is already encrypted");
            return Ok(());
        }

        let nonce = nonce
            .map(|n| {
                <[u8; StandardAeadTail::NONCE_SIZE]>::try_from(n)
                    .map(Into::into)
                    .map_err(|_| Error::EncryptionFailed)
            })
            .transpose()?
            .unwrap_or_else(|| ChaCha20Poly1305::generate_nonce(&mut OsRng));

        let tag = self
            .cipher
            .encrypt_in_place_detached(&nonce, &[], zc_packet.mut_payload())
            .map_err(|_| Error::EncryptionFailed)?;

        let tail = StandardAeadTail {
            tag: tag.into(),
            nonce: nonce.into(),
        };

        let pm_header = zc_packet.mut_peer_manager_header().unwrap();
        pm_header.set_encrypted(true);
        zc_packet.mut_inner().extend_from_slice(tail.as_bytes());
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use crate::{
        packet::{StandardAeadTail, ZCPacket},
        tunnel::encrypt::{Encryptor, chacha20::ChaCha20Cipher},
    };
    use zerocopy::FromBytes;

    #[test]
    fn test_chacha20_cipher() {
        let key = [7u8; 32];
        let cipher = ChaCha20Cipher::new(key);
        let text = b"Hello, ChaCha20";
        let mut packet = ZCPacket::new_with_payload(text);
        packet.fill_peer_manager_hdr(0, 0, 0);

        cipher.encrypt(&mut packet).unwrap();
        assert_eq!(packet.payload().len(), text.len() + StandardAeadTail::SIZE);
        assert!(packet.peer_manager_header().unwrap().is_encrypted());

        cipher.decrypt(&mut packet).unwrap();
        assert_eq!(packet.payload(), text);
        assert!(!packet.peer_manager_header().unwrap().is_encrypted());
    }

    #[test]
    fn test_chacha20_cipher_with_nonce() {
        let key = [7u8; 32];
        let cipher = ChaCha20Cipher::new(key);
        let text = b"Hello";
        let nonce = [3u8; 12];

        let mut packet1 = ZCPacket::new_with_payload(text);
        packet1.fill_peer_manager_hdr(0, 0, 0);
        cipher
            .encrypt_with_nonce(&mut packet1, Some(&nonce))
            .unwrap();

        let mut packet2 = ZCPacket::new_with_payload(text);
        packet2.fill_peer_manager_hdr(0, 0, 0);
        cipher
            .encrypt_with_nonce(&mut packet2, Some(&nonce))
            .unwrap();

        assert_eq!(packet1.payload(), packet2.payload());

        let tail = StandardAeadTail::ref_from_suffix(packet1.payload()).unwrap();
        assert_eq!(tail.nonce, nonce);

        cipher.decrypt(&mut packet1).unwrap();
        assert_eq!(packet1.payload(), text);
    }
}
