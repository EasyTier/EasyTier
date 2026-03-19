use rand::RngCore;
use ring::aead::{self};
use ring::aead::{LessSafeKey, UnboundKey};
use zerocopy::{AsBytes, FromBytes, FromZeroes};

use crate::tunnel::packet_def::{StandardAeadTail, ZCPacket};

use super::{Encryptor, Error};

#[derive(Clone)]
pub struct RingCipher {
    pub(crate) cipher: RingEnum,
}

pub enum RingEnum {
    Aes128Gcm(LessSafeKey, [u8; 16]),
    Aes256Gcm(LessSafeKey, [u8; 32]),
    ChaCha20(LessSafeKey, [u8; 32]),
}

impl RingEnum {
    fn get_cipher(&self) -> &LessSafeKey {
        match &self {
            RingEnum::Aes128Gcm(cipher, _) => cipher,
            RingEnum::Aes256Gcm(cipher, _) => cipher,
            RingEnum::ChaCha20(cipher, _) => cipher,
        }
    }
}

impl Clone for RingEnum {
    fn clone(&self) -> Self {
        match &self {
            RingEnum::Aes128Gcm(_, key) => {
                let c =
                    LessSafeKey::new(UnboundKey::new(&aead::AES_128_GCM, key.as_slice()).unwrap());
                RingEnum::Aes128Gcm(c, *key)
            }
            RingEnum::Aes256Gcm(_, key) => {
                let c =
                    LessSafeKey::new(UnboundKey::new(&aead::AES_256_GCM, key.as_slice()).unwrap());
                RingEnum::Aes256Gcm(c, *key)
            }
            RingEnum::ChaCha20(_, key) => {
                let c = LessSafeKey::new(
                    UnboundKey::new(&aead::CHACHA20_POLY1305, key.as_slice()).unwrap(),
                );
                RingEnum::ChaCha20(c, *key)
            }
        }
    }
}

impl RingCipher {
    pub fn new_aes128_gcm(key: [u8; 16]) -> Self {
        let cipher = LessSafeKey::new(UnboundKey::new(&aead::AES_128_GCM, &key).unwrap());
        Self {
            cipher: RingEnum::Aes128Gcm(cipher, key),
        }
    }

    pub fn new_aes256_gcm(key: [u8; 32]) -> Self {
        let cipher = LessSafeKey::new(UnboundKey::new(&aead::AES_256_GCM, &key).unwrap());
        Self {
            cipher: RingEnum::Aes256Gcm(cipher, key),
        }
    }

    pub fn new_chacha20(key: [u8; 32]) -> Self {
        let unbound_key = UnboundKey::new(&aead::CHACHA20_POLY1305, &key).unwrap();
        let cipher = LessSafeKey::new(unbound_key);
        Self {
            cipher: RingEnum::ChaCha20(cipher, key),
        }
    }
}

impl Encryptor for RingCipher {
    fn decrypt(&self, zc_packet: &mut ZCPacket) -> Result<(), Error> {
        let pm_header = zc_packet.peer_manager_header().unwrap();
        if !pm_header.is_encrypted() {
            return Ok(());
        }

        let payload_len = zc_packet.payload().len();
        if payload_len < StandardAeadTail::SIZE {
            return Err(Error::PacketTooShort(zc_packet.payload().len()));
        }

        let text_and_tag_len = payload_len - StandardAeadTail::NONCE_SIZE;

        let aes_tail = StandardAeadTail::ref_from_suffix(zc_packet.payload()).unwrap();
        let nonce = aead::Nonce::assume_unique_for_key(aes_tail.nonce);

        self.cipher
            .get_cipher()
            .open_in_place(
                nonce,
                aead::Aad::empty(),
                &mut zc_packet.mut_payload()[..text_and_tag_len],
            )
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

        let mut tail = StandardAeadTail::new_zeroed();

        match nonce {
            Some(n) => tail.nonce = n.try_into().map_err(|_| Error::EncryptionFailed)?,
            None => rand::thread_rng().fill_bytes(&mut tail.nonce),
        }
        let nonce = aead::Nonce::assume_unique_for_key(tail.nonce);

        let tag = self
            .cipher
            .get_cipher()
            .seal_in_place_separate_tag(nonce, aead::Aad::empty(), zc_packet.mut_payload())
            .map_err(|_| Error::EncryptionFailed)?;

        let tag = tag.as_ref();
        if tag.len() != StandardAeadTail::TAG_SIZE {
            return Err(Error::InvalidTag(tag.to_vec()));
        }
        tail.tag.copy_from_slice(tag);

        let pm_header = zc_packet.mut_peer_manager_header().unwrap();
        pm_header.set_encrypted(true);
        zc_packet.mut_inner().extend_from_slice(tail.as_bytes());
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use crate::{
        peers::encrypt::{ring::RingCipher, Encryptor},
        tunnel::packet_def::{StandardAeadTail, ZCPacket},
    };
    use zerocopy::FromBytes;

    #[test]
    fn test_aes_gcm_cipher() {
        let key = [0u8; 16];
        let cipher = RingCipher::new_aes128_gcm(key);
        let text = b"1234567";
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
    fn test_aes_gcm_cipher_with_nonce() {
        let key = [7u8; 16];
        let cipher = RingCipher::new_aes128_gcm(key);
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

    #[test]
    fn test_ring_chacha20_cipher() {
        let key = [0u8; 32];
        let cipher = RingCipher::new_chacha20(key);
        let text = b"Hello, World! This is a test message for Ring ChaCha20-Poly1305.";
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
    fn test_ring_chacha20_cipher_with_nonce() {
        let key = [9u8; 32];
        let cipher = RingCipher::new_chacha20(key);
        let text = b"Hello";
        let nonce = [5u8; 12];

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
        assert!(!packet1.peer_manager_header().unwrap().is_encrypted());
    }
}
