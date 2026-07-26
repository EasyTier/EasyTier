use rand::RngCore as _;
use ring::aead::{self, LessSafeKey, UnboundKey};
use zerocopy::{AsBytes as _, FromBytes as _, FromZeroes as _};

use crate::packet::{StandardAeadTail, ZCPacket};

use super::{Encryptor, Error};

#[derive(Clone)]
pub struct RingCipher {
    cipher: RingCipherKind,
}

enum RingCipherKind {
    Aes128Gcm(LessSafeKey, [u8; 16]),
    Aes256Gcm(LessSafeKey, [u8; 32]),
    ChaCha20Poly1305(LessSafeKey, [u8; 32]),
}

impl RingCipherKind {
    fn key(&self) -> &LessSafeKey {
        match self {
            Self::Aes128Gcm(cipher, _)
            | Self::Aes256Gcm(cipher, _)
            | Self::ChaCha20Poly1305(cipher, _) => cipher,
        }
    }
}

impl Clone for RingCipherKind {
    fn clone(&self) -> Self {
        match self {
            Self::Aes128Gcm(_, key) => Self::Aes128Gcm(
                LessSafeKey::new(UnboundKey::new(&aead::AES_128_GCM, key).unwrap()),
                *key,
            ),
            Self::Aes256Gcm(_, key) => Self::Aes256Gcm(
                LessSafeKey::new(UnboundKey::new(&aead::AES_256_GCM, key).unwrap()),
                *key,
            ),
            Self::ChaCha20Poly1305(_, key) => Self::ChaCha20Poly1305(
                LessSafeKey::new(UnboundKey::new(&aead::CHACHA20_POLY1305, key).unwrap()),
                *key,
            ),
        }
    }
}

impl RingCipher {
    pub fn new_aes128_gcm(key: [u8; 16]) -> Self {
        Self {
            cipher: RingCipherKind::Aes128Gcm(
                LessSafeKey::new(UnboundKey::new(&aead::AES_128_GCM, &key).unwrap()),
                key,
            ),
        }
    }

    pub fn new_aes256_gcm(key: [u8; 32]) -> Self {
        Self {
            cipher: RingCipherKind::Aes256Gcm(
                LessSafeKey::new(UnboundKey::new(&aead::AES_256_GCM, &key).unwrap()),
                key,
            ),
        }
    }

    pub fn new_chacha20(key: [u8; 32]) -> Self {
        Self {
            cipher: RingCipherKind::ChaCha20Poly1305(
                LessSafeKey::new(UnboundKey::new(&aead::CHACHA20_POLY1305, &key).unwrap()),
                key,
            ),
        }
    }
}

impl Encryptor for RingCipher {
    fn decrypt(&self, packet: &mut ZCPacket) -> Result<(), Error> {
        let header = packet.peer_manager_header().unwrap();
        if !header.is_encrypted() {
            return Ok(());
        }

        let payload_len = packet.payload().len();
        if payload_len < StandardAeadTail::SIZE {
            return Err(Error::PacketTooShort(payload_len));
        }

        let text_and_tag_len = payload_len - StandardAeadTail::SIZE + StandardAeadTail::TAG_SIZE;
        let tail = StandardAeadTail::ref_from_suffix(packet.payload()).unwrap();
        let nonce = aead::Nonce::assume_unique_for_key(tail.nonce);

        self.cipher
            .key()
            .open_in_place(
                nonce,
                aead::Aad::empty(),
                &mut packet.mut_payload()[..text_and_tag_len],
            )
            .map_err(|_| Error::DecryptionFailed)?;

        packet
            .mut_peer_manager_header()
            .unwrap()
            .set_encrypted(false);
        let old_len = packet.buf_len();
        packet
            .mut_inner()
            .truncate(old_len - StandardAeadTail::SIZE);
        Ok(())
    }

    fn encrypt(&self, packet: &mut ZCPacket) -> Result<(), Error> {
        self.encrypt_with_nonce(packet, None)
    }

    fn encrypt_with_nonce(&self, packet: &mut ZCPacket, nonce: Option<&[u8]>) -> Result<(), Error> {
        let header = packet.peer_manager_header().unwrap();
        if header.is_encrypted() {
            tracing::warn!(?packet, "packet is already encrypted");
            return Ok(());
        }

        let mut tail = StandardAeadTail::new_zeroed();
        match nonce {
            Some(nonce) => {
                tail.nonce = nonce.try_into().map_err(|_| Error::EncryptionFailed)?;
            }
            None => rand::thread_rng().fill_bytes(&mut tail.nonce),
        }

        let nonce = aead::Nonce::assume_unique_for_key(tail.nonce);
        let tag = self
            .cipher
            .key()
            .seal_in_place_separate_tag(nonce, aead::Aad::empty(), packet.mut_payload())
            .map_err(|_| Error::EncryptionFailed)?;
        tail.tag.copy_from_slice(tag.as_ref());

        packet
            .mut_peer_manager_header()
            .unwrap()
            .set_encrypted(true);
        packet.mut_inner().extend_from_slice(tail.as_bytes());
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn round_trip(cipher: RingCipher) {
        let plaintext = b"ring accelerated packet";
        let mut packet = ZCPacket::new_with_payload(plaintext);
        packet.fill_peer_manager_hdr(1, 2, 1);

        cipher
            .encrypt_with_nonce(&mut packet, Some(&[3; StandardAeadTail::NONCE_SIZE]))
            .unwrap();
        assert!(packet.peer_manager_header().unwrap().is_encrypted());

        cipher.decrypt(&mut packet).unwrap();
        assert_eq!(packet.payload(), plaintext);
        assert!(!packet.peer_manager_header().unwrap().is_encrypted());
    }

    #[test]
    fn ring_algorithms_round_trip() {
        round_trip(RingCipher::new_aes128_gcm([1; 16]));
        round_trip(RingCipher::new_aes256_gcm([2; 32]));
        round_trip(RingCipher::new_chacha20([3; 32]));
    }
}
