use rand::RngCore;
use ring::aead::{self, Aad, LessSafeKey, Nonce, UnboundKey};
use zerocopy::{AsBytes, FromBytes, FromZeroes};

use super::{Encryptor, Error};
use crate::tunnel::packet_def::ZCPacket;

#[repr(C, packed)]
#[derive(AsBytes, FromBytes, FromZeroes, Clone, Debug, Default)]
pub struct ChaCha20Poly1305Tail {
    pub tag: [u8; 16],
    pub nonce: [u8; 12],
}

pub const CHACHA20_POLY1305_ENCRYPTION_RESERVED: usize =
    std::mem::size_of::<ChaCha20Poly1305Tail>();

#[derive(Clone)]
pub struct RingChaCha20Cipher {
    cipher: LessSafeKey,
    key: [u8; 32],
}

impl RingChaCha20Cipher {
    pub fn new(key: [u8; 32]) -> Self {
        let unbound_key = UnboundKey::new(&aead::CHACHA20_POLY1305, &key).unwrap();
        let cipher = LessSafeKey::new(unbound_key);
        Self { cipher, key }
    }
}

impl Encryptor for RingChaCha20Cipher {
    fn decrypt(&self, zc_packet: &mut ZCPacket) -> Result<(), Error> {
        let pm_header = zc_packet.peer_manager_header().unwrap();
        if !pm_header.is_encrypted() {
            return Ok(());
        }

        let payload_len = zc_packet.payload().len();
        if payload_len < CHACHA20_POLY1305_ENCRYPTION_RESERVED {
            return Err(Error::PacketTooShort(zc_packet.payload().len()));
        }

        let text_and_tag_len = payload_len - CHACHA20_POLY1305_ENCRYPTION_RESERVED + 16;

        let chacha20_tail = ChaCha20Poly1305Tail::ref_from_suffix(zc_packet.payload()).unwrap();
        let nonce = Nonce::assume_unique_for_key(chacha20_tail.nonce);

        let rs = self.cipher.open_in_place(
            nonce,
            Aad::empty(),
            &mut zc_packet.mut_payload()[..text_and_tag_len],
        );

        if rs.is_err() {
            return Err(Error::DecryptionFailed);
        }

        let pm_header = zc_packet.mut_peer_manager_header().unwrap();
        pm_header.set_encrypted(false);
        let old_len = zc_packet.buf_len();
        zc_packet
            .mut_inner()
            .truncate(old_len - CHACHA20_POLY1305_ENCRYPTION_RESERVED);

        Ok(())
    }

    fn encrypt(&self, zc_packet: &mut ZCPacket) -> Result<(), Error> {
        let pm_header = zc_packet.peer_manager_header().unwrap();
        if pm_header.is_encrypted() {
            tracing::warn!(?zc_packet, "packet is already encrypted");
            return Ok(());
        }

        let mut tail = ChaCha20Poly1305Tail::default();
        rand::thread_rng().fill_bytes(&mut tail.nonce);
        let nonce = Nonce::assume_unique_for_key(tail.nonce);

        let rs =
            self.cipher
                .seal_in_place_separate_tag(nonce, Aad::empty(), zc_packet.mut_payload());

        match rs {
            Ok(tag) => {
                tail.tag.copy_from_slice(tag.as_ref());
                let pm_header = zc_packet.mut_peer_manager_header().unwrap();
                pm_header.set_encrypted(true);
                zc_packet.mut_inner().extend_from_slice(tail.as_bytes());
                Ok(())
            }
            Err(_) => Err(Error::EncryptionFailed),
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::{
        peers::encrypt::{ring_chacha20::RingChaCha20Cipher, Encryptor},
        tunnel::packet_def::ZCPacket,
    };

    use super::CHACHA20_POLY1305_ENCRYPTION_RESERVED;

    #[test]
    fn test_ring_chacha20_cipher() {
        let key = [0u8; 32];
        let cipher = RingChaCha20Cipher::new(key);
        let text = b"Hello, World! This is a test message for Ring ChaCha20-Poly1305.";
        let mut packet = ZCPacket::new_with_payload(text);
        packet.fill_peer_manager_hdr(0, 0, 0);

        cipher.encrypt(&mut packet).unwrap();
        assert_eq!(
            packet.payload().len(),
            text.len() + CHACHA20_POLY1305_ENCRYPTION_RESERVED
        );
        assert!(packet.peer_manager_header().unwrap().is_encrypted());

        cipher.decrypt(&mut packet).unwrap();
        assert_eq!(packet.payload(), text);
        assert!(!packet.peer_manager_header().unwrap().is_encrypted());
    }
}
