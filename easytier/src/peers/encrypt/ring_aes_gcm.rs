use rand::RngCore;
use ring::aead::{self};
use ring::aead::{LessSafeKey, UnboundKey};
use zerocopy::{AsBytes, FromBytes};

use crate::tunnel::packet_def::{AesGcmTail, ZCPacket, AES_GCM_ENCRYPTION_RESERVED};

use super::{Encryptor, Error};

#[derive(Clone)]
pub struct AesGcmCipher {
    pub(crate) cipher: AesGcmEnum,
}

pub enum AesGcmEnum {
    AesGCM128(LessSafeKey, [u8; 16]),
    AesGCM256(LessSafeKey, [u8; 32]),
}

impl Clone for AesGcmEnum {
    fn clone(&self) -> Self {
        match &self {
            AesGcmEnum::AesGCM128(_, key) => {
                let c =
                    LessSafeKey::new(UnboundKey::new(&aead::AES_128_GCM, key.as_slice()).unwrap());
                AesGcmEnum::AesGCM128(c, *key)
            }
            AesGcmEnum::AesGCM256(_, key) => {
                let c =
                    LessSafeKey::new(UnboundKey::new(&aead::AES_256_GCM, key.as_slice()).unwrap());
                AesGcmEnum::AesGCM256(c, *key)
            }
        }
    }
}

impl AesGcmCipher {
    pub fn new_128(key: [u8; 16]) -> Self {
        let cipher = LessSafeKey::new(UnboundKey::new(&aead::AES_128_GCM, &key).unwrap());
        Self {
            cipher: AesGcmEnum::AesGCM128(cipher, key),
        }
    }

    pub fn new_256(key: [u8; 32]) -> Self {
        let cipher = LessSafeKey::new(UnboundKey::new(&aead::AES_256_GCM, &key).unwrap());
        Self {
            cipher: AesGcmEnum::AesGCM256(cipher, key),
        }
    }
}

impl Encryptor for AesGcmCipher {
    fn decrypt(&self, zc_packet: &mut ZCPacket) -> Result<(), Error> {
        let pm_header = zc_packet.peer_manager_header().unwrap();
        if !pm_header.is_encrypted() {
            return Ok(());
        }

        let payload_len = zc_packet.payload().len();
        if payload_len < AES_GCM_ENCRYPTION_RESERVED {
            return Err(Error::PacketTooShort(zc_packet.payload().len()));
        }

        let text_and_tag_len = payload_len - AES_GCM_ENCRYPTION_RESERVED + 16;

        let aes_tail = AesGcmTail::ref_from_suffix(zc_packet.payload()).unwrap();
        let nonce = aead::Nonce::assume_unique_for_key(aes_tail.nonce.clone());

        let rs = match &self.cipher {
            AesGcmEnum::AesGCM128(cipher, _) => cipher.open_in_place(
                nonce,
                aead::Aad::empty(),
                &mut zc_packet.mut_payload()[..text_and_tag_len],
            ),
            AesGcmEnum::AesGCM256(cipher, _) => cipher.open_in_place(
                nonce,
                aead::Aad::empty(),
                &mut zc_packet.mut_payload()[..text_and_tag_len],
            ),
        };
        if let Err(_) = rs {
            return Err(Error::DecryptionFailed);
        }

        let pm_header = zc_packet.mut_peer_manager_header().unwrap();
        pm_header.set_encrypted(false);
        let old_len = zc_packet.buf_len();
        zc_packet
            .mut_inner()
            .truncate(old_len - AES_GCM_ENCRYPTION_RESERVED);
        return Ok(());
    }

    fn encrypt(&self, zc_packet: &mut ZCPacket) -> Result<(), Error> {
        let pm_header = zc_packet.peer_manager_header().unwrap();
        if pm_header.is_encrypted() {
            tracing::warn!(?zc_packet, "packet is already encrypted");
            return Ok(());
        }

        let mut tail = AesGcmTail::default();
        rand::thread_rng().fill_bytes(&mut tail.nonce);
        let nonce = aead::Nonce::assume_unique_for_key(tail.nonce.clone());

        let rs = match &self.cipher {
            AesGcmEnum::AesGCM128(cipher, _) => cipher.seal_in_place_separate_tag(
                nonce,
                aead::Aad::empty(),
                zc_packet.mut_payload(),
            ),
            AesGcmEnum::AesGCM256(cipher, _) => cipher.seal_in_place_separate_tag(
                nonce,
                aead::Aad::empty(),
                zc_packet.mut_payload(),
            ),
        };
        return match rs {
            Ok(tag) => {
                let tag = tag.as_ref();
                if tag.len() != 16 {
                    return Err(Error::InvalidTag(tag.to_vec()));
                }
                tail.tag.copy_from_slice(tag);

                let pm_header = zc_packet.mut_peer_manager_header().unwrap();
                pm_header.set_encrypted(true);
                zc_packet.mut_inner().extend_from_slice(tail.as_bytes());
                Ok(())
            }
            Err(_) => Err(Error::EncryptionFailed),
        };
    }
}

#[cfg(test)]
mod tests {
    use crate::{
        peers::encrypt::{ring_aes_gcm::AesGcmCipher, Encryptor},
        tunnel::packet_def::{ZCPacket, AES_GCM_ENCRYPTION_RESERVED},
    };

    #[test]
    fn test_aes_gcm_cipher() {
        let key = [0u8; 16];
        let cipher = AesGcmCipher::new_128(key);
        let text = b"1234567";
        let mut packet = ZCPacket::new_with_payload(text);
        packet.fill_peer_manager_hdr(0, 0, 0);
        cipher.encrypt(&mut packet).unwrap();
        assert_eq!(
            packet.payload().len(),
            text.len() + AES_GCM_ENCRYPTION_RESERVED
        );
        assert_eq!(packet.peer_manager_header().unwrap().is_encrypted(), true);

        cipher.decrypt(&mut packet).unwrap();
        assert_eq!(packet.payload(), text);
        assert_eq!(packet.peer_manager_header().unwrap().is_encrypted(), false);
    }
}
