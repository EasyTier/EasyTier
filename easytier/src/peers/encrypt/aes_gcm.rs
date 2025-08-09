use aes_gcm::aead::consts::{U12, U16};
use aes_gcm::aead::generic_array::GenericArray;
use aes_gcm::{AeadCore, AeadInPlace, Aes128Gcm, Aes256Gcm, Key, KeyInit, Nonce, Tag};
use rand::rngs::OsRng;
use zerocopy::{AsBytes, FromBytes};

use crate::tunnel::packet_def::{AesGcmTail, ZCPacket, AES_GCM_ENCRYPTION_RESERVED};

use super::{Encryptor, Error};

#[derive(Clone)]
pub struct AesGcmCipher {
    pub(crate) cipher: AesGcmEnum,
}

#[derive(Clone)]
pub enum AesGcmEnum {
    AES128GCM(Box<Aes128Gcm>),
    AES256GCM(Box<Aes256Gcm>),
}

impl AesGcmCipher {
    pub fn new_128(key: [u8; 16]) -> Self {
        let key: &Key<Aes128Gcm> = &key.into();
        Self {
            cipher: AesGcmEnum::AES128GCM(Box::new(Aes128Gcm::new(key))),
        }
    }
    pub fn new_256(key: [u8; 32]) -> Self {
        let key: &Key<Aes256Gcm> = &key.into();
        Self {
            cipher: AesGcmEnum::AES256GCM(Box::new(Aes256Gcm::new(key))),
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

        let text_len = payload_len - AES_GCM_ENCRYPTION_RESERVED;

        let aes_tail = AesGcmTail::ref_from_suffix(zc_packet.payload())
            .unwrap()
            .clone();
        let nonce: &GenericArray<u8, U12> = Nonce::from_slice(&aes_tail.nonce);

        let tag: GenericArray<u8, U16> = Tag::clone_from_slice(aes_tail.tag.as_slice());
        let rs = match &self.cipher {
            AesGcmEnum::AES128GCM(aes_gcm) => aes_gcm.decrypt_in_place_detached(
                nonce,
                &[],
                &mut zc_packet.mut_payload()[..text_len],
                &tag,
            ),
            AesGcmEnum::AES256GCM(aes_gcm) => aes_gcm.decrypt_in_place_detached(
                nonce,
                &[],
                &mut zc_packet.mut_payload()[..text_len],
                &tag,
            ),
        };

        if let Err(e) = rs {
            println!("error: {:?}", e.to_string());
            return Err(Error::DecryptionFailed);
        }

        let pm_header = zc_packet.mut_peer_manager_header().unwrap();
        pm_header.set_encrypted(false);
        let old_len = zc_packet.buf_len();
        zc_packet
            .mut_inner()
            .truncate(old_len - AES_GCM_ENCRYPTION_RESERVED);
        Ok(())
    }

    fn encrypt(&self, zc_packet: &mut ZCPacket) -> Result<(), Error> {
        let pm_header = zc_packet.peer_manager_header().unwrap();
        if pm_header.is_encrypted() {
            tracing::warn!(?zc_packet, "packet is already encrypted");
            return Ok(());
        }

        let mut tail = AesGcmTail::default();
        let rs = match &self.cipher {
            AesGcmEnum::AES128GCM(aes_gcm) => {
                let nonce = Aes128Gcm::generate_nonce(&mut OsRng);
                tail.nonce.copy_from_slice(nonce.as_slice());
                aes_gcm.encrypt_in_place_detached(&nonce, &[], zc_packet.mut_payload())
            }
            AesGcmEnum::AES256GCM(aes_gcm) => {
                let nonce = Aes256Gcm::generate_nonce(&mut OsRng);
                tail.nonce.copy_from_slice(nonce.as_slice());
                aes_gcm.encrypt_in_place_detached(&nonce, &[], zc_packet.mut_payload())
            }
        };

        match rs {
            Ok(tag) => {
                tail.tag.copy_from_slice(tag.as_slice());

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
        peers::encrypt::{aes_gcm::AesGcmCipher, Encryptor},
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
        assert!(packet.peer_manager_header().unwrap().is_encrypted());

        cipher.decrypt(&mut packet).unwrap();
        assert_eq!(packet.payload(), text);
        assert!(!packet.peer_manager_header().unwrap().is_encrypted());
    }
}
