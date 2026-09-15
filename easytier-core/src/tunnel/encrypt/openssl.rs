use openssl::symm::{Cipher, Crypter, Mode};
use rand::RngCore as _;
use zerocopy::{AsBytes as _, FromBytes as _, FromZeroes as _};

use crate::packet::{StandardAeadTail, ZCPacket};

use super::{Encryptor, Error};

#[derive(Clone)]
pub struct OpenSslCipher {
    cipher: OpenSslCipherKind,
}

#[derive(Clone, Copy)]
enum OpenSslCipherKind {
    Aes128Gcm([u8; 16]),
    Aes256Gcm([u8; 32]),
    ChaCha20Poly1305([u8; 32]),
}

impl OpenSslCipher {
    pub fn new_aes128_gcm(key: [u8; 16]) -> Self {
        Self {
            cipher: OpenSslCipherKind::Aes128Gcm(key),
        }
    }

    pub fn new_aes256_gcm(key: [u8; 32]) -> Self {
        Self {
            cipher: OpenSslCipherKind::Aes256Gcm(key),
        }
    }

    pub fn new_chacha20(key: [u8; 32]) -> Self {
        Self {
            cipher: OpenSslCipherKind::ChaCha20Poly1305(key),
        }
    }

    fn cipher_and_key(&self) -> (Cipher, &[u8]) {
        match &self.cipher {
            OpenSslCipherKind::Aes128Gcm(key) => (Cipher::aes_128_gcm(), key),
            OpenSslCipherKind::Aes256Gcm(key) => (Cipher::aes_256_gcm(), key),
            OpenSslCipherKind::ChaCha20Poly1305(key) => (Cipher::chacha20_poly1305(), key),
        }
    }
}

impl Encryptor for OpenSslCipher {
    fn decrypt(&self, packet: &mut ZCPacket) -> Result<(), Error> {
        let header = packet.peer_manager_header().unwrap();
        if !header.is_encrypted() {
            return Ok(());
        }

        let payload_len = packet.payload().len();
        if payload_len < StandardAeadTail::SIZE {
            return Err(Error::PacketTooShort(payload_len));
        }

        let (cipher, key) = self.cipher_and_key();
        let tail = StandardAeadTail::ref_from_suffix(packet.payload()).unwrap();
        let mut decrypter = Crypter::new(cipher, Mode::Decrypt, key, Some(&tail.nonce))
            .map_err(|_| Error::DecryptionFailed)?;
        decrypter
            .set_tag(&tail.tag)
            .map_err(|_| Error::DecryptionFailed)?;

        let text_len = payload_len - StandardAeadTail::SIZE;
        let mut output = vec![0; text_len + cipher.block_size()];
        let mut written = decrypter
            .update(&packet.payload()[..text_len], &mut output)
            .map_err(|_| Error::DecryptionFailed)?;
        written += decrypter
            .finalize(&mut output[written..])
            .map_err(|_| Error::DecryptionFailed)?;

        packet.mut_payload()[..written].copy_from_slice(&output[..written]);
        packet
            .mut_peer_manager_header()
            .unwrap()
            .set_encrypted(false);
        let old_len = packet.buf_len();
        packet
            .mut_inner()
            .truncate(old_len - (payload_len - written));
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

        let (cipher, key) = self.cipher_and_key();
        let mut tail = StandardAeadTail::new_zeroed();
        match nonce {
            Some(nonce) => {
                tail.nonce = nonce.try_into().map_err(|_| Error::EncryptionFailed)?;
            }
            None => rand::thread_rng().fill_bytes(&mut tail.nonce),
        }

        let mut encrypter = Crypter::new(cipher, Mode::Encrypt, key, Some(&tail.nonce))
            .map_err(|_| Error::EncryptionFailed)?;
        let payload_len = packet.payload().len();
        let mut output = vec![0; payload_len + cipher.block_size()];
        let mut written = encrypter
            .update(packet.payload(), &mut output)
            .map_err(|_| Error::EncryptionFailed)?;
        written += encrypter
            .finalize(&mut output[written..])
            .map_err(|_| Error::EncryptionFailed)?;
        packet.mut_payload()[..written].copy_from_slice(&output[..written]);
        encrypter
            .get_tag(&mut tail.tag)
            .map_err(|_| Error::EncryptionFailed)?;

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

    fn round_trip(cipher: OpenSslCipher) {
        let plaintext = b"openssl accelerated packet";
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
    fn openssl_algorithms_round_trip() {
        round_trip(OpenSslCipher::new_aes128_gcm([1; 16]));
        round_trip(OpenSslCipher::new_aes256_gcm([2; 32]));
        round_trip(OpenSslCipher::new_chacha20([3; 32]));
    }
}
