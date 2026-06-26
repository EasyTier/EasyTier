use crate::tunnel::packet_def::{StandardAeadTail, ZCPacket};
use openssl::symm::{Cipher, Crypter, Mode};
use rand::RngCore;
use zerocopy::{AsBytes, FromBytes, FromZeroes};

use crate::peers::encrypt::{Encryptor, Error};

#[derive(Clone)]
pub struct OpenSslCipher {
    pub(crate) cipher: OpenSslEnum,
}

#[derive(Clone, Copy)]
pub enum OpenSslEnum {
    Aes128Gcm([u8; 16]),
    Aes256Gcm([u8; 32]),
    ChaCha20([u8; 32]),
}

impl OpenSslCipher {
    pub fn new_aes128_gcm(key: [u8; 16]) -> Self {
        Self {
            cipher: OpenSslEnum::Aes128Gcm(key),
        }
    }

    pub fn new_aes256_gcm(key: [u8; 32]) -> Self {
        Self {
            cipher: OpenSslEnum::Aes256Gcm(key),
        }
    }

    pub fn new_chacha20(key: [u8; 32]) -> Self {
        Self {
            cipher: OpenSslEnum::ChaCha20(key),
        }
    }

    fn get_cipher_and_key(&self) -> (Cipher, &[u8]) {
        match &self.cipher {
            OpenSslEnum::Aes128Gcm(key) => (Cipher::aes_128_gcm(), key.as_slice()),
            OpenSslEnum::Aes256Gcm(key) => (Cipher::aes_256_gcm(), key.as_slice()),
            OpenSslEnum::ChaCha20(key) => (Cipher::chacha20_poly1305(), key.as_slice()),
        }
    }
}

impl Encryptor for OpenSslCipher {
    fn decrypt(&self, zc_packet: &mut ZCPacket) -> Result<(), Error> {
        let pm_header = zc_packet.peer_manager_header().unwrap();
        if !pm_header.is_encrypted() {
            return Ok(());
        }

        let payload = zc_packet.payload();
        let len = payload.len();
        if len < StandardAeadTail::SIZE {
            return Err(Error::PacketTooShort(len));
        }

        let (cipher, key) = self.get_cipher_and_key();

        // 提取 nonce/IV 和 tag
        let tail = StandardAeadTail::ref_from_suffix(payload).unwrap();

        let mut decrypter = Crypter::new(cipher, Mode::Decrypt, key, Some(&tail.nonce))
            .map_err(|_| Error::DecryptionFailed)?;

        decrypter
            .set_tag(&tail.tag)
            .map_err(|_| Error::DecryptionFailed)?;

        let text_len = len - StandardAeadTail::SIZE;
        let mut output = vec![0u8; text_len + cipher.block_size()];
        let mut count = decrypter
            .update(&payload[..text_len], &mut output)
            .map_err(|_| Error::DecryptionFailed)?;

        count += decrypter
            .finalize(&mut output[count..])
            .map_err(|_| Error::DecryptionFailed)?;

        // 更新数据包
        zc_packet.mut_payload()[..count].copy_from_slice(&output[..count]);
        let pm_header = zc_packet.mut_peer_manager_header().unwrap();
        pm_header.set_encrypted(false);

        let len = zc_packet.buf_len() - (len - count);
        zc_packet.mut_inner().truncate(len);

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

        let (cipher, key) = self.get_cipher_and_key();

        let mut tail = StandardAeadTail::new_zeroed();
        if let Some(nonce) = nonce {
            if nonce.len() != StandardAeadTail::NONCE_SIZE {
                return Err(Error::EncryptionFailed);
            }
            tail.nonce.copy_from_slice(nonce);
        } else {
            rand::thread_rng().fill_bytes(&mut tail.nonce);
        }

        let mut encrypter = Crypter::new(cipher, Mode::Encrypt, key, Some(&tail.nonce))
            .map_err(|_| Error::EncryptionFailed)?;

        let payload_len = zc_packet.payload().len();
        let mut output = vec![0u8; payload_len + cipher.block_size()];

        let mut count = encrypter
            .update(zc_packet.payload(), &mut output)
            .map_err(|_| Error::EncryptionFailed)?;

        count += encrypter
            .finalize(&mut output[count..])
            .map_err(|_| Error::EncryptionFailed)?;

        // 更新数据包内容
        zc_packet.mut_payload()[..count].copy_from_slice(&output[..count]);

        encrypter
            .get_tag(&mut tail.tag)
            .map_err(|_| Error::EncryptionFailed)?;

        // 添加 nonce/IV & tag 的结构
        zc_packet.mut_inner().extend_from_slice(tail.as_bytes());

        let pm_header = zc_packet.mut_peer_manager_header().unwrap();
        pm_header.set_encrypted(true);

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn run_cipher_test_with_nonce(cipher: OpenSslCipher) {
        let text = b"Hello, World! This is a standardized test message.";
        let nonce: [u8; 12] = [101, 102, 103, 104, 105, 106, 107, 108, 109, 110, 111, 112];

        let mut packet = ZCPacket::new_with_payload(text);
        packet.fill_peer_manager_hdr(0, 0, 0);

        cipher
            .encrypt_with_nonce(&mut packet, Some(&nonce))
            .unwrap();

        let payload = packet.payload();
        let len = payload.len();

        assert!(len > text.len() + StandardAeadTail::SIZE - 1);
        assert!(packet.peer_manager_header().unwrap().is_encrypted());

        let tail = StandardAeadTail::ref_from_suffix(payload).unwrap().clone();
        assert_eq!(tail.nonce, nonce);

        cipher.decrypt(&mut packet).unwrap();
        assert_eq!(packet.payload(), text);
        assert!(!packet.peer_manager_header().unwrap().is_encrypted());
    }

    #[test]
    fn test_openssl_aes128_gcm() {
        let key = [1u8; 16];
        let cipher = OpenSslCipher::new_aes128_gcm(key);
        run_cipher_test_with_nonce(cipher);
    }

    #[test]
    fn test_openssl_aes256_gcm() {
        let key = [2u8; 32];
        let cipher = OpenSslCipher::new_aes256_gcm(key);
        run_cipher_test_with_nonce(cipher);
    }

    #[test]
    fn test_openssl_chacha20() {
        let key = [3u8; 32];
        let cipher = OpenSslCipher::new_chacha20(key);
        run_cipher_test_with_nonce(cipher);
    }
}
