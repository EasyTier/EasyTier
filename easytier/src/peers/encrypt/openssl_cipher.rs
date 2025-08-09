use openssl::symm::{Cipher, Crypter, Mode};
use rand::RngCore;
use zerocopy::{AsBytes, FromBytes, FromZeroes};

use crate::tunnel::packet_def::ZCPacket;

use crate::peers::encrypt::{Encryptor, Error};

// OpenSSL 加密尾部结构
#[repr(C, packed)]
#[derive(AsBytes, FromBytes, FromZeroes, Clone, Debug, Default)]
pub struct OpenSslTail {
    pub nonce: [u8; 16], // 使用 16 字节的 nonce/IV
}

pub const OPENSSL_ENCRYPTION_RESERVED: usize = std::mem::size_of::<OpenSslTail>();

#[derive(Clone)]
pub struct OpenSslCipher {
    pub(crate) cipher: OpenSslEnum,
}

pub enum OpenSslEnum {
    Aes128Gcm([u8; 16]),
    Aes256Gcm([u8; 32]),
    Chacha20([u8; 32]),
}

impl Clone for OpenSslEnum {
    fn clone(&self) -> Self {
        match &self {
            OpenSslEnum::Aes128Gcm(key) => OpenSslEnum::Aes128Gcm(*key),
            OpenSslEnum::Aes256Gcm(key) => OpenSslEnum::Aes256Gcm(*key),
            OpenSslEnum::Chacha20(key) => OpenSslEnum::Chacha20(*key),
        }
    }
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
            cipher: OpenSslEnum::Chacha20(key),
        }
    }

    fn get_cipher_and_key(&self) -> (Cipher, &[u8]) {
        match &self.cipher {
            OpenSslEnum::Aes128Gcm(key) => (Cipher::aes_128_gcm(), key.as_slice()),
            OpenSslEnum::Aes256Gcm(key) => (Cipher::aes_256_gcm(), key.as_slice()),
            OpenSslEnum::Chacha20(key) => (Cipher::chacha20_poly1305(), key.as_slice()),
        }
    }

    fn is_aead_cipher(&self) -> bool {
        matches!(
            self.cipher,
            OpenSslEnum::Aes128Gcm(_) | OpenSslEnum::Aes256Gcm(_) | OpenSslEnum::Chacha20(_)
        )
    }

    fn get_nonce_size(&self) -> usize {
        match &self.cipher {
            OpenSslEnum::Aes128Gcm(_) | OpenSslEnum::Aes256Gcm(_) | OpenSslEnum::Chacha20(_) => 12, // GCM and ChaCha20-Poly1305 use 12-byte nonce
        }
    }
}

impl Encryptor for OpenSslCipher {
    fn decrypt(&self, zc_packet: &mut ZCPacket) -> Result<(), Error> {
        let pm_header = zc_packet.peer_manager_header().unwrap();
        if !pm_header.is_encrypted() {
            return Ok(());
        }

        let payload_len = zc_packet.payload().len();
        if payload_len < OPENSSL_ENCRYPTION_RESERVED {
            return Err(Error::PacketTooShort(zc_packet.payload().len()));
        }

        let (cipher, key) = self.get_cipher_and_key();
        let is_aead = self.is_aead_cipher();
        let nonce_size = self.get_nonce_size();

        // 提取 nonce/IV
        let openssl_tail = OpenSslTail::ref_from_suffix(zc_packet.payload())
            .unwrap()
            .clone();

        let text_len = if is_aead {
            payload_len - OPENSSL_ENCRYPTION_RESERVED - 16 // AEAD 需要减去 tag 长度
        } else {
            payload_len - OPENSSL_ENCRYPTION_RESERVED
        };

        let mut decrypter = Crypter::new(
            cipher,
            Mode::Decrypt,
            key,
            Some(&openssl_tail.nonce[..nonce_size]),
        )
        .map_err(|_| Error::DecryptionFailed)?;

        if is_aead {
            // 对于 AEAD 模式，需要设置 tag
            let tag_start = text_len;
            let tag = &zc_packet.payload()[tag_start..tag_start + 16];
            decrypter
                .set_tag(tag)
                .map_err(|_| Error::DecryptionFailed)?;
        }

        let mut output = vec![0u8; text_len + cipher.block_size()];
        let mut count = decrypter
            .update(&zc_packet.payload()[..text_len], &mut output)
            .map_err(|_| Error::DecryptionFailed)?;

        count += decrypter
            .finalize(&mut output[count..])
            .map_err(|_| Error::DecryptionFailed)?;

        // 更新数据包
        zc_packet.mut_payload()[..count].copy_from_slice(&output[..count]);
        let pm_header = zc_packet.mut_peer_manager_header().unwrap();
        pm_header.set_encrypted(false);
        let old_len = zc_packet.buf_len();
        let new_len = old_len - (payload_len - count);
        zc_packet.mut_inner().truncate(new_len);

        Ok(())
    }

    fn encrypt(&self, zc_packet: &mut ZCPacket) -> Result<(), Error> {
        let pm_header = zc_packet.peer_manager_header().unwrap();
        if pm_header.is_encrypted() {
            tracing::warn!(?zc_packet, "packet is already encrypted");
            return Ok(());
        }

        let (cipher, key) = self.get_cipher_and_key();
        let is_aead = self.is_aead_cipher();
        let nonce_size = self.get_nonce_size();

        let mut tail = OpenSslTail::default();
        rand::thread_rng().fill_bytes(&mut tail.nonce[..nonce_size]);

        let mut encrypter =
            Crypter::new(cipher, Mode::Encrypt, key, Some(&tail.nonce[..nonce_size]))
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

        // 对于 AEAD 模式，添加 tag
        if is_aead {
            let mut tag = vec![0u8; 16]; // GCM 标签通常是 16 字节
            encrypter
                .get_tag(&mut tag)
                .map_err(|_| Error::EncryptionFailed)?;
            zc_packet.mut_inner().extend_from_slice(&tag);
        }

        // 添加 nonce/IV
        zc_packet.mut_inner().extend_from_slice(tail.as_bytes());

        let pm_header = zc_packet.mut_peer_manager_header().unwrap();
        pm_header.set_encrypted(true);

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use crate::{
        peers::encrypt::{openssl_cipher::OpenSslCipher, Encryptor},
        tunnel::packet_def::ZCPacket,
    };

    use super::OPENSSL_ENCRYPTION_RESERVED;

    #[test]
    fn test_openssl_aes128_gcm() {
        let key = [0u8; 16];
        let cipher = OpenSslCipher::new_aes128_gcm(key);
        let text = b"Hello, World! This is a test message for OpenSSL AES-128-GCM.";
        let mut packet = ZCPacket::new_with_payload(text);
        packet.fill_peer_manager_hdr(0, 0, 0);

        // 加密
        cipher.encrypt(&mut packet).unwrap();
        assert!(packet.payload().len() > text.len() + OPENSSL_ENCRYPTION_RESERVED);
        assert_eq!(packet.peer_manager_header().unwrap().is_encrypted(), true);

        // 解密
        cipher.decrypt(&mut packet).unwrap();
        assert_eq!(packet.payload(), text);
        assert_eq!(packet.peer_manager_header().unwrap().is_encrypted(), false);
    }

    #[test]
    fn test_openssl_chacha20() {
        let key = [0u8; 32];
        let cipher = OpenSslCipher::new_chacha20(key);
        let text = b"Hello, World! This is a test message for OpenSSL ChaCha20.";
        let mut packet = ZCPacket::new_with_payload(text);
        packet.fill_peer_manager_hdr(0, 0, 0);

        // 加密
        cipher.encrypt(&mut packet).unwrap();
        assert!(packet.payload().len() > text.len());
        assert_eq!(packet.peer_manager_header().unwrap().is_encrypted(), true);

        // 解密
        cipher.decrypt(&mut packet).unwrap();
        assert_eq!(packet.payload(), text);
        assert_eq!(packet.peer_manager_header().unwrap().is_encrypted(), false);
    }
}
