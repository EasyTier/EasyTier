use rand::RngCore;
use zerocopy::{AsBytes, FromBytes, FromZeroes};

use crate::tunnel::packet_def::ZCPacket;

use super::{Encryptor, Error};

// ChaCha20 尾部结构，只需要存储 nonce
#[repr(C, packed)]
#[derive(AsBytes, FromBytes, FromZeroes, Clone, Debug, Default)]
pub struct ChaCha20Tail {
    pub nonce: [u8; 12],
}

pub const CHACHA20_ENCRYPTION_RESERVED: usize = std::mem::size_of::<ChaCha20Tail>();

#[derive(Clone)]
pub struct ChaCha20Cipher {
    pub(crate) cipher: ChaCha20Enum,
}

pub enum ChaCha20Enum {
    ChaCha20([u8; 32]),
}

impl Clone for ChaCha20Enum {
    fn clone(&self) -> Self {
        match &self {
            ChaCha20Enum::ChaCha20(key) => ChaCha20Enum::ChaCha20(*key),
        }
    }
}

impl ChaCha20Cipher {
    pub fn new(key: [u8; 32]) -> Self {
        Self {
            cipher: ChaCha20Enum::ChaCha20(key),
        }
    }

    fn encrypt_decrypt_data(&self, data: &mut [u8], nonce: &[u8; 12]) -> Result<(), Error> {
        use chacha20::cipher::{KeyIvInit, StreamCipher};
        use chacha20::{ChaCha20, Key, Nonce};

        match &self.cipher {
            ChaCha20Enum::ChaCha20(key) => {
                let key = Key::from_slice(key);
                let nonce = Nonce::from_slice(nonce);
                let mut cipher = ChaCha20::new(key, nonce);
                cipher.apply_keystream(data);
                Ok(())
            }
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
        if payload_len < CHACHA20_ENCRYPTION_RESERVED {
            return Err(Error::PacketTooShort(zc_packet.payload().len()));
        }

        let text_len = payload_len - CHACHA20_ENCRYPTION_RESERVED;

        // 提取 nonce
        let chacha20_tail = ChaCha20Tail::ref_from_suffix(zc_packet.payload())
            .unwrap()
            .clone();

        // 解密数据
        self.encrypt_decrypt_data(
            &mut zc_packet.mut_payload()[..text_len], 
            &chacha20_tail.nonce
        )?;

        let pm_header = zc_packet.mut_peer_manager_header().unwrap();
        pm_header.set_encrypted(false);
        let old_len = zc_packet.buf_len();
        zc_packet
            .mut_inner()
            .truncate(old_len - CHACHA20_ENCRYPTION_RESERVED);
        
        Ok(())
    }

    fn encrypt(&self, zc_packet: &mut ZCPacket) -> Result<(), Error> {
        let pm_header = zc_packet.peer_manager_header().unwrap();
        if pm_header.is_encrypted() {
            tracing::warn!(?zc_packet, "packet is already encrypted");
            return Ok(());
        }

        let mut tail = ChaCha20Tail::default();
        rand::thread_rng().fill_bytes(&mut tail.nonce);

        // 加密数据
        self.encrypt_decrypt_data(zc_packet.mut_payload(), &tail.nonce)?;

        let pm_header = zc_packet.mut_peer_manager_header().unwrap();
        pm_header.set_encrypted(true);
        zc_packet.mut_inner().extend_from_slice(tail.as_bytes());

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use crate::{
        peers::encrypt::{chacha20_cipher::ChaCha20Cipher, Encryptor},
        tunnel::packet_def::ZCPacket,
    };

    use super::CHACHA20_ENCRYPTION_RESERVED;

    #[test]
    fn test_chacha20_cipher() {
        let key = [0u8; 32];
        let cipher = ChaCha20Cipher::new(key);
        let text = b"Hello, World! This is a test message for ChaCha20.";
        let mut packet = ZCPacket::new_with_payload(text);
        packet.fill_peer_manager_hdr(0, 0, 0);
        
        // 加密
        cipher.encrypt(&mut packet).unwrap();
        assert_eq!(
            packet.payload().len(),
            text.len() + CHACHA20_ENCRYPTION_RESERVED
        );
        assert_eq!(packet.peer_manager_header().unwrap().is_encrypted(), true);

        // 解密
        cipher.decrypt(&mut packet).unwrap();
        assert_eq!(packet.payload(), text);
        assert_eq!(packet.peer_manager_header().unwrap().is_encrypted(), false);
    }
}
