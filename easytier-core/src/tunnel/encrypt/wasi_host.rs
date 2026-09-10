use std::sync::Arc;

use rand::RngCore as _;
use zerocopy::FromBytes as _;

use crate::{
    config::EncryptionAlgorithm,
    packet::{StandardAeadTail, ZCPacket},
    wasi::{
        abi::{
            AEAD_AES_128_GCM, AEAD_AES_256_GCM, AEAD_CHACHA20_POLY1305, HOST_CRYPTO_AUTH_FAILED,
        },
        imports::{crypto_aead_open, crypto_aead_seal},
    },
};

use super::{Encryptor, Error};

pub(super) struct WasiHostAead {
    algorithm: u32,
    key: Box<[u8]>,
    fallback: Arc<dyn Encryptor>,
}

impl WasiHostAead {
    pub(super) fn new(
        algorithm: EncryptionAlgorithm,
        key: &[u8],
        fallback: Arc<dyn Encryptor>,
    ) -> Self {
        let algorithm = match algorithm {
            EncryptionAlgorithm::AesGcm => AEAD_AES_128_GCM,
            EncryptionAlgorithm::Aes256Gcm => AEAD_AES_256_GCM,
            EncryptionAlgorithm::ChaCha20 => AEAD_CHACHA20_POLY1305,
            EncryptionAlgorithm::Xor => unreachable!("XOR is not an AEAD algorithm"),
        };
        Self {
            algorithm,
            key: key.into(),
            fallback,
        }
    }

    fn call(
        &self,
        open: bool,
        nonce: &[u8; StandardAeadTail::NONCE_SIZE],
        buffer: &mut [u8],
        text_len: usize,
    ) -> i32 {
        let key_len = u32::try_from(self.key.len()).expect("AEAD keys fit u32");
        let nonce_len = u32::try_from(nonce.len()).expect("AEAD nonces fit u32");
        let text_len = u32::try_from(text_len).expect("packet payloads fit u32");
        let function = if open {
            crypto_aead_open
        } else {
            crypto_aead_seal
        };
        unsafe {
            function(
                self.algorithm,
                self.key.as_ptr() as u32,
                key_len,
                nonce.as_ptr() as u32,
                nonce_len,
                0,
                0,
                buffer.as_mut_ptr() as u32,
                text_len,
            )
        }
    }
}

impl Encryptor for WasiHostAead {
    fn decrypt(&self, packet: &mut ZCPacket) -> Result<(), Error> {
        let header = packet.peer_manager_header().unwrap();
        if !header.is_encrypted() {
            return Ok(());
        }

        let payload_len = packet.payload().len();
        if payload_len < StandardAeadTail::SIZE {
            return Err(Error::PacketTooShort(payload_len));
        }

        let text_len = payload_len - StandardAeadTail::SIZE;
        let tail = StandardAeadTail::ref_from_suffix(packet.payload())
            .unwrap()
            .clone();
        let status = self.call(
            true,
            &tail.nonce,
            &mut packet.mut_payload()[..text_len + StandardAeadTail::TAG_SIZE],
            text_len,
        );
        if status == HOST_CRYPTO_AUTH_FAILED {
            return Err(Error::DecryptionFailed);
        }
        if status != 0 {
            return self.fallback.decrypt(packet);
        }

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

        let mut nonce_bytes = [0; StandardAeadTail::NONCE_SIZE];
        match nonce {
            Some(nonce) => {
                nonce_bytes = nonce.try_into().map_err(|_| Error::EncryptionFailed)?;
            }
            None => rand::thread_rng().fill_bytes(&mut nonce_bytes),
        }

        let text_len = packet.payload().len();
        let old_len = packet.buf_len();
        packet
            .mut_inner()
            .extend_from_slice(&[0; StandardAeadTail::TAG_SIZE]);
        let status = self.call(false, &nonce_bytes, packet.mut_payload(), text_len);
        if status != 0 {
            packet.mut_inner().truncate(old_len);
            return self.fallback.encrypt_with_nonce(packet, Some(&nonce_bytes));
        }

        packet.mut_inner().extend_from_slice(&nonce_bytes);
        packet
            .mut_peer_manager_header()
            .unwrap()
            .set_encrypted(true);
        Ok(())
    }
}
