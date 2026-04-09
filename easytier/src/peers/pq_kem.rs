use hmac::{Hmac, Mac as _};
use sha2::Sha256;

type HmacSha256 = Hmac<Sha256>;

/// Combine a Noise-derived root key with a post-quantum shared secret via HKDF-SHA256
/// to produce a hybrid root key. Security holds if either X25519 or ML-KEM is unbroken.
pub fn hybrid_root_key(noise_root_key: [u8; 32], pq_shared_secret: [u8; 32]) -> [u8; 32] {
    // HKDF-Extract: PRK = HMAC-SHA256(salt=pq_shared_secret, IKM=noise_root_key)
    let mut extract = HmacSha256::new_from_slice(&pq_shared_secret).unwrap();
    extract.update(&noise_root_key);
    let prk = extract.finalize().into_bytes();

    // HKDF-Expand: OKM = HMAC-SHA256(PRK, info || 0x01)
    let mut expand = HmacSha256::new_from_slice(&prk).unwrap();
    expand.update(b"et-pq-hybrid");
    expand.update(&[1u8]);
    let okm = expand.finalize().into_bytes();

    let mut key = [0u8; 32];
    key.copy_from_slice(&okm[..32]);
    key
}

#[cfg(feature = "pq-kem")]
pub mod kem {
    use ml_kem::kem::{Decapsulate, Encapsulate};
    use ml_kem::{Ciphertext, EncodedSizeUser, KemCore, MlKem768, MlKem768Params, SharedKey};

    /// ML-KEM-768 encapsulation key size in bytes.
    pub const EK_LEN: usize = 1184;
    /// ML-KEM-768 ciphertext size in bytes.
    pub const CT_LEN: usize = 1088;

    /// Client-side state held between Msg1 (send ek) and Msg2 (receive ct).
    pub struct PqKeyPair {
        dk: ml_kem::kem::DecapsulationKey<MlKem768Params>,
        pub ek_bytes: Vec<u8>,
    }

    /// Generate an ML-KEM-768 keypair. Returns a `PqKeyPair` whose `ek_bytes`
    /// should be sent to the peer in the handshake message.
    pub fn generate_keypair() -> PqKeyPair {
        let (dk, ek) = MlKem768::generate(&mut rand::rngs::OsRng);
        let ek_bytes = ek.as_bytes().to_vec();
        PqKeyPair { dk, ek_bytes }
    }

    /// Server-side: encapsulate a shared secret using the client's encapsulation key.
    /// Returns `(shared_secret, ciphertext_bytes)`.
    pub fn encapsulate(ek_bytes: &[u8]) -> Result<([u8; 32], Vec<u8>), &'static str> {
        use ml_kem::kem::EncapsulationKey;
        if ek_bytes.len() != EK_LEN {
            return Err("invalid ek length");
        }
        let ek_array = ml_kem::Encoded::<EncapsulationKey<MlKem768Params>>::try_from(ek_bytes)
            .map_err(|_| "invalid ek length")?;
        let ek = EncapsulationKey::<MlKem768Params>::from_bytes(&ek_array);
        let (ct, ss): (Ciphertext<MlKem768>, SharedKey<MlKem768>) = ek
            .encapsulate(&mut rand::rngs::OsRng)
            .map_err(|_| "encapsulation failed")?;
        let mut ss_out = [0u8; 32];
        ss_out.copy_from_slice(ss.as_slice());
        Ok((ss_out, ct.as_slice().to_vec()))
    }

    /// Client-side: decapsulate using our decapsulation key and the server's ciphertext.
    /// Returns the shared secret.
    pub fn decapsulate(kp: &PqKeyPair, ct_bytes: &[u8]) -> Result<[u8; 32], &'static str> {
        if ct_bytes.len() != CT_LEN {
            return Err("invalid ct length");
        }
        let ct: Ciphertext<MlKem768> =
            Ciphertext::<MlKem768>::try_from(ct_bytes).map_err(|_| "invalid ct length")?;
        let ss: SharedKey<MlKem768> = kp.dk.decapsulate(&ct).map_err(|_| "decapsulation failed")?;
        let mut ss_out = [0u8; 32];
        ss_out.copy_from_slice(ss.as_slice());
        Ok(ss_out)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_hybrid_root_key_deterministic() {
        let noise_key = [0xAA; 32];
        let pq_ss = [0xBB; 32];
        let h1 = hybrid_root_key(noise_key, pq_ss);
        let h2 = hybrid_root_key(noise_key, pq_ss);
        assert_eq!(h1, h2);
        // Different inputs produce different outputs.
        assert_ne!(h1, hybrid_root_key([0xCC; 32], pq_ss));
        assert_ne!(h1, hybrid_root_key(noise_key, [0xCC; 32]));
    }

    #[cfg(feature = "pq-kem")]
    #[test]
    fn test_kem_roundtrip() {
        let kp = kem::generate_keypair();
        assert_eq!(kp.ek_bytes.len(), kem::EK_LEN);

        let (ss_server, ct) = kem::encapsulate(&kp.ek_bytes).unwrap();
        assert_eq!(ct.len(), kem::CT_LEN);

        let ss_client = kem::decapsulate(&kp, &ct).unwrap();
        assert_eq!(ss_server, ss_client);
    }
}
