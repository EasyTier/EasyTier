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

    #[test]
    fn test_hybrid_root_key_output_length() {
        let key = hybrid_root_key([0x01; 32], [0x02; 32]);
        assert_eq!(key.len(), 32);
    }

    #[test]
    fn test_hybrid_root_key_not_identity() {
        // Output must not equal either input.
        let noise_key = [0xAA; 32];
        let pq_ss = [0xBB; 32];
        let key = hybrid_root_key(noise_key, pq_ss);
        assert_ne!(key, noise_key);
        assert_ne!(key, pq_ss);
    }

    #[test]
    fn test_hybrid_root_key_not_commutative() {
        // Swapping noise_key and pq_ss must produce a different result,
        // confirming the two roles are distinct in the HKDF construction.
        let a = [0xAA; 32];
        let b = [0xBB; 32];
        assert_ne!(hybrid_root_key(a, b), hybrid_root_key(b, a));
    }

    #[test]
    fn test_hybrid_root_key_zero_inputs() {
        // All-zero inputs are valid; the function must not panic and must
        // still produce a non-zero output (HKDF expands to non-trivial bytes).
        let key = hybrid_root_key([0u8; 32], [0u8; 32]);
        assert_eq!(key.len(), 32);
        // The HKDF output for all-zero inputs is a well-defined non-zero value.
        assert_ne!(key, [0u8; 32]);
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

    #[cfg(feature = "pq-kem")]
    #[test]
    fn test_kem_invalid_ek_length() {
        // Encapsulation with an undersized key must return an error, not panic.
        let err = kem::encapsulate(&[0u8; 32]);
        assert!(err.is_err());
    }

    #[cfg(feature = "pq-kem")]
    #[test]
    fn test_kem_invalid_ct_length() {
        // Decapsulation with an undersized ciphertext must return an error.
        let kp = kem::generate_keypair();
        let err = kem::decapsulate(&kp, &[0u8; 32]);
        assert!(err.is_err());
    }

    #[cfg(feature = "pq-kem")]
    #[test]
    fn test_kem_different_keypairs_produce_different_secrets() {
        let kp1 = kem::generate_keypair();
        let kp2 = kem::generate_keypair();

        let (ss1, _ct1) = kem::encapsulate(&kp1.ek_bytes).unwrap();
        let (ss2, _ct2) = kem::encapsulate(&kp2.ek_bytes).unwrap();

        // Two independent keypairs must yield different shared secrets.
        assert_ne!(ss1, ss2);
    }

    #[cfg(feature = "pq-kem")]
    #[test]
    fn test_kem_ciphertext_for_wrong_keypair_differs() {
        // Decapsulating a ciphertext with the wrong keypair must not yield
        // the same shared secret (implicit-rejection property of ML-KEM).
        let kp1 = kem::generate_keypair();
        let kp2 = kem::generate_keypair();

        let (ss_correct, ct) = kem::encapsulate(&kp1.ek_bytes).unwrap();
        // ML-KEM uses implicit rejection: decapsulation with the wrong key
        // succeeds but returns a pseudo-random value that differs from the
        // genuine shared secret.
        let ss_wrong = kem::decapsulate(&kp2, &ct).unwrap();
        assert_ne!(ss_correct, ss_wrong);
    }

    #[cfg(feature = "pq-kem")]
    #[test]
    fn test_kem_shared_secret_length() {
        let kp = kem::generate_keypair();
        let (ss_server, ct) = kem::encapsulate(&kp.ek_bytes).unwrap();
        let ss_client = kem::decapsulate(&kp, &ct).unwrap();
        assert_eq!(ss_server.len(), 32);
        assert_eq!(ss_client.len(), 32);
    }

    #[cfg(feature = "pq-kem")]
    #[test]
    fn test_kem_hybrid_integration() {
        // Full end-to-end: KEM roundtrip feeds into hybrid_root_key, and both
        // sides must arrive at the same hybrid key given the same noise root key.
        let kp = kem::generate_keypair();
        let (ss_server, ct) = kem::encapsulate(&kp.ek_bytes).unwrap();
        let ss_client = kem::decapsulate(&kp, &ct).unwrap();

        let noise_root_key = [0x42u8; 32];
        let hybrid_server = hybrid_root_key(noise_root_key, ss_server);
        let hybrid_client = hybrid_root_key(noise_root_key, ss_client);

        assert_eq!(hybrid_server, hybrid_client);
        // The hybrid key must differ from the raw noise root key.
        assert_ne!(hybrid_server, noise_root_key);
    }
}
