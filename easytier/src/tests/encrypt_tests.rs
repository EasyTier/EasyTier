//! Encryption module tests
//!
//! This module contains comprehensive tests for the encryption functionality,
//! including AES-GCM cipher tests and NullCipher tests.
//!
//! ## Auto-compatibility
//! The performance tests automatically iterate over all available encryption algorithms.
//! When adding a new algorithm, simply add it to the `get_all_encryptors()` function.

use std::sync::Arc;

use crate::{
    peers::encrypt::{Encryptor, NullCipher},
    tunnel::packet_def::{ZCPacket, AES_GCM_ENCRYPTION_RESERVED},
};

#[cfg(feature = "aes-gcm")]
use crate::peers::encrypt::aes_gcm::AesGcmCipher as AesGcmCipherCrate;

#[cfg(feature = "wireguard")]
use crate::peers::encrypt::ring_aes_gcm::AesGcmCipher as RingAesGcmCipher;

#[cfg(feature = "wireguard")]
use crate::peers::encrypt::ring_chacha20::RingChaCha20Cipher;

// ==================== Algorithm Registry ====================

/// Encryptor configuration for auto-discovery testing
pub struct EncryptorConfig {
    /// Display name for the algorithm
    pub name: &'static str,
    /// The encryptor instance
    pub encryptor: Arc<dyn Encryptor>,
    /// Whether this algorithm is suitable for performance testing
    pub perf_testable: bool,
}

/// Returns all available encryptors for testing.
///
/// ## Adding New Algorithms
/// When adding a new encryption algorithm, add it to this function:
/// 1. Add the appropriate #[cfg(feature = "...")] guard
/// 2. Create the encryptor instance with test keys
/// 3. Add it to the list with appropriate metadata
///
/// The performance tests will automatically pick up the new algorithm.
pub fn get_all_encryptors() -> Vec<EncryptorConfig> {
    let key_128 = [42u8; 16];
    let key_256 = [42u8; 32];

    let mut encryptors = Vec::new();

    // NullCipher - always available but not suitable for perf testing
    encryptors.push(EncryptorConfig {
        name: "NullCipher",
        encryptor: Arc::new(NullCipher),
        perf_testable: false,
    });

    // Ring AES-GCM implementations (wireguard feature)
    #[cfg(feature = "wireguard")]
    {
        encryptors.push(EncryptorConfig {
            name: "Ring-AES-128-GCM",
            encryptor: Arc::new(RingAesGcmCipher::new_128(key_128)),
            perf_testable: true,
        });
        encryptors.push(EncryptorConfig {
            name: "Ring-AES-256-GCM",
            encryptor: Arc::new(RingAesGcmCipher::new_256(key_256)),
            perf_testable: true,
        });
        encryptors.push(EncryptorConfig {
            name: "Ring-ChaCha20",
            encryptor: Arc::new(RingChaCha20Cipher::new(key_256)),
            perf_testable: true,
        });
    }

    // aes-gcm crate implementations
    #[cfg(feature = "aes-gcm")]
    {
        encryptors.push(EncryptorConfig {
            name: "Crate-AES-128-GCM",
            encryptor: Arc::new(AesGcmCipherCrate::new_128(key_128)),
            perf_testable: true,
        });
        encryptors.push(EncryptorConfig {
            name: "Crate-AES-256-GCM",
            encryptor: Arc::new(AesGcmCipherCrate::new_256(key_256)),
            perf_testable: true,
        });
    }

    // OpenSSL implementations
    #[cfg(feature = "openssl-crypto")]
    {
        use crate::peers::encrypt::openssl_cipher::OpenSslCipher;
        encryptors.push(EncryptorConfig {
            name: "OpenSSL-AES-128-GCM",
            encryptor: Arc::new(OpenSslCipher::new_aes128_gcm(key_128)),
            perf_testable: true,
        });
        encryptors.push(EncryptorConfig {
            name: "OpenSSL-AES-256-GCM",
            encryptor: Arc::new(OpenSslCipher::new_aes256_gcm(key_256)),
            perf_testable: true,
        });
        encryptors.push(EncryptorConfig {
            name: "OpenSSL-ChaCha20",
            encryptor: Arc::new(OpenSslCipher::new_chacha20(key_256)),
            perf_testable: true,
        });
    }

    // XOR cipher (always available, simple but not secure)
    {
        use crate::peers::encrypt::xor_cipher::XorCipher;
        encryptors.push(EncryptorConfig {
            name: "XOR-Cipher",
            encryptor: Arc::new(XorCipher::new(&key_128)),
            perf_testable: true,
        });
    }

    encryptors
}

/// Returns only encryptors suitable for performance testing
pub fn get_perf_testable_encryptors() -> Vec<EncryptorConfig> {
    get_all_encryptors()
        .into_iter()
        .filter(|e| e.perf_testable)
        .collect()
}

// ==================== NullCipher Tests ====================

#[test]
fn test_null_cipher_encrypt() {
    let cipher = NullCipher;
    let text = b"test data";
    let mut packet = ZCPacket::new_with_payload(text);
    packet.fill_peer_manager_hdr(0, 0, 0);

    // NullCipher encrypt should be a no-op
    cipher.encrypt(&mut packet).unwrap();
    assert_eq!(packet.payload(), text);
    assert_eq!(packet.peer_manager_header().unwrap().is_encrypted(), false);
}

#[test]
fn test_null_cipher_decrypt_unencrypted() {
    let cipher = NullCipher;
    let text = b"test data";
    let mut packet = ZCPacket::new_with_payload(text);
    packet.fill_peer_manager_hdr(0, 0, 0);

    // NullCipher decrypt on unencrypted packet should succeed
    cipher.decrypt(&mut packet).unwrap();
    assert_eq!(packet.payload(), text);
}

#[test]
fn test_null_cipher_decrypt_encrypted_fails() {
    let cipher = NullCipher;
    let text = b"test data";
    let mut packet = ZCPacket::new_with_payload(text);
    packet.fill_peer_manager_hdr(0, 0, 0);
    packet.mut_peer_manager_header().unwrap().set_encrypted(true);

    // NullCipher should fail on encrypted packets
    let result = cipher.decrypt(&mut packet);
    assert!(result.is_err());
}

#[test]
fn test_null_cipher_empty_payload() {
    let cipher = NullCipher;
    let text = b"";
    let mut packet = ZCPacket::new_with_payload(text);
    packet.fill_peer_manager_hdr(0, 0, 0);

    cipher.encrypt(&mut packet).unwrap();
    cipher.decrypt(&mut packet).unwrap();
    assert_eq!(packet.payload(), text);
}

// ==================== AES-GCM Crate Tests ====================

#[cfg(feature = "aes-gcm")]
mod aes_gcm_crate_tests {
    use super::*;

    #[test]
    fn test_aes_128_gcm_basic() {
        let key = [0u8; 16];
        let cipher = AesGcmCipherCrate::new_128(key);
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

    #[test]
    fn test_aes_256_gcm_basic() {
        let key = [0u8; 32];
        let cipher = AesGcmCipherCrate::new_256(key);
        let text = b"test data for aes-256-gcm encryption";
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

    #[test]
    fn test_aes_gcm_empty_payload() {
        let key = [0u8; 16];
        let cipher = AesGcmCipherCrate::new_128(key);
        let text = b"";
        let mut packet = ZCPacket::new_with_payload(text);
        packet.fill_peer_manager_hdr(0, 0, 0);

        cipher.encrypt(&mut packet).unwrap();
        assert_eq!(packet.payload().len(), AES_GCM_ENCRYPTION_RESERVED);
        assert_eq!(packet.peer_manager_header().unwrap().is_encrypted(), true);

        cipher.decrypt(&mut packet).unwrap();
        assert_eq!(packet.payload(), text);
        assert_eq!(packet.peer_manager_header().unwrap().is_encrypted(), false);
    }

    #[test]
    fn test_aes_gcm_large_payload() {
        let key = [0u8; 16];
        let cipher = AesGcmCipherCrate::new_128(key);
        // 64KB data
        let text: Vec<u8> = (0..65536).map(|i| (i % 256) as u8).collect();
        let mut packet = ZCPacket::new_with_payload(&text);
        packet.fill_peer_manager_hdr(0, 0, 0);

        cipher.encrypt(&mut packet).unwrap();
        assert_eq!(
            packet.payload().len(),
            text.len() + AES_GCM_ENCRYPTION_RESERVED
        );
        assert_eq!(packet.peer_manager_header().unwrap().is_encrypted(), true);

        cipher.decrypt(&mut packet).unwrap();
        assert_eq!(packet.payload(), text.as_slice());
        assert_eq!(packet.peer_manager_header().unwrap().is_encrypted(), false);
    }

    #[test]
    fn test_aes_gcm_multiple_encrypt_decrypt() {
        let key = [42u8; 16];
        let cipher = AesGcmCipherCrate::new_128(key);

        for i in 0..10 {
            let text = format!("test message number {}", i);
            let mut packet = ZCPacket::new_with_payload(text.as_bytes());
            packet.fill_peer_manager_hdr(0, 0, 0);

            cipher.encrypt(&mut packet).unwrap();
            assert_eq!(packet.peer_manager_header().unwrap().is_encrypted(), true);

            cipher.decrypt(&mut packet).unwrap();
            assert_eq!(packet.payload(), text.as_bytes());
            assert_eq!(packet.peer_manager_header().unwrap().is_encrypted(), false);
        }
    }

    #[test]
    fn test_aes_gcm_different_keys_produce_different_ciphertext() {
        let key1 = [0u8; 16];
        let key2 = [1u8; 16];
        let cipher1 = AesGcmCipherCrate::new_128(key1);
        let cipher2 = AesGcmCipherCrate::new_128(key2);
        let text = b"same plaintext";

        let mut packet1 = ZCPacket::new_with_payload(text);
        packet1.fill_peer_manager_hdr(0, 0, 0);
        cipher1.encrypt(&mut packet1).unwrap();

        let mut packet2 = ZCPacket::new_with_payload(text);
        packet2.fill_peer_manager_hdr(0, 0, 0);
        cipher2.encrypt(&mut packet2).unwrap();

        // Ciphertexts should be different (with very high probability)
        assert_ne!(packet1.payload(), packet2.payload());
    }

    #[test]
    fn test_aes_gcm_decrypt_unencrypted_packet() {
        let key = [0u8; 16];
        let cipher = AesGcmCipherCrate::new_128(key);
        let text = b"unencrypted data";
        let mut packet = ZCPacket::new_with_payload(text);
        packet.fill_peer_manager_hdr(0, 0, 0);

        // Should not fail when decrypting unencrypted packet
        cipher.decrypt(&mut packet).unwrap();
        assert_eq!(packet.payload(), text);
    }

    #[test]
    fn test_aes_gcm_double_encrypt() {
        let key = [0u8; 16];
        let cipher = AesGcmCipherCrate::new_128(key);
        let text = b"test data";
        let mut packet = ZCPacket::new_with_payload(text);
        packet.fill_peer_manager_hdr(0, 0, 0);

        cipher.encrypt(&mut packet).unwrap();
        let encrypted_len = packet.payload().len();

        // Second encrypt should be a no-op (already encrypted)
        cipher.encrypt(&mut packet).unwrap();
        assert_eq!(packet.payload().len(), encrypted_len);

        cipher.decrypt(&mut packet).unwrap();
        assert_eq!(packet.payload(), text);
    }

    #[test]
    fn test_aes_gcm_wrong_key_decrypt_fails() {
        let key1 = [0u8; 16];
        let key2 = [1u8; 16];
        let cipher1 = AesGcmCipherCrate::new_128(key1);
        let cipher2 = AesGcmCipherCrate::new_128(key2);
        let text = b"secret data";

        let mut packet = ZCPacket::new_with_payload(text);
        packet.fill_peer_manager_hdr(0, 0, 0);
        cipher1.encrypt(&mut packet).unwrap();

        // Decrypting with wrong key should fail
        let result = cipher2.decrypt(&mut packet);
        assert!(result.is_err());
    }

    #[test]
    fn test_aes_gcm_packet_too_short() {
        let key = [0u8; 16];
        let cipher = AesGcmCipherCrate::new_128(key);

        // Create a packet that's too short to contain encryption metadata
        let mut packet = ZCPacket::new_with_payload(&[1u8; 10]);
        packet.fill_peer_manager_hdr(0, 0, 0);
        packet.mut_peer_manager_header().unwrap().set_encrypted(true);

        let result = cipher.decrypt(&mut packet);
        assert!(result.is_err());
    }
}

// ==================== Ring AES-GCM Tests ====================

#[cfg(feature = "wireguard")]
mod ring_aes_gcm_tests {
    use super::*;

    #[test]
    fn test_ring_aes_128_gcm_basic() {
        let key = [0u8; 16];
        let cipher = RingAesGcmCipher::new_128(key);
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

    #[test]
    fn test_ring_aes_256_gcm_basic() {
        let key = [0u8; 32];
        let cipher = RingAesGcmCipher::new_256(key);
        let text = b"test data for ring aes-256-gcm encryption";
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

    #[test]
    fn test_ring_aes_gcm_empty_payload() {
        let key = [0u8; 16];
        let cipher = RingAesGcmCipher::new_128(key);
        let text = b"";
        let mut packet = ZCPacket::new_with_payload(text);
        packet.fill_peer_manager_hdr(0, 0, 0);

        cipher.encrypt(&mut packet).unwrap();
        assert_eq!(packet.payload().len(), AES_GCM_ENCRYPTION_RESERVED);
        assert_eq!(packet.peer_manager_header().unwrap().is_encrypted(), true);

        cipher.decrypt(&mut packet).unwrap();
        assert_eq!(packet.payload(), text);
        assert_eq!(packet.peer_manager_header().unwrap().is_encrypted(), false);
    }

    #[test]
    fn test_ring_aes_gcm_large_payload() {
        let key = [0u8; 16];
        let cipher = RingAesGcmCipher::new_128(key);
        // 64KB data
        let text: Vec<u8> = (0..65536).map(|i| (i % 256) as u8).collect();
        let mut packet = ZCPacket::new_with_payload(&text);
        packet.fill_peer_manager_hdr(0, 0, 0);

        cipher.encrypt(&mut packet).unwrap();
        assert_eq!(
            packet.payload().len(),
            text.len() + AES_GCM_ENCRYPTION_RESERVED
        );
        assert_eq!(packet.peer_manager_header().unwrap().is_encrypted(), true);

        cipher.decrypt(&mut packet).unwrap();
        assert_eq!(packet.payload(), text.as_slice());
        assert_eq!(packet.peer_manager_header().unwrap().is_encrypted(), false);
    }

    #[test]
    fn test_ring_aes_gcm_multiple_encrypt_decrypt() {
        let key = [42u8; 16];
        let cipher = RingAesGcmCipher::new_128(key);

        for i in 0..10 {
            let text = format!("test message number {}", i);
            let mut packet = ZCPacket::new_with_payload(text.as_bytes());
            packet.fill_peer_manager_hdr(0, 0, 0);

            cipher.encrypt(&mut packet).unwrap();
            assert_eq!(packet.peer_manager_header().unwrap().is_encrypted(), true);

            cipher.decrypt(&mut packet).unwrap();
            assert_eq!(packet.payload(), text.as_bytes());
            assert_eq!(packet.peer_manager_header().unwrap().is_encrypted(), false);
        }
    }

    #[test]
    fn test_ring_aes_gcm_different_keys_produce_different_ciphertext() {
        let key1 = [0u8; 16];
        let key2 = [1u8; 16];
        let cipher1 = RingAesGcmCipher::new_128(key1);
        let cipher2 = RingAesGcmCipher::new_128(key2);
        let text = b"same plaintext";

        let mut packet1 = ZCPacket::new_with_payload(text);
        packet1.fill_peer_manager_hdr(0, 0, 0);
        cipher1.encrypt(&mut packet1).unwrap();

        let mut packet2 = ZCPacket::new_with_payload(text);
        packet2.fill_peer_manager_hdr(0, 0, 0);
        cipher2.encrypt(&mut packet2).unwrap();

        // Ciphertexts should be different (with very high probability)
        assert_ne!(packet1.payload(), packet2.payload());
    }

    #[test]
    fn test_ring_aes_gcm_decrypt_unencrypted_packet() {
        let key = [0u8; 16];
        let cipher = RingAesGcmCipher::new_128(key);
        let text = b"unencrypted data";
        let mut packet = ZCPacket::new_with_payload(text);
        packet.fill_peer_manager_hdr(0, 0, 0);

        // Should not fail when decrypting unencrypted packet
        cipher.decrypt(&mut packet).unwrap();
        assert_eq!(packet.payload(), text);
    }

    #[test]
    fn test_ring_aes_gcm_double_encrypt() {
        let key = [0u8; 16];
        let cipher = RingAesGcmCipher::new_128(key);
        let text = b"test data";
        let mut packet = ZCPacket::new_with_payload(text);
        packet.fill_peer_manager_hdr(0, 0, 0);

        cipher.encrypt(&mut packet).unwrap();
        let encrypted_len = packet.payload().len();

        // Second encrypt should be a no-op (already encrypted)
        cipher.encrypt(&mut packet).unwrap();
        assert_eq!(packet.payload().len(), encrypted_len);

        cipher.decrypt(&mut packet).unwrap();
        assert_eq!(packet.payload(), text);
    }

    #[test]
    fn test_ring_aes_gcm_wrong_key_decrypt_fails() {
        let key1 = [0u8; 16];
        let key2 = [1u8; 16];
        let cipher1 = RingAesGcmCipher::new_128(key1);
        let cipher2 = RingAesGcmCipher::new_128(key2);
        let text = b"secret data";

        let mut packet = ZCPacket::new_with_payload(text);
        packet.fill_peer_manager_hdr(0, 0, 0);
        cipher1.encrypt(&mut packet).unwrap();

        // Decrypting with wrong key should fail
        let result = cipher2.decrypt(&mut packet);
        assert!(result.is_err());
    }

    #[test]
    fn test_ring_aes_gcm_packet_too_short() {
        let key = [0u8; 16];
        let cipher = RingAesGcmCipher::new_128(key);

        // Create a packet that's too short to contain encryption metadata
        let mut packet = ZCPacket::new_with_payload(&[1u8; 10]);
        packet.fill_peer_manager_hdr(0, 0, 0);
        packet.mut_peer_manager_header().unwrap().set_encrypted(true);

        let result = cipher.decrypt(&mut packet);
        assert!(result.is_err());
    }

    #[test]
    fn test_ring_aes_gcm_cipher_clone() {
        let key = [0u8; 16];
        let cipher = RingAesGcmCipher::new_128(key);
        let cloned_cipher = cipher.clone();
        let text = b"test clone";

        let mut packet = ZCPacket::new_with_payload(text);
        packet.fill_peer_manager_hdr(0, 0, 0);
        cipher.encrypt(&mut packet).unwrap();

        // Cloned cipher should be able to decrypt
        cloned_cipher.decrypt(&mut packet).unwrap();
        assert_eq!(packet.payload(), text);
    }
}

// ==================== Performance Tests ====================

/// Performance benchmark results
struct BenchResult {
    operation: String,
    data_size: usize,
    iterations: usize,
    total_time_ms: f64,
    throughput_mb_s: f64,
    ops_per_sec: f64,
}

impl BenchResult {
    fn print(&self) {
        println!(
            "| {:25} | {:>10} | {:>10} | {:>12.2} ms | {:>10.2} MB/s | {:>10.0} ops/s |",
            self.operation,
            format_size(self.data_size),
            self.iterations,
            self.total_time_ms,
            self.throughput_mb_s,
            self.ops_per_sec
        );
    }
}

fn format_size(bytes: usize) -> String {
    if bytes >= 1024 * 1024 {
        format!("{} MB", bytes / (1024 * 1024))
    } else if bytes >= 1024 {
        format!("{} KB", bytes / 1024)
    } else {
        format!("{} B", bytes)
    }
}

fn print_bench_header() {
    println!("\n+---------------------------+------------+------------+--------------+-------------+-------------+");
    println!("| Operation                 |  Data Size | Iterations |   Total Time |  Throughput |      Ops/s  |");
    println!("+---------------------------+------------+------------+--------------+-------------+-------------+");
}

fn print_bench_footer() {
    println!("+---------------------------+------------+------------+--------------+-------------+-------------+\n");
}

/// Auto-compatible performance tests module
///
/// This module automatically tests all available encryption algorithms.
/// When adding a new algorithm, just add it to `get_all_encryptors()`.
mod encryption_perf_tests {
    use super::*;
    use std::time::Instant;

    const ITERATIONS_SMALL: usize = 10000;
    const ITERATIONS_MEDIUM: usize = 1000;

    // Small scale: 1KB, 4KB
    const SMALL_SIZES: &[usize] = &[1024, 4096];
    // Medium scale: 64KB, 256KB
    const MEDIUM_SIZES: &[usize] = &[65536, 262144];

    /// Generic encrypt benchmark using dyn Encryptor
    fn run_encrypt_bench(
        cipher: &dyn Encryptor,
        data_size: usize,
        iterations: usize,
        cipher_name: &str,
    ) -> BenchResult {
        let data: Vec<u8> = (0..data_size).map(|i| (i % 256) as u8).collect();

        let start = Instant::now();
        for _ in 0..iterations {
            let mut packet = ZCPacket::new_with_payload(&data);
            packet.fill_peer_manager_hdr(0, 0, 0);
            cipher.encrypt(&mut packet).unwrap();
        }
        let elapsed = start.elapsed();

        let total_time_ms = elapsed.as_secs_f64() * 1000.0;
        let total_bytes = data_size * iterations;
        let throughput_mb_s = (total_bytes as f64 / (1024.0 * 1024.0)) / elapsed.as_secs_f64();
        let ops_per_sec = iterations as f64 / elapsed.as_secs_f64();

        BenchResult {
            operation: format!("{} Encrypt", cipher_name),
            data_size,
            iterations,
            total_time_ms,
            throughput_mb_s,
            ops_per_sec,
        }
    }

    /// Generic decrypt benchmark using dyn Encryptor
    fn run_decrypt_bench(
        cipher: &dyn Encryptor,
        data_size: usize,
        iterations: usize,
        cipher_name: &str,
    ) -> BenchResult {
        let data: Vec<u8> = (0..data_size).map(|i| (i % 256) as u8).collect();

        // Pre-encrypt packets
        let mut encrypted_packets: Vec<ZCPacket> = Vec::with_capacity(iterations);
        for _ in 0..iterations {
            let mut packet = ZCPacket::new_with_payload(&data);
            packet.fill_peer_manager_hdr(0, 0, 0);
            cipher.encrypt(&mut packet).unwrap();
            encrypted_packets.push(packet);
        }

        let start = Instant::now();
        for packet in encrypted_packets.iter_mut() {
            cipher.decrypt(packet).unwrap();
        }
        let elapsed = start.elapsed();

        let total_time_ms = elapsed.as_secs_f64() * 1000.0;
        let total_bytes = data_size * iterations;
        let throughput_mb_s = (total_bytes as f64 / (1024.0 * 1024.0)) / elapsed.as_secs_f64();
        let ops_per_sec = iterations as f64 / elapsed.as_secs_f64();

        BenchResult {
            operation: format!("{} Decrypt", cipher_name),
            data_size,
            iterations,
            total_time_ms,
            throughput_mb_s,
            ops_per_sec,
        }
    }

    /// Generic roundtrip benchmark using dyn Encryptor
    fn run_roundtrip_bench(
        cipher: &dyn Encryptor,
        data_size: usize,
        iterations: usize,
        cipher_name: &str,
    ) -> BenchResult {
        let data: Vec<u8> = (0..data_size).map(|i| (i % 256) as u8).collect();

        let start = Instant::now();
        for _ in 0..iterations {
            let mut packet = ZCPacket::new_with_payload(&data);
            packet.fill_peer_manager_hdr(0, 0, 0);
            cipher.encrypt(&mut packet).unwrap();
            cipher.decrypt(&mut packet).unwrap();
        }
        let elapsed = start.elapsed();

        let total_time_ms = elapsed.as_secs_f64() * 1000.0;
        let total_bytes = data_size * iterations;
        let throughput_mb_s = (total_bytes as f64 / (1024.0 * 1024.0)) / elapsed.as_secs_f64();
        let ops_per_sec = iterations as f64 / elapsed.as_secs_f64();

        BenchResult {
            operation: format!("{} Roundtrip", cipher_name),
            data_size,
            iterations,
            total_time_ms,
            throughput_mb_s,
            ops_per_sec,
        }
    }

    /// Run performance test for a single algorithm at given scale
    fn run_algorithm_perf_test(
        config: &EncryptorConfig,
        sizes: &[usize],
        iterations: usize,
        scale_name: &str,
    ) {
        println!(
            "\n========== {} {} Scale Performance Test ==========",
            config.name, scale_name
        );
        print_bench_header();

        for &size in sizes {
            run_encrypt_bench(config.encryptor.as_ref(), size, iterations, config.name).print();
            run_decrypt_bench(config.encryptor.as_ref(), size, iterations, config.name).print();
            run_roundtrip_bench(config.encryptor.as_ref(), size, iterations, config.name).print();
        }

        print_bench_footer();
    }

    /// Test all encryption algorithms at small scale (1KB, 4KB × 10000 iterations)
    #[test]
    fn perf_all_algorithms_small_scale() {
        let encryptors = get_perf_testable_encryptors();

        println!("\n╔══════════════════════════════════════════════════════════════════╗");
        println!("║     AUTO-DISCOVERY: Small Scale Encryption Performance Test      ║");
        println!("║     Testing {} algorithm(s) at 1KB and 4KB                        ║", encryptors.len());
        println!("╚══════════════════════════════════════════════════════════════════╝");

        for config in &encryptors {
            run_algorithm_perf_test(config, SMALL_SIZES, ITERATIONS_SMALL, "Small");
        }

        println!("\n[Auto-discovery complete: {} algorithms tested]", encryptors.len());
    }

    /// Test all encryption algorithms at medium scale (64KB, 256KB × 1000 iterations)
    #[test]
    fn perf_all_algorithms_medium_scale() {
        let encryptors = get_perf_testable_encryptors();

        println!("\n╔══════════════════════════════════════════════════════════════════╗");
        println!("║     AUTO-DISCOVERY: Medium Scale Encryption Performance Test     ║");
        println!("║     Testing {} algorithm(s) at 64KB and 256KB                     ║", encryptors.len());
        println!("╚══════════════════════════════════════════════════════════════════╝");

        for config in &encryptors {
            run_algorithm_perf_test(config, MEDIUM_SIZES, ITERATIONS_MEDIUM, "Medium");
        }

        println!("\n[Auto-discovery complete: {} algorithms tested]", encryptors.len());
    }

    /// Compare all encryption algorithms side by side
    #[test]
    fn perf_all_algorithms_comparison() {
        let encryptors = get_perf_testable_encryptors();

        println!("\n╔══════════════════════════════════════════════════════════════════╗");
        println!("║     AUTO-DISCOVERY: Encryption Algorithm Comparison              ║");
        println!("║     Comparing {} algorithm(s) across all data sizes              ║", encryptors.len());
        println!("╚══════════════════════════════════════════════════════════════════╝\n");

        // Test all sizes
        let all_sizes: Vec<usize> = SMALL_SIZES.iter().chain(MEDIUM_SIZES.iter()).copied().collect();
        let iterations_for_size = |size: usize| {
            if size <= 4096 {
                ITERATIONS_SMALL
            } else {
                ITERATIONS_MEDIUM
            }
        };

        for &size in &all_sizes {
            println!("\n--- Data Size: {} ---", format_size(size));
            print_bench_header();

            let iters = iterations_for_size(size);
            for config in &encryptors {
                run_roundtrip_bench(config.encryptor.as_ref(), size, iters, config.name).print();
            }

            print_bench_footer();
        }

        println!("\n[Auto-discovery complete: {} algorithms compared]", encryptors.len());
    }

    /// Verify all registered encryptors work correctly (basic functionality test)
    #[test]
    fn test_all_registered_encryptors() {
        let encryptors = get_all_encryptors();
        let test_data = b"test data for encryption verification";

        println!("\n========== Testing All Registered Encryptors ==========");
        println!("Found {} encryptor(s)\n", encryptors.len());

        for config in &encryptors {
            let mut packet = ZCPacket::new_with_payload(test_data);
            packet.fill_peer_manager_hdr(0, 0, 0);

            // Encrypt
            config.encryptor.encrypt(&mut packet).unwrap();

            // Decrypt
            config.encryptor.decrypt(&mut packet).unwrap();

            // Verify
            assert_eq!(
                packet.payload(),
                test_data,
                "Encryptor {} failed roundtrip test",
                config.name
            );

            println!("  ✓ {} - OK", config.name);
        }

        println!("\nAll {} encryptors passed basic functionality test!", encryptors.len());
    }
}

// ==================== Encryption Size Comparison Tests ====================

/// Test to display encryption size comparison for all algorithms
/// This test shows original size vs encrypted size with overhead
#[test]
fn test_encryption_size_comparison() {
    let encryptors = get_all_encryptors();

    // Different test data sizes
    let test_sizes: Vec<(&str, usize)> = vec![
        ("Tiny (16 bytes)", 16),
        ("Small (64 bytes)", 64),
        ("Medium (256 bytes)", 256),
        ("Standard (1 KB)", 1024),
        ("Large (4 KB)", 4096),
        ("Extra Large (64 KB)", 65536),
    ];

    println!("\n");
    println!("╔══════════════════════════════════════════════════════════════════════════════════════════╗");
    println!("║                    ENCRYPTION SIZE COMPARISON - ALL ALGORITHMS                          ║");
    println!("╠══════════════════════════════════════════════════════════════════════════════════════════╣");

    for (size_name, data_size) in &test_sizes {
        let test_data: Vec<u8> = (0..*data_size).map(|i| (i % 256) as u8).collect();
        let original_size = test_data.len();

        println!("║                                                                                          ║");
        println!("║  📊 Data Size: {:<73} ║", size_name);
        println!("║  📦 Original Size: {:<68} ║", format!("{} bytes", original_size));
        println!("║                                                                                          ║");
        println!("║  {:<20} │ {:>12} │ {:>12} │ {:>10} │ {:<18} ║",
            "Algorithm", "Original", "Encrypted", "Overhead", "Status");
        println!("║  ────────────────────┼──────────────┼──────────────┼────────────┼─────────────────── ║");

        for config in &encryptors {
            let mut packet = ZCPacket::new_with_payload(&test_data);
            packet.fill_peer_manager_hdr(0, 0, 0);

            // Encrypt
            config.encryptor.encrypt(&mut packet).unwrap();

            let is_encrypted = packet.peer_manager_header().unwrap().is_encrypted();
            let encrypted_size = packet.payload().len();

            let (overhead_str, status) = if is_encrypted {
                let overhead = encrypted_size as i64 - original_size as i64;
                let overhead_pct = (overhead as f64 / original_size as f64) * 100.0;
                (format!("+{} B", overhead), format!("🔒 +{:.1}%", overhead_pct))
            } else {
                ("0 B".to_string(), "○ No encryption".to_string())
            };

            println!("║  {:<20} │ {:>10} B │ {:>10} B │ {:>10} │ {:<18} ║",
                config.name,
                original_size,
                encrypted_size,
                overhead_str,
                status
            );

            // Decrypt and verify
            config.encryptor.decrypt(&mut packet).unwrap();
            assert_eq!(packet.payload(), test_data.as_slice(),
                "Data integrity check failed for {}", config.name);
        }

        println!("║  ────────────────────┴──────────────┴──────────────┴────────────┴─────────────────── ║");
    }

    println!("║                                                                                          ║");
    println!("║  Legend: 🔒 = Encrypted (overhead includes nonce + auth tag), ○ = No encryption          ║");
    println!("║  Note: AES-GCM overhead = 12 bytes (nonce) + 16 bytes (auth tag) = 28 bytes fixed        ║");
    println!("╚══════════════════════════════════════════════════════════════════════════════════════════╝");
    println!("\n");
}

// ==================== Cross-implementation Tests ====================

#[cfg(all(feature = "aes-gcm", feature = "wireguard"))]
mod cross_impl_tests {
    use super::*;

    #[test]
    fn test_both_implementations_produce_valid_output() {
        let key_128 = [0u8; 16];
        let key_256 = [0u8; 32];
        let text = b"cross implementation test";

        // Test AES-128
        let crate_cipher = AesGcmCipherCrate::new_128(key_128);
        let ring_cipher = RingAesGcmCipher::new_128(key_128);

        let mut packet1 = ZCPacket::new_with_payload(text);
        packet1.fill_peer_manager_hdr(0, 0, 0);
        crate_cipher.encrypt(&mut packet1).unwrap();
        crate_cipher.decrypt(&mut packet1).unwrap();
        assert_eq!(packet1.payload(), text);

        let mut packet2 = ZCPacket::new_with_payload(text);
        packet2.fill_peer_manager_hdr(0, 0, 0);
        ring_cipher.encrypt(&mut packet2).unwrap();
        ring_cipher.decrypt(&mut packet2).unwrap();
        assert_eq!(packet2.payload(), text);

        // Test AES-256
        let crate_cipher = AesGcmCipherCrate::new_256(key_256);
        let ring_cipher = RingAesGcmCipher::new_256(key_256);

        let mut packet1 = ZCPacket::new_with_payload(text);
        packet1.fill_peer_manager_hdr(0, 0, 0);
        crate_cipher.encrypt(&mut packet1).unwrap();
        crate_cipher.decrypt(&mut packet1).unwrap();
        assert_eq!(packet1.payload(), text);

        let mut packet2 = ZCPacket::new_with_payload(text);
        packet2.fill_peer_manager_hdr(0, 0, 0);
        ring_cipher.encrypt(&mut packet2).unwrap();
        ring_cipher.decrypt(&mut packet2).unwrap();
        assert_eq!(packet2.payload(), text);
    }
}
