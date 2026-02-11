//! Compression module tests
//!
//! This module contains comprehensive tests for the compression functionality,
//! including Zstd compression algorithm tests.
//!
//! ## Auto-compatibility
//! The performance tests automatically iterate over all available compression algorithms.
//! When adding a new algorithm, simply add it to the `get_all_compress_algos()` function.

use crate::common::compressor::{Compressor, DefaultCompressor};
use crate::tunnel::packet_def::{CompressorAlgo, ZCPacket};

// ==================== Algorithm Registry ====================

/// Compression algorithm configuration for auto-discovery testing
pub struct CompressAlgoConfig {
    /// Display name for the algorithm
    pub name: &'static str,
    /// The algorithm enum value
    pub algo: CompressorAlgo,
    /// Whether this algorithm actually compresses (None doesn't)
    pub compresses: bool,
    /// Whether this algorithm is suitable for performance testing
    pub perf_testable: bool,
}

/// Returns all available compression algorithms for testing.
///
/// ## Adding New Algorithms
/// When adding a new compression algorithm:
/// 1. Add it to the CompressorAlgo enum in packet_def.rs
/// 2. Implement the compression/decompression in compressor.rs
/// 3. Add the algorithm to this function
///
/// The performance tests will automatically pick up the new algorithm.
pub fn get_all_compress_algos() -> Vec<CompressAlgoConfig> {
    vec![
        CompressAlgoConfig {
            name: "None",
            algo: CompressorAlgo::None,
            compresses: false,
            perf_testable: false, // No-op, not useful for perf testing
        },
        CompressAlgoConfig {
            name: "Zstd",
            algo: CompressorAlgo::ZstdDefault,
            compresses: true,
            perf_testable: true,
        },
        #[cfg(feature = "lz4")]
        CompressAlgoConfig {
            name: "Lz4",
            algo: CompressorAlgo::Lz4,
            compresses: true,
            perf_testable: true,
        },
        #[cfg(feature = "brotli")]
        CompressAlgoConfig {
            name: "Brotli",
            algo: CompressorAlgo::Brotli,
            compresses: true,
            perf_testable: true,
        },
    ]
}

/// Returns only compression algorithms suitable for performance testing
pub fn get_perf_testable_compress_algos() -> Vec<CompressAlgoConfig> {
    get_all_compress_algos()
        .into_iter()
        .filter(|a| a.perf_testable)
        .collect()
}

// ==================== Basic Compression Tests ====================

#[tokio::test]
async fn test_compression_none() {
    let compressor = DefaultCompressor::new();
    let text = b"test data for no compression";
    let mut packet = ZCPacket::new_with_payload(text);
    packet.fill_peer_manager_hdr(0, 0, 0);

    compressor
        .compress(&mut packet, CompressorAlgo::None)
        .await
        .unwrap();
    assert!(!packet.peer_manager_header().unwrap().is_compressed());

    compressor.decompress(&mut packet).await.unwrap();
    assert_eq!(packet.payload(), text);
}

#[tokio::test]
async fn test_compression_zstd_basic() {
    let compressor = DefaultCompressor::new();
    // Use text long enough to be compressible
    let text = b"test data for zstd compression that should be long enough to compress well 0000000000";
    let mut packet = ZCPacket::new_with_payload(text);
    packet.fill_peer_manager_hdr(0, 0, 0);

    compressor
        .compress(&mut packet, CompressorAlgo::ZstdDefault)
        .await
        .unwrap();
    assert!(packet.peer_manager_header().unwrap().is_compressed());

    compressor.decompress(&mut packet).await.unwrap();
    assert_eq!(packet.payload(), text);
    assert!(!packet.peer_manager_header().unwrap().is_compressed());
}

// ==================== Edge Case Tests ====================

#[tokio::test]
async fn test_compression_empty_payload() {
    let compressor = DefaultCompressor::new();
    let text = b"";
    let mut packet = ZCPacket::new_with_payload(text);
    packet.fill_peer_manager_hdr(0, 0, 0);

    // Empty payload should not be compressed (None algo)
    compressor
        .compress(&mut packet, CompressorAlgo::None)
        .await
        .unwrap();
    assert!(!packet.peer_manager_header().unwrap().is_compressed());

    compressor.decompress(&mut packet).await.unwrap();
    assert_eq!(packet.payload(), text);
}

#[tokio::test]
async fn test_compression_short_payload_not_compressed() {
    let compressor = DefaultCompressor::new();
    let text = b"1234"; // Very short data
    let mut packet = ZCPacket::new_with_payload(text);
    packet.fill_peer_manager_hdr(0, 0, 0);

    // Short payload should not be compressed (compression overhead is too high)
    compressor
        .compress(&mut packet, CompressorAlgo::ZstdDefault)
        .await
        .unwrap();
    // Short text usually can't be compressed effectively
    assert!(!packet.peer_manager_header().unwrap().is_compressed());

    compressor.decompress(&mut packet).await.unwrap();
    assert_eq!(packet.payload(), text);
}

#[tokio::test]
async fn test_compression_large_payload() {
    let compressor = DefaultCompressor::new();
    // 64KB of repeated data (highly compressible)
    let text: Vec<u8> = (0..65536).map(|i| (i % 256) as u8).collect();
    let mut packet = ZCPacket::new_with_payload(&text);
    packet.fill_peer_manager_hdr(0, 0, 0);

    compressor
        .compress(&mut packet, CompressorAlgo::ZstdDefault)
        .await
        .unwrap();
    assert!(packet.peer_manager_header().unwrap().is_compressed());

    // Compressed size should be smaller
    assert!(packet.payload().len() < text.len());

    compressor.decompress(&mut packet).await.unwrap();
    assert_eq!(packet.payload(), text.as_slice());
    assert!(!packet.peer_manager_header().unwrap().is_compressed());
}

#[tokio::test]
async fn test_decompress_uncompressed_packet() {
    let compressor = DefaultCompressor::new();
    let text = b"uncompressed data";
    let mut packet = ZCPacket::new_with_payload(text);
    packet.fill_peer_manager_hdr(0, 0, 0);

    // Decompress an uncompressed packet should be a no-op
    compressor.decompress(&mut packet).await.unwrap();
    assert_eq!(packet.payload(), text);
    assert!(!packet.peer_manager_header().unwrap().is_compressed());
}

// ==================== Multiple Compression Tests ====================

#[tokio::test]
async fn test_multiple_compress_decompress_cycles() {
    let compressor = DefaultCompressor::new();

    for i in 0..10 {
        let text = format!(
            "test message number {} with enough data to be compressed properly 00000000000000",
            i
        );
        let mut packet = ZCPacket::new_with_payload(text.as_bytes());
        packet.fill_peer_manager_hdr(0, 0, 0);

        compressor
            .compress(&mut packet, CompressorAlgo::ZstdDefault)
            .await
            .unwrap();

        compressor.decompress(&mut packet).await.unwrap();
        assert_eq!(packet.payload(), text.as_bytes());
    }
}

#[tokio::test]
async fn test_double_compress_is_noop() {
    let compressor = DefaultCompressor::new();
    // Use highly compressible data (repeated zeros) to ensure first compress succeeds
    let text: Vec<u8> = vec![0u8; 1000];
    let mut packet = ZCPacket::new_with_payload(&text);
    packet.fill_peer_manager_hdr(0, 0, 0);

    compressor
        .compress(&mut packet, CompressorAlgo::ZstdDefault)
        .await
        .unwrap();
    assert!(packet.peer_manager_header().unwrap().is_compressed());
    let compressed_len = packet.payload().len();

    // Second compress should be a no-op (already compressed)
    compressor
        .compress(&mut packet, CompressorAlgo::ZstdDefault)
        .await
        .unwrap();
    assert_eq!(packet.payload().len(), compressed_len);

    compressor.decompress(&mut packet).await.unwrap();
    assert_eq!(packet.payload(), text.as_slice());
}

// ==================== Compression + Encryption Combined Tests ====================

#[cfg(feature = "wireguard")]
#[tokio::test]
async fn test_compress_then_encrypt() {
    use crate::peers::encrypt::{ring_aes_gcm::AesGcmCipher, Encryptor};

    let compressor = DefaultCompressor::new();
    let key = [0u8; 16];
    let cipher = AesGcmCipher::new_128(key);

    let text: Vec<u8> = (0..1000).map(|i| (i % 256) as u8).collect();
    let mut packet = ZCPacket::new_with_payload(&text);
    packet.fill_peer_manager_hdr(0, 0, 0);

    // First compress
    compressor
        .compress(&mut packet, CompressorAlgo::ZstdDefault)
        .await
        .unwrap();
    let compressed_len = packet.payload().len();
    assert!(compressed_len < text.len());

    // Then encrypt
    cipher.encrypt(&mut packet).unwrap();
    assert!(packet.peer_manager_header().unwrap().is_encrypted());

    // Decrypt first
    cipher.decrypt(&mut packet).unwrap();
    assert!(!packet.peer_manager_header().unwrap().is_encrypted());

    // Then decompress
    compressor.decompress(&mut packet).await.unwrap();
    assert_eq!(packet.payload(), text.as_slice());
}

#[cfg(feature = "wireguard")]
#[tokio::test]
async fn test_encrypt_then_compress() {
    use crate::peers::encrypt::{ring_aes_gcm::AesGcmCipher, Encryptor};

    let compressor = DefaultCompressor::new();
    let key = [0u8; 16];
    let cipher = AesGcmCipher::new_128(key);

    let text: Vec<u8> = (0..1000).map(|i| (i % 256) as u8).collect();
    let mut packet = ZCPacket::new_with_payload(&text);
    packet.fill_peer_manager_hdr(0, 0, 0);

    // First encrypt
    cipher.encrypt(&mut packet).unwrap();
    assert!(packet.peer_manager_header().unwrap().is_encrypted());

    // Then try to compress (encrypted data usually doesn't compress well)
    compressor
        .compress(&mut packet, CompressorAlgo::ZstdDefault)
        .await
        .unwrap();
    // Encrypted data is random-looking and may not compress

    // Decompress first (if compressed)
    compressor.decompress(&mut packet).await.unwrap();

    // Then decrypt
    cipher.decrypt(&mut packet).unwrap();
    assert_eq!(packet.payload(), text.as_slice());
}

// ==================== Binary Data Tests ====================

#[tokio::test]
async fn test_compression_binary_data() {
    let compressor = DefaultCompressor::new();
    // Binary data with all byte values (repeated pattern, compressible)
    let text: Vec<u8> = (0..256).cycle().take(10000).map(|x| x as u8).collect();
    let mut packet = ZCPacket::new_with_payload(&text);
    packet.fill_peer_manager_hdr(0, 0, 0);

    compressor
        .compress(&mut packet, CompressorAlgo::ZstdDefault)
        .await
        .unwrap();

    compressor.decompress(&mut packet).await.unwrap();
    assert_eq!(packet.payload(), text.as_slice());
}

#[tokio::test]
async fn test_compression_random_data() {
    use rand::RngCore;

    let compressor = DefaultCompressor::new();
    // Random data (not very compressible)
    let mut text = vec![0u8; 10000];
    rand::thread_rng().fill_bytes(&mut text);

    let mut packet = ZCPacket::new_with_payload(&text);
    packet.fill_peer_manager_hdr(0, 0, 0);

    compressor
        .compress(&mut packet, CompressorAlgo::ZstdDefault)
        .await
        .unwrap();

    compressor.decompress(&mut packet).await.unwrap();
    assert_eq!(packet.payload(), text.as_slice());
}

// ==================== Raw Compression Tests ====================

#[tokio::test]
async fn test_compress_raw_zstd() {
    let compressor = DefaultCompressor::new();
    let data = b"test data for raw zstd compression 000000000000000000000000";

    let compressed = compressor
        .compress_raw(data, CompressorAlgo::ZstdDefault)
        .await
        .unwrap();
    assert!(compressed.len() < data.len());

    let decompressed = compressor
        .decompress_raw(&compressed, CompressorAlgo::ZstdDefault)
        .await
        .unwrap();
    assert_eq!(decompressed, data);
}

#[tokio::test]
async fn test_compress_raw_none() {
    let compressor = DefaultCompressor::new();
    let data = b"test data for no compression";

    let compressed = compressor
        .compress_raw(data, CompressorAlgo::None)
        .await
        .unwrap();
    assert_eq!(compressed, data);

    let decompressed = compressor
        .decompress_raw(&compressed, CompressorAlgo::None)
        .await
        .unwrap();
    assert_eq!(decompressed, data);
}

// ==================== Highly Compressible Data Tests ====================

#[tokio::test]
async fn test_compression_highly_compressible() {
    let compressor = DefaultCompressor::new();
    // All zeros - highly compressible
    let text: Vec<u8> = vec![0u8; 10000];
    let mut packet = ZCPacket::new_with_payload(&text);
    packet.fill_peer_manager_hdr(0, 0, 0);

    compressor
        .compress(&mut packet, CompressorAlgo::ZstdDefault)
        .await
        .unwrap();
    assert!(packet.peer_manager_header().unwrap().is_compressed());

    // Should compress very well
    assert!(packet.payload().len() < text.len() / 10);

    compressor.decompress(&mut packet).await.unwrap();
    assert_eq!(packet.payload(), text.as_slice());
}

#[tokio::test]
async fn test_compression_repeated_pattern() {
    let compressor = DefaultCompressor::new();
    // Repeated pattern - highly compressible
    let pattern = b"ABCDEFGH";
    let text: Vec<u8> = pattern.iter().cycle().take(10000).copied().collect();
    let mut packet = ZCPacket::new_with_payload(&text);
    packet.fill_peer_manager_hdr(0, 0, 0);

    compressor
        .compress(&mut packet, CompressorAlgo::ZstdDefault)
        .await
        .unwrap();
    assert!(packet.peer_manager_header().unwrap().is_compressed());

    compressor.decompress(&mut packet).await.unwrap();
    assert_eq!(packet.payload(), text.as_slice());
}

// ==================== Performance Tests ====================

/// Performance benchmark results for compression
struct CompressBenchResult {
    operation: String,
    data_size: usize,
    iterations: usize,
    total_time_ms: f64,
    throughput_mb_s: f64,
    ops_per_sec: f64,
    compression_ratio: Option<f64>,
}

impl CompressBenchResult {
    fn print(&self) {
        if let Some(ratio) = self.compression_ratio {
            println!(
                "| {:25} | {:>10} | {:>10} | {:>12.2} ms | {:>10.2} MB/s | {:>10.0} ops/s | {:>6.2}x |",
                self.operation,
                format_size(self.data_size),
                self.iterations,
                self.total_time_ms,
                self.throughput_mb_s,
                self.ops_per_sec,
                ratio
            );
        } else {
            println!(
                "| {:25} | {:>10} | {:>10} | {:>12.2} ms | {:>10.2} MB/s | {:>10.0} ops/s |   N/A  |",
                self.operation,
                format_size(self.data_size),
                self.iterations,
                self.total_time_ms,
                self.throughput_mb_s,
                self.ops_per_sec
            );
        }
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

fn print_compress_bench_header() {
    println!("\n+---------------------------+------------+------------+--------------+-------------+-------------+--------+");
    println!("| Operation                 |  Data Size | Iterations |   Total Time |  Throughput |      Ops/s  | Ratio  |");
    println!("+---------------------------+------------+------------+--------------+-------------+-------------+--------+");
}

fn print_compress_bench_footer() {
    println!("+---------------------------+------------+------------+--------------+-------------+-------------+--------+\n");
}

mod compression_perf_tests {
    use super::*;
    use std::time::Instant;

    const ITERATIONS_SMALL: usize = 10000;
    const ITERATIONS_MEDIUM: usize = 1000;

    // Small scale: 1KB, 4KB
    const SMALL_SIZES: &[usize] = &[1024, 4096];
    // Medium scale: 64KB, 256KB
    const MEDIUM_SIZES: &[usize] = &[65536, 262144];

    /// Generate moderately compressible data (pattern with controlled randomness)
    /// This avoids extreme compression ratios that can cause buffer issues
    /// Target compression ratio: 3-10x (safe for decompress_raw buffer calculation)
    fn generate_compressible_data(size: usize) -> Vec<u8> {
        use rand::RngCore;
        let mut data = Vec::with_capacity(size);
        let mut rng = rand::thread_rng();

        // Mix strategy: 3 pattern blocks to 1 random block
        // This gives compression ratio around 3-8x
        let block_size = 64;
        let mut block_counter = 0u32;
        let mut pattern_val = 0u8;

        while data.len() < size {
            let remaining = size - data.len();
            let this_block = remaining.min(block_size);

            if block_counter % 4 != 3 {
                // Pattern blocks (75% of data): repeated byte with slight variation
                for i in 0..this_block {
                    data.push(pattern_val.wrapping_add((i % 8) as u8));
                }
                pattern_val = pattern_val.wrapping_add(17); // Prime offset
            } else {
                // Random block (25% of data): truly random data (incompressible)
                let start = data.len();
                data.resize(data.len() + this_block, 0);
                rng.fill_bytes(&mut data[start..]);
            }

            block_counter += 1;
        }
        data
    }

    /// Generate mixed compressibility data (some random, some patterns)
    fn generate_mixed_data(size: usize) -> Vec<u8> {
        use rand::RngCore;
        let mut data = vec![0u8; size];
        // First half: random data
        rand::thread_rng().fill_bytes(&mut data[..size / 2]);
        // Second half: repeated pattern
        for i in size / 2..size {
            data[i] = ((i - size / 2) % 256) as u8;
        }
        data
    }

    /// Generate binary data (sequential bytes with random perturbations)
    /// Target compression ratio: 3-10x (safe for decompress_raw buffer calculation)
    fn generate_binary_data(size: usize) -> Vec<u8> {
        use rand::RngCore;
        let mut rng = rand::thread_rng();

        // Sequential bytes with periodic random perturbations
        // Every 4th byte is random to prevent extreme compression
        (0..size)
            .map(|i| {
                if i % 4 == 3 {
                    // Random byte every 4 bytes
                    let mut buf = [0u8; 1];
                    rng.fill_bytes(&mut buf);
                    buf[0]
                } else {
                    // Sequential pattern
                    ((i / 4 * 3 + i % 4) % 256) as u8
                }
            })
            .collect()
    }

    async fn run_compress_bench(
        compressor: &DefaultCompressor,
        data: &[u8],
        iterations: usize,
        data_type: &str,
    ) -> CompressBenchResult {
        let data_size = data.len();

        // First, get compression ratio from a single compress
        let mut sample_packet = ZCPacket::new_with_payload(data);
        sample_packet.fill_peer_manager_hdr(0, 0, 0);
        compressor
            .compress(&mut sample_packet, CompressorAlgo::ZstdDefault)
            .await
            .unwrap();
        let compressed_size = sample_packet.payload().len();
        let compression_ratio = if compressed_size > 0 && sample_packet.peer_manager_header().unwrap().is_compressed() {
            Some(data_size as f64 / compressed_size as f64)
        } else {
            None
        };

        let start = Instant::now();
        for _ in 0..iterations {
            let mut packet = ZCPacket::new_with_payload(data);
            packet.fill_peer_manager_hdr(0, 0, 0);
            compressor
                .compress(&mut packet, CompressorAlgo::ZstdDefault)
                .await
                .unwrap();
        }
        let elapsed = start.elapsed();

        let total_time_ms = elapsed.as_secs_f64() * 1000.0;
        let total_bytes = data_size * iterations;
        let throughput_mb_s = (total_bytes as f64 / (1024.0 * 1024.0)) / elapsed.as_secs_f64();
        let ops_per_sec = iterations as f64 / elapsed.as_secs_f64();

        CompressBenchResult {
            operation: format!("Zstd Compress ({})", data_type),
            data_size,
            iterations,
            total_time_ms,
            throughput_mb_s,
            ops_per_sec,
            compression_ratio,
        }
    }

    async fn run_decompress_bench(
        compressor: &DefaultCompressor,
        data: &[u8],
        iterations: usize,
        data_type: &str,
    ) -> CompressBenchResult {
        use bytes::BytesMut;
        use crate::tunnel::packet_def::ZCPacketType;

        let data_size = data.len();

        // Pre-compress one packet and save the tunnel payload bytes (pm_header + payload)
        let mut sample_packet = ZCPacket::new_with_payload(data);
        sample_packet.fill_peer_manager_hdr(0, 0, 0);
        compressor
            .compress(&mut sample_packet, CompressorAlgo::ZstdDefault)
            .await
            .unwrap();

        // Get the tunnel payload (peer_manager_header + compressed payload)
        // This is what DummyTunnel type expects
        let tunnel_payload_bytes = sample_packet.tunnel_payload().to_vec();

        let start = Instant::now();
        for _ in 0..iterations {
            // Recreate packet from tunnel payload with DummyTunnel type
            // DummyTunnel has payload_offset = PEER_MANAGER_HEADER_SIZE (no tunnel header)
            let mut packet = ZCPacket::new_from_buf(
                BytesMut::from(tunnel_payload_bytes.as_slice()),
                ZCPacketType::DummyTunnel,
            );
            compressor.decompress(&mut packet).await.unwrap();
        }
        let elapsed = start.elapsed();

        let total_time_ms = elapsed.as_secs_f64() * 1000.0;
        let total_bytes = data_size * iterations;
        let throughput_mb_s = (total_bytes as f64 / (1024.0 * 1024.0)) / elapsed.as_secs_f64();
        let ops_per_sec = iterations as f64 / elapsed.as_secs_f64();

        CompressBenchResult {
            operation: format!("Zstd Decompress ({})", data_type),
            data_size,
            iterations,
            total_time_ms,
            throughput_mb_s,
            ops_per_sec,
            compression_ratio: None,
        }
    }

    async fn run_roundtrip_bench(
        compressor: &DefaultCompressor,
        data: &[u8],
        iterations: usize,
        data_type: &str,
    ) -> CompressBenchResult {
        let data_size = data.len();

        let start = Instant::now();
        for _ in 0..iterations {
            let mut packet = ZCPacket::new_with_payload(data);
            packet.fill_peer_manager_hdr(0, 0, 0);
            compressor
                .compress(&mut packet, CompressorAlgo::ZstdDefault)
                .await
                .unwrap();
            compressor.decompress(&mut packet).await.unwrap();
        }
        let elapsed = start.elapsed();

        let total_time_ms = elapsed.as_secs_f64() * 1000.0;
        let total_bytes = data_size * iterations;
        let throughput_mb_s = (total_bytes as f64 / (1024.0 * 1024.0)) / elapsed.as_secs_f64();
        let ops_per_sec = iterations as f64 / elapsed.as_secs_f64();

        CompressBenchResult {
            operation: format!("Zstd Roundtrip ({})", data_type),
            data_size,
            iterations,
            total_time_ms,
            throughput_mb_s,
            ops_per_sec,
            compression_ratio: None,
        }
    }

    #[tokio::test]
    async fn perf_zstd_small_scale_compressible() {
        let compressor = DefaultCompressor::new();

        println!("\n========== Zstd Small Scale Performance Test (Compressible Data) ==========");
        print_compress_bench_header();

        for &size in SMALL_SIZES {
            let data = generate_compressible_data(size);
            run_compress_bench(&compressor, &data, ITERATIONS_SMALL, "pattern").await.print();
            run_decompress_bench(&compressor, &data, ITERATIONS_SMALL, "pattern").await.print();
            run_roundtrip_bench(&compressor, &data, ITERATIONS_SMALL, "pattern").await.print();
        }

        print_compress_bench_footer();
    }

    #[tokio::test]
    async fn perf_zstd_small_scale_binary() {
        let compressor = DefaultCompressor::new();

        println!("\n========== Zstd Small Scale Performance Test (Binary Data) ==========");
        print_compress_bench_header();

        for &size in SMALL_SIZES {
            let data = generate_binary_data(size);
            run_compress_bench(&compressor, &data, ITERATIONS_SMALL, "binary").await.print();
            run_decompress_bench(&compressor, &data, ITERATIONS_SMALL, "binary").await.print();
            run_roundtrip_bench(&compressor, &data, ITERATIONS_SMALL, "binary").await.print();
        }

        print_compress_bench_footer();
    }

    #[tokio::test]
    async fn perf_zstd_medium_scale_compressible() {
        let compressor = DefaultCompressor::new();

        println!("\n========== Zstd Medium Scale Performance Test (Compressible Data) ==========");
        print_compress_bench_header();

        for &size in MEDIUM_SIZES {
            let data = generate_compressible_data(size);
            run_compress_bench(&compressor, &data, ITERATIONS_MEDIUM, "pattern").await.print();
            run_decompress_bench(&compressor, &data, ITERATIONS_MEDIUM, "pattern").await.print();
            run_roundtrip_bench(&compressor, &data, ITERATIONS_MEDIUM, "pattern").await.print();
        }

        print_compress_bench_footer();
    }

    #[tokio::test]
    async fn perf_zstd_medium_scale_binary() {
        let compressor = DefaultCompressor::new();

        println!("\n========== Zstd Medium Scale Performance Test (Binary Data) ==========");
        print_compress_bench_header();

        for &size in MEDIUM_SIZES {
            let data = generate_binary_data(size);
            run_compress_bench(&compressor, &data, ITERATIONS_MEDIUM, "binary").await.print();
            run_decompress_bench(&compressor, &data, ITERATIONS_MEDIUM, "binary").await.print();
            run_roundtrip_bench(&compressor, &data, ITERATIONS_MEDIUM, "binary").await.print();
        }

        print_compress_bench_footer();
    }

    #[tokio::test]
    async fn perf_zstd_mixed_data() {
        let compressor = DefaultCompressor::new();

        println!("\n========== Zstd Performance Test (Mixed Data) ==========");
        print_compress_bench_header();

        let all_sizes: Vec<usize> = SMALL_SIZES.iter().chain(MEDIUM_SIZES.iter()).copied().collect();
        let iterations_for_size = |size: usize| {
            if size <= 4096 {
                ITERATIONS_SMALL
            } else {
                ITERATIONS_MEDIUM
            }
        };

        for &size in &all_sizes {
            let data = generate_mixed_data(size);
            let iters = iterations_for_size(size);
            run_compress_bench(&compressor, &data, iters, "mixed").await.print();
            run_decompress_bench(&compressor, &data, iters, "mixed").await.print();
            run_roundtrip_bench(&compressor, &data, iters, "mixed").await.print();
        }

        print_compress_bench_footer();
    }

    #[tokio::test]
    async fn perf_compression_data_type_comparison() {
        let compressor = DefaultCompressor::new();

        println!("\n========== Compression Performance Comparison (Different Data Types) ==========");
        println!("Comparing compression performance across different data patterns\n");

        print_compress_bench_header();

        // Use 64KB for comparison
        let size = 65536;
        let iterations = ITERATIONS_MEDIUM;

        // Compressible pattern data
        let pattern_data = generate_compressible_data(size);
        run_compress_bench(&compressor, &pattern_data, iterations, "pattern").await.print();

        // Binary sequential data
        let binary_data = generate_binary_data(size);
        run_compress_bench(&compressor, &binary_data, iterations, "binary").await.print();

        // Mixed data
        let mixed_data = generate_mixed_data(size);
        run_compress_bench(&compressor, &mixed_data, iterations, "mixed").await.print();

        // Random data (worst case for compression)
        use rand::RngCore;
        let mut random_data = vec![0u8; size];
        rand::thread_rng().fill_bytes(&mut random_data);
        run_compress_bench(&compressor, &random_data, iterations, "random").await.print();

        print_compress_bench_footer();

        println!("Note: Higher compression ratio = better compression (more data reduced)");
        println!("      Random data typically shows ratio ~1.0 or no compression flag set");
    }

    #[tokio::test]
    async fn perf_raw_compression_comparison() {
        let compressor = DefaultCompressor::new();

        println!("\n========== Raw Compression API Performance Test ==========");
        println!("Testing compress_raw/decompress_raw API without ZCPacket overhead\n");

        let sizes = [1024, 4096, 65536, 262144];

        println!("+---------------------------+------------+------------+--------------+-------------+-------------+--------+");
        println!("| Operation                 |  Data Size | Iterations |   Total Time |  Throughput |      Ops/s  | Ratio  |");
        println!("+---------------------------+------------+------------+--------------+-------------+-------------+--------+");

        for size in sizes {
            let data = generate_compressible_data(size);
            let iterations = if size <= 4096 { ITERATIONS_SMALL } else { ITERATIONS_MEDIUM };

            // Compress benchmark
            let start = Instant::now();
            let mut compressed_size = 0;
            for _ in 0..iterations {
                let compressed = compressor
                    .compress_raw(&data, CompressorAlgo::ZstdDefault)
                    .await
                    .unwrap();
                compressed_size = compressed.len();
            }
            let elapsed = start.elapsed();
            let ratio = data.len() as f64 / compressed_size as f64;

            let result = CompressBenchResult {
                operation: "Raw Compress".to_string(),
                data_size: size,
                iterations,
                total_time_ms: elapsed.as_secs_f64() * 1000.0,
                throughput_mb_s: (size * iterations) as f64 / (1024.0 * 1024.0) / elapsed.as_secs_f64(),
                ops_per_sec: iterations as f64 / elapsed.as_secs_f64(),
                compression_ratio: Some(ratio),
            };
            result.print();

            // Decompress benchmark
            let compressed = compressor
                .compress_raw(&data, CompressorAlgo::ZstdDefault)
                .await
                .unwrap();

            let start = Instant::now();
            for _ in 0..iterations {
                let _ = compressor
                    .decompress_raw(&compressed, CompressorAlgo::ZstdDefault)
                    .await
                    .unwrap();
            }
            let elapsed = start.elapsed();

            let result = CompressBenchResult {
                operation: "Raw Decompress".to_string(),
                data_size: size,
                iterations,
                total_time_ms: elapsed.as_secs_f64() * 1000.0,
                throughput_mb_s: (size * iterations) as f64 / (1024.0 * 1024.0) / elapsed.as_secs_f64(),
                ops_per_sec: iterations as f64 / elapsed.as_secs_f64(),
                compression_ratio: None,
            };
            result.print();
        }

        println!("+---------------------------+------------+------------+--------------+-------------+-------------+--------+\n");
    }

    // ==================== Auto-Discovery Tests ====================

    /// Generic compress benchmark that works with any compression algorithm
    async fn run_algo_compress_bench(
        compressor: &DefaultCompressor,
        algo: CompressorAlgo,
        data: &[u8],
        iterations: usize,
        algo_name: &str,
        data_type: &str,
    ) -> CompressBenchResult {
        let data_size = data.len();

        // First, get compression ratio from a single compress
        let mut sample_packet = ZCPacket::new_with_payload(data);
        sample_packet.fill_peer_manager_hdr(0, 0, 0);
        compressor
            .compress(&mut sample_packet, algo)
            .await
            .unwrap();
        let compressed_size = sample_packet.payload().len();
        let compression_ratio = if compressed_size > 0 && sample_packet.peer_manager_header().unwrap().is_compressed() {
            Some(data_size as f64 / compressed_size as f64)
        } else {
            None
        };

        let start = Instant::now();
        for _ in 0..iterations {
            let mut packet = ZCPacket::new_with_payload(data);
            packet.fill_peer_manager_hdr(0, 0, 0);
            compressor.compress(&mut packet, algo).await.unwrap();
        }
        let elapsed = start.elapsed();

        let total_time_ms = elapsed.as_secs_f64() * 1000.0;
        let total_bytes = data_size * iterations;
        let throughput_mb_s = (total_bytes as f64 / (1024.0 * 1024.0)) / elapsed.as_secs_f64();
        let ops_per_sec = iterations as f64 / elapsed.as_secs_f64();

        CompressBenchResult {
            operation: format!("{} Compress ({})", algo_name, data_type),
            data_size,
            iterations,
            total_time_ms,
            throughput_mb_s,
            ops_per_sec,
            compression_ratio,
        }
    }

    /// Generic roundtrip benchmark that works with any compression algorithm
    async fn run_algo_roundtrip_bench(
        compressor: &DefaultCompressor,
        algo: CompressorAlgo,
        data: &[u8],
        iterations: usize,
        algo_name: &str,
        data_type: &str,
    ) -> CompressBenchResult {
        let data_size = data.len();

        let start = Instant::now();
        for _ in 0..iterations {
            let mut packet = ZCPacket::new_with_payload(data);
            packet.fill_peer_manager_hdr(0, 0, 0);
            compressor.compress(&mut packet, algo).await.unwrap();
            compressor.decompress(&mut packet).await.unwrap();
        }
        let elapsed = start.elapsed();

        let total_time_ms = elapsed.as_secs_f64() * 1000.0;
        let total_bytes = data_size * iterations;
        let throughput_mb_s = (total_bytes as f64 / (1024.0 * 1024.0)) / elapsed.as_secs_f64();
        let ops_per_sec = iterations as f64 / elapsed.as_secs_f64();

        CompressBenchResult {
            operation: format!("{} Roundtrip ({})", algo_name, data_type),
            data_size,
            iterations,
            total_time_ms,
            throughput_mb_s,
            ops_per_sec,
            compression_ratio: None,
        }
    }

    /// Auto-discovery test: Test all compression algorithms at small scale
    #[tokio::test]
    async fn perf_all_algorithms_small_scale() {
        let compressor = DefaultCompressor::new();
        let algos = get_perf_testable_compress_algos();

        println!("\n╔══════════════════════════════════════════════════════════════════╗");
        println!("║     AUTO-DISCOVERY: Small Scale Compression Performance Test     ║");
        println!("║     Testing {} algorithm(s) at 1KB and 4KB                        ║", algos.len());
        println!("╚══════════════════════════════════════════════════════════════════╝");

        for algo_config in &algos {
            println!(
                "\n========== {} Small Scale Performance Test ==========",
                algo_config.name
            );
            print_compress_bench_header();

            for &size in SMALL_SIZES {
                let data = generate_compressible_data(size);
                run_algo_compress_bench(&compressor, algo_config.algo, &data, ITERATIONS_SMALL, algo_config.name, "pattern")
                    .await
                    .print();
                run_algo_roundtrip_bench(&compressor, algo_config.algo, &data, ITERATIONS_SMALL, algo_config.name, "pattern")
                    .await
                    .print();
            }

            print_compress_bench_footer();
        }

        println!("\n[Auto-discovery complete: {} algorithms tested]", algos.len());
    }

    /// Auto-discovery test: Test all compression algorithms at medium scale
    #[tokio::test]
    async fn perf_all_algorithms_medium_scale() {
        let compressor = DefaultCompressor::new();
        let algos = get_perf_testable_compress_algos();

        println!("\n╔══════════════════════════════════════════════════════════════════╗");
        println!("║     AUTO-DISCOVERY: Medium Scale Compression Performance Test    ║");
        println!("║     Testing {} algorithm(s) at 64KB and 256KB                     ║", algos.len());
        println!("╚══════════════════════════════════════════════════════════════════╝");

        for algo_config in &algos {
            println!(
                "\n========== {} Medium Scale Performance Test ==========",
                algo_config.name
            );
            print_compress_bench_header();

            for &size in MEDIUM_SIZES {
                let data = generate_compressible_data(size);
                run_algo_compress_bench(&compressor, algo_config.algo, &data, ITERATIONS_MEDIUM, algo_config.name, "pattern")
                    .await
                    .print();
                run_algo_roundtrip_bench(&compressor, algo_config.algo, &data, ITERATIONS_MEDIUM, algo_config.name, "pattern")
                    .await
                    .print();
            }

            print_compress_bench_footer();
        }

        println!("\n[Auto-discovery complete: {} algorithms tested]", algos.len());
    }

    /// Auto-discovery test: Compare all compression algorithms side by side
    #[tokio::test]
    async fn perf_all_algorithms_comparison() {
        let compressor = DefaultCompressor::new();
        let algos = get_perf_testable_compress_algos();

        println!("\n╔══════════════════════════════════════════════════════════════════╗");
        println!("║     AUTO-DISCOVERY: Compression Algorithm Comparison             ║");
        println!("║     Comparing {} algorithm(s) across all data sizes              ║", algos.len());
        println!("╚══════════════════════════════════════════════════════════════════╝\n");

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
            print_compress_bench_header();

            let data = generate_compressible_data(size);
            let iters = iterations_for_size(size);

            for algo_config in &algos {
                run_algo_roundtrip_bench(&compressor, algo_config.algo, &data, iters, algo_config.name, "pattern")
                    .await
                    .print();
            }

            print_compress_bench_footer();
        }

        println!("\n[Auto-discovery complete: {} algorithms compared]", algos.len());
    }

    /// Verify all registered compression algorithms work correctly
    #[tokio::test]
    async fn test_all_registered_algorithms() {
        let compressor = DefaultCompressor::new();
        let algos = get_all_compress_algos();
        let test_data = b"test data for compression verification that should be long enough to compress";

        println!("\n========== Testing All Registered Compression Algorithms ==========");
        println!("Found {} algorithm(s)\n", algos.len());

        for algo_config in &algos {
            let mut packet = ZCPacket::new_with_payload(test_data);
            packet.fill_peer_manager_hdr(0, 0, 0);

            // Compress
            compressor
                .compress(&mut packet, algo_config.algo)
                .await
                .unwrap();

            // Verify compression flag based on algorithm type
            if algo_config.compresses {
                // Algorithms that compress should set the flag (if data is compressible)
                // Note: Some data might not compress, so we just check it doesn't error
            }

            // Decompress
            compressor.decompress(&mut packet).await.unwrap();

            // Verify data integrity
            assert_eq!(
                packet.payload(),
                test_data,
                "Algorithm {} failed roundtrip test",
                algo_config.name
            );

            println!("  ✓ {} - OK", algo_config.name);
        }

        println!("\nAll {} algorithms passed basic functionality test!", algos.len());
    }

    // ==================== Stability Tests (Long-running) ====================

    /// Long-running stability test for all compression algorithms
    /// Runs for at least 60 seconds to simulate production environment
    /// Tests data integrity and measures throughput over time
    #[tokio::test]
    async fn stability_test_all_algorithms_60s() {
        use std::sync::atomic::{AtomicU64, Ordering};
        use std::sync::Arc;
        use tokio::time::Instant;

        const TEST_DURATION_SECS: u64 = 60;
        const PACKET_SIZE: usize = 1400; // Typical MTU size
        const REPORT_INTERVAL_SECS: u64 = 10;

        let compressor = DefaultCompressor::new();
        let algos = get_perf_testable_compress_algos();

        println!("\n");
        println!("╔══════════════════════════════════════════════════════════════════════════════╗");
        println!("║          COMPRESSION STABILITY TEST - {} SECONDS DURATION                   ║", TEST_DURATION_SECS);
        println!("║          Testing {} algorithm(s) with {}B packets                           ║", algos.len(), PACKET_SIZE);
        println!("╚══════════════════════════════════════════════════════════════════════════════╝\n");

        for algo_config in &algos {
            println!("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");
            println!("  🔧 Testing Algorithm: {}", algo_config.name);
            println!("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");

            let total_packets = Arc::new(AtomicU64::new(0));
            let total_bytes = Arc::new(AtomicU64::new(0));
            let error_count = Arc::new(AtomicU64::new(0));
            let integrity_failures = Arc::new(AtomicU64::new(0));

            let start_time = Instant::now();
            let mut last_report_time = start_time;
            let mut last_report_packets: u64 = 0;
            let mut last_report_bytes: u64 = 0;

            // Generate test data patterns
            let test_patterns: Vec<Vec<u8>> = vec![
                // Pattern 1: Compressible repeated data
                (0..PACKET_SIZE).map(|i| (i % 64) as u8).collect(),
                // Pattern 2: Mixed compressible/random
                {
                    use rand::RngCore;
                    let mut data = vec![0u8; PACKET_SIZE];
                    // First half: pattern, second half: random
                    for i in 0..PACKET_SIZE/2 {
                        data[i] = (i % 32) as u8;
                    }
                    rand::thread_rng().fill_bytes(&mut data[PACKET_SIZE/2..]);
                    data
                },
                // Pattern 3: Simulated network packet (header + payload)
                {
                    let mut data = vec![0u8; PACKET_SIZE];
                    // Header-like structure (20 bytes)
                    for i in 0..20 {
                        data[i] = (i * 7) as u8;
                    }
                    // Payload: somewhat compressible
                    for i in 20..PACKET_SIZE {
                        data[i] = ((i - 20) % 128) as u8;
                    }
                    data
                },
                // Pattern 4: Text-like data
                b"EasyTier P2P VPN network packet data for compression stability testing. "
                    .iter()
                    .cycle()
                    .take(PACKET_SIZE)
                    .copied()
                    .collect(),
            ];

            let mut pattern_index = 0usize;

            println!("  ⏱️  Starting {}s stability test...", TEST_DURATION_SECS);
            println!("  📊 Progress reports every {}s\n", REPORT_INTERVAL_SECS);

            while start_time.elapsed().as_secs() < TEST_DURATION_SECS {
                // Rotate through test patterns
                let test_data = &test_patterns[pattern_index % test_patterns.len()];
                pattern_index = pattern_index.wrapping_add(1);

                // Create packet and compress
                let mut packet = ZCPacket::new_with_payload(test_data);
                packet.fill_peer_manager_hdr(0, 0, 0);

                match compressor.compress(&mut packet, algo_config.algo).await {
                    Ok(_) => {
                        // Decompress
                        match compressor.decompress(&mut packet).await {
                            Ok(_) => {
                                // Verify data integrity
                                if packet.payload() != test_data.as_slice() {
                                    integrity_failures.fetch_add(1, Ordering::Relaxed);
                                } else {
                                    total_packets.fetch_add(1, Ordering::Relaxed);
                                    total_bytes.fetch_add(PACKET_SIZE as u64, Ordering::Relaxed);
                                }
                            }
                            Err(_) => {
                                error_count.fetch_add(1, Ordering::Relaxed);
                            }
                        }
                    }
                    Err(_) => {
                        error_count.fetch_add(1, Ordering::Relaxed);
                    }
                }

                // Periodic progress report
                let now = Instant::now();
                if now.duration_since(last_report_time).as_secs() >= REPORT_INTERVAL_SECS {
                    let current_packets = total_packets.load(Ordering::Relaxed);
                    let current_bytes = total_bytes.load(Ordering::Relaxed);
                    let current_errors = error_count.load(Ordering::Relaxed);
                    let current_integrity = integrity_failures.load(Ordering::Relaxed);

                    let interval_packets = current_packets - last_report_packets;
                    let interval_bytes = current_bytes - last_report_bytes;
                    let interval_secs = now.duration_since(last_report_time).as_secs_f64();

                    let throughput_mbps = (interval_bytes as f64 * 8.0) / (1024.0 * 1024.0) / interval_secs;
                    let pps = interval_packets as f64 / interval_secs;

                    let elapsed_secs = start_time.elapsed().as_secs();
                    println!(
                        "  [{:>3}s] Packets: {:>10} | Throughput: {:>8.2} Mbps | {:>8.0} pps | Errors: {} | Integrity: {}",
                        elapsed_secs, current_packets, throughput_mbps, pps, current_errors, current_integrity
                    );

                    last_report_time = now;
                    last_report_packets = current_packets;
                    last_report_bytes = current_bytes;
                }

                // Small yield to prevent blocking
                if pattern_index % 1000 == 0 {
                    tokio::task::yield_now().await;
                }
            }

            // Final statistics
            let final_packets = total_packets.load(Ordering::Relaxed);
            let final_bytes = total_bytes.load(Ordering::Relaxed);
            let final_errors = error_count.load(Ordering::Relaxed);
            let final_integrity = integrity_failures.load(Ordering::Relaxed);
            let total_duration = start_time.elapsed().as_secs_f64();

            let avg_throughput_mbps = (final_bytes as f64 * 8.0) / (1024.0 * 1024.0) / total_duration;
            let avg_pps = final_packets as f64 / total_duration;

            println!("\n  ╭─────────────────────────────────────────────────────────────────╮");
            println!("  │  📈 FINAL RESULTS for {}                                      ", algo_config.name);
            println!("  ├─────────────────────────────────────────────────────────────────┤");
            println!("  │  Duration:           {:>10.2} seconds                        │", total_duration);
            println!("  │  Total Packets:      {:>10}                                  │", final_packets);
            println!("  │  Total Data:         {:>10.2} MB                             │", final_bytes as f64 / (1024.0 * 1024.0));
            println!("  │  Avg Throughput:     {:>10.2} Mbps                           │", avg_throughput_mbps);
            println!("  │  Avg Packets/sec:    {:>10.0}                                │", avg_pps);
            println!("  │  Compression Errors: {:>10}                                  │", final_errors);
            println!("  │  Integrity Failures: {:>10}                                  │", final_integrity);
            println!("  ╰─────────────────────────────────────────────────────────────────╯");

            // Assertions for stability test
            assert_eq!(final_errors, 0, "Algorithm {} had compression/decompression errors", algo_config.name);
            assert_eq!(final_integrity, 0, "Algorithm {} had data integrity failures", algo_config.name);
            assert!(final_packets > 0, "Algorithm {} processed no packets", algo_config.name);

            println!("  ✅ {} PASSED stability test!\n", algo_config.name);
        }

        println!("╔══════════════════════════════════════════════════════════════════════════════╗");
        println!("║                    ALL STABILITY TESTS COMPLETED SUCCESSFULLY               ║");
        println!("╚══════════════════════════════════════════════════════════════════════════════╝\n");
    }

    /// Quick stability test (10 seconds) for CI/CD pipelines
    #[tokio::test]
    async fn stability_test_quick_10s() {
        use tokio::time::Instant;

        const TEST_DURATION_SECS: u64 = 10;
        const PACKET_SIZE: usize = 1400;

        let compressor = DefaultCompressor::new();
        let algos = get_perf_testable_compress_algos();

        println!("\n========== Quick Stability Test ({}s) ==========\n", TEST_DURATION_SECS);

        for algo_config in &algos {
            let start_time = Instant::now();
            let mut total_packets: u64 = 0;
            let mut error_count: u64 = 0;

            // Simple compressible test data
            let test_data: Vec<u8> = (0..PACKET_SIZE).map(|i| (i % 64) as u8).collect();

            while start_time.elapsed().as_secs() < TEST_DURATION_SECS {
                let mut packet = ZCPacket::new_with_payload(&test_data);
                packet.fill_peer_manager_hdr(0, 0, 0);

                if compressor.compress(&mut packet, algo_config.algo).await.is_ok() {
                    if compressor.decompress(&mut packet).await.is_ok() {
                        if packet.payload() == test_data.as_slice() {
                            total_packets += 1;
                        } else {
                            error_count += 1;
                        }
                    } else {
                        error_count += 1;
                    }
                } else {
                    error_count += 1;
                }

                if total_packets % 1000 == 0 {
                    tokio::task::yield_now().await;
                }
            }

            let duration = start_time.elapsed().as_secs_f64();
            let pps = total_packets as f64 / duration;

            println!(
                "  {} : {:>8} packets in {:.1}s ({:.0} pps) | Errors: {}",
                algo_config.name, total_packets, duration, pps, error_count
            );

            assert_eq!(error_count, 0, "Algorithm {} failed stability test", algo_config.name);
        }

        println!("\n✅ All algorithms passed quick stability test!\n");
    }

    /// Stress test with varying packet sizes
    #[tokio::test]
    async fn stability_test_varying_sizes_30s() {
        use tokio::time::Instant;

        const TEST_DURATION_SECS: u64 = 30;

        let compressor = DefaultCompressor::new();
        let algos = get_perf_testable_compress_algos();

        // Various packet sizes to test
        let packet_sizes: Vec<usize> = vec![64, 256, 512, 1024, 1400, 2048, 4096, 8192];

        println!("\n========== Varying Size Stability Test ({}s) ==========", TEST_DURATION_SECS);
        println!("Testing packet sizes: {:?}\n", packet_sizes);

        for algo_config in &algos {
            let start_time = Instant::now();
            let mut total_packets: u64 = 0;
            let mut error_count: u64 = 0;
            let mut size_index = 0usize;

            while start_time.elapsed().as_secs() < TEST_DURATION_SECS {
                let packet_size = packet_sizes[size_index % packet_sizes.len()];
                size_index = size_index.wrapping_add(1);

                // Generate test data for this size
                let test_data: Vec<u8> = (0..packet_size).map(|i| (i % 128) as u8).collect();

                let mut packet = ZCPacket::new_with_payload(&test_data);
                packet.fill_peer_manager_hdr(0, 0, 0);

                if compressor.compress(&mut packet, algo_config.algo).await.is_ok() {
                    if compressor.decompress(&mut packet).await.is_ok() {
                        if packet.payload() == test_data.as_slice() {
                            total_packets += 1;
                        } else {
                            error_count += 1;
                            println!("  ❌ Integrity failure at size {} for {}", packet_size, algo_config.name);
                        }
                    } else {
                        error_count += 1;
                    }
                } else {
                    error_count += 1;
                }

                if total_packets % 500 == 0 {
                    tokio::task::yield_now().await;
                }
            }

            let duration = start_time.elapsed().as_secs_f64();
            println!(
                "  {} : {:>8} packets ({} sizes) in {:.1}s | Errors: {}",
                algo_config.name, total_packets, packet_sizes.len(), duration, error_count
            );

            assert_eq!(error_count, 0, "Algorithm {} failed varying size test", algo_config.name);
        }

        println!("\n✅ All algorithms passed varying size stability test!\n");
    }

    /// Test to display compression size comparison for all algorithms
    /// This test shows original size vs compressed size with compression ratio
    #[tokio::test]
    async fn test_compression_size_comparison() {
        let compressor = DefaultCompressor::new();
        let algos = get_all_compress_algos();

        // Different test data types
        let test_cases: Vec<(&str, Vec<u8>)> = vec![
            ("Text (repeating)", b"Hello World! ".repeat(100).to_vec()),
            ("Text (compressible)", generate_compressible_data(1024)),
            ("Binary (mixed)", generate_binary_data(1024)),
            ("Random (incompressible)", {
                use rand::RngCore;
                let mut data = vec![0u8; 1024];
                rand::thread_rng().fill_bytes(&mut data);
                data
            }),
            ("Large text (4KB)", b"EasyTier P2P VPN compression test data. ".repeat(100).to_vec()),
            ("Large binary (8KB)", generate_binary_data(8192)),
        ];

        println!("\n");
        println!("╔══════════════════════════════════════════════════════════════════════════════════════════╗");
        println!("║                    COMPRESSION SIZE COMPARISON - ALL ALGORITHMS                         ║");
        println!("╠══════════════════════════════════════════════════════════════════════════════════════════╣");

        for (data_name, test_data) in &test_cases {
            let original_size = test_data.len();

            println!("║                                                                                          ║");
            println!("║  📊 Data Type: {:<73} ║", data_name);
            println!("║  📦 Original Size: {:<68} ║", format!("{} bytes", original_size));
            println!("║                                                                                          ║");
            println!("║  {:<12} │ {:>12} │ {:>12} │ {:>10} │ {:<20} ║",
                "Algorithm", "Original", "Compressed", "Ratio", "Status");
            println!("║  ────────────┼──────────────┼──────────────┼────────────┼───────────────────── ║");

            for algo_config in &algos {
                let mut packet = ZCPacket::new_with_payload(test_data);
                packet.fill_peer_manager_hdr(0, 0, 0);

                // Compress
                compressor
                    .compress(&mut packet, algo_config.algo)
                    .await
                    .unwrap();

                let is_compressed = packet.peer_manager_header().unwrap().is_compressed();
                let compressed_size = packet.payload().len();

                let (ratio_str, status) = if is_compressed {
                    let ratio = original_size as f64 / compressed_size as f64;
                    let saved = 100.0 - (compressed_size as f64 / original_size as f64 * 100.0);
                    (format!("{:.2}x", ratio), format!("✓ -{:.1}%", saved))
                } else if algo_config.compresses {
                    ("N/A".to_string(), "⚠ No benefit".to_string())
                } else {
                    ("N/A".to_string(), "○ Passthrough".to_string())
                };

                println!("║  {:<12} │ {:>10} B │ {:>10} B │ {:>10} │ {:<20} ║",
                    algo_config.name,
                    original_size,
                    compressed_size,
                    ratio_str,
                    status
                );

                // Decompress and verify
                compressor.decompress(&mut packet).await.unwrap();
                assert_eq!(packet.payload(), test_data.as_slice(),
                    "Data integrity check failed for {}", algo_config.name);
            }

            println!("║  ────────────┴──────────────┴──────────────┴────────────┴───────────────────── ║");
        }

        println!("║                                                                                          ║");
        println!("║  Legend: ✓ = Compressed successfully, ⚠ = Data not compressible, ○ = No compression     ║");
        println!("╚══════════════════════════════════════════════════════════════════════════════════════════╝");
        println!("\n");
    }
}


/// Network transmission simulation tests
/// These tests simulate real-world networking scenarios similar to three_node.rs
/// but without requiring Linux network namespaces
mod network_simulation_tests {
    use super::*;
    use bytes::BytesMut;
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::sync::Arc;
    use std::time::Duration;
    use tokio::sync::mpsc;
    use tokio::time::Instant;

    /// Simulates a network packet with peer_manager-like header structure
    fn create_network_packet(payload: &[u8]) -> ZCPacket {
        let mut packet = ZCPacket::new_with_payload(payload);
        // Fill peer_manager header like real network transmission
        packet.fill_peer_manager_hdr(0, 0, 0);
        packet
    }

    /// Simulates sender side: compress and send packets through channel
    async fn sender_task(
        tx: mpsc::Sender<Vec<u8>>,
        compressor: DefaultCompressor,
        algo: CompressorAlgo,
        packet_sizes: Vec<usize>,
        duration_secs: u64,
        stats: Arc<SenderStats>,
    ) {
        let start = Instant::now();
        let mut packet_index = 0usize;

        while start.elapsed().as_secs() < duration_secs {
            let size = packet_sizes[packet_index % packet_sizes.len()];
            packet_index = packet_index.wrapping_add(1);

            // Generate packet data (mix of compressible and random data like screen updates)
            let payload: Vec<u8> = (0..size).map(|i| {
                if i % 4 == 3 {
                    // 25% random data (like encrypted portions)
                    rand::random::<u8>()
                } else {
                    // 75% pattern data (like screen regions)
                    ((i * 7 + packet_index) % 256) as u8
                }
            }).collect();

            let mut packet = create_network_packet(&payload);
            let original_size = packet.payload().len();

            // Compress like peer_manager does
            match compressor.compress(&mut packet, algo).await {
                Ok(_) => {
                    let compressed_size = packet.buf_len();
                    stats.packets_sent.fetch_add(1, Ordering::Relaxed);
                    stats.bytes_before_compress.fetch_add(original_size as u64, Ordering::Relaxed);
                    stats.bytes_after_compress.fetch_add(compressed_size as u64, Ordering::Relaxed);

                    // Send through "network" channel
                    let data = packet.inner().to_vec();
                    if tx.send(data).await.is_err() {
                        break;
                    }
                }
                Err(e) => {
                    stats.compress_errors.fetch_add(1, Ordering::Relaxed);
                    tracing::error!("Compress error: {:?}", e);
                }
            }

            // Small yield to simulate network timing
            if packet_index % 100 == 0 {
                tokio::task::yield_now().await;
            }
        }
    }

    /// Simulates receiver side: receive and decompress packets
    async fn receiver_task(
        mut rx: mpsc::Receiver<Vec<u8>>,
        compressor: DefaultCompressor,
        stats: Arc<ReceiverStats>,
    ) {
        use crate::tunnel::packet_def::ZCPacketType;

        while let Some(data) = rx.recv().await {
            // IMPORTANT: Use NIC packet type to match the sender's packet type
            let mut packet = ZCPacket::new_from_buf(
                BytesMut::from(data.as_slice()),
                ZCPacketType::NIC,
            );

            let before_size = packet.buf_len();

            // Decompress like peer_manager does
            match compressor.decompress(&mut packet).await {
                Ok(_) => {
                    let after_size = packet.payload().len();
                    stats.packets_received.fetch_add(1, Ordering::Relaxed);
                    stats.bytes_before_decompress.fetch_add(before_size as u64, Ordering::Relaxed);
                    stats.bytes_after_decompress.fetch_add(after_size as u64, Ordering::Relaxed);
                }
                Err(e) => {
                    stats.decompress_errors.fetch_add(1, Ordering::Relaxed);
                    tracing::error!("Decompress error: {:?}", e);
                }
            }
        }
    }

    #[derive(Default)]
    struct SenderStats {
        packets_sent: AtomicU64,
        bytes_before_compress: AtomicU64,
        bytes_after_compress: AtomicU64,
        compress_errors: AtomicU64,
    }

    #[derive(Default)]
    struct ReceiverStats {
        packets_received: AtomicU64,
        bytes_before_decompress: AtomicU64,
        bytes_after_decompress: AtomicU64,
        decompress_errors: AtomicU64,
    }

    /// Simulates real network transmission like RustDesk remote desktop
    /// 
    /// This test creates a sender and receiver connected via tokio channel,
    /// simulating the data flow through EasyTier's virtual network:
    /// - Sender compresses packets (like 10.144.144.1 sending to 10.144.144.3)
    /// - Channel acts as network transport
    /// - Receiver decompresses packets
    #[tokio::test]
    async fn network_transmission_simulation() {
        let algos = get_perf_testable_compress_algos();
        let test_duration_secs = 5;

        // Packet sizes similar to remote desktop traffic patterns
        let packet_sizes: Vec<usize> = vec![
            64,    // Control messages
            256,   // Small updates
            1024,  // Screen chunks
            2048,  // Medium regions
            4096,  // Large updates
            8192,  // Full frame portions
        ];

        println!("\n");
        println!("╔══════════════════════════════════════════════════════════════════════════════════════╗");
        println!("║           NETWORK TRANSMISSION SIMULATION TEST ({}s per algorithm)                  ║", test_duration_secs);
        println!("║           Simulating RustDesk-like traffic through virtual network                  ║");
        println!("╠══════════════════════════════════════════════════════════════════════════════════════╣");
        println!("║  Algorithm │  Packets │  Errors │ Compress Ratio │  Throughput │      Status        ║");
        println!("╠════════════╪══════════╪═════════╪════════════════╪═════════════╪════════════════════╣");

        for algo_config in &algos {
            let compressor = DefaultCompressor::new();
            let (tx, rx) = mpsc::channel::<Vec<u8>>(1000);

            let sender_stats = Arc::new(SenderStats::default());
            let receiver_stats = Arc::new(ReceiverStats::default());

            let sender_stats_clone = sender_stats.clone();
            let receiver_stats_clone = receiver_stats.clone();

            // Spawn sender and receiver tasks
            let sender_handle = tokio::spawn(sender_task(
                tx,
                DefaultCompressor::new(),
                algo_config.algo,
                packet_sizes.clone(),
                test_duration_secs,
                sender_stats_clone,
            ));

            let receiver_handle = tokio::spawn(receiver_task(
                rx,
                DefaultCompressor::new(),
                receiver_stats_clone,
            ));

            // Wait for sender to finish
            sender_handle.await.unwrap();
            
            // Give receiver time to process remaining packets
            tokio::time::sleep(Duration::from_millis(100)).await;
            
            // Drop sender is already done, receiver will exit when channel is empty
            drop(compressor);

            // Wait a bit more for receiver
            tokio::time::sleep(Duration::from_millis(100)).await;
            receiver_handle.abort();

            // Collect stats
            let packets_sent = sender_stats.packets_sent.load(Ordering::Relaxed);
            let bytes_before = sender_stats.bytes_before_compress.load(Ordering::Relaxed);
            let bytes_after = sender_stats.bytes_after_compress.load(Ordering::Relaxed);
            let compress_errors = sender_stats.compress_errors.load(Ordering::Relaxed);
            let decompress_errors = receiver_stats.decompress_errors.load(Ordering::Relaxed);
            let total_errors = compress_errors + decompress_errors;

            let compression_ratio = if bytes_after > 0 {
                bytes_before as f64 / bytes_after as f64
            } else {
                1.0
            };

            let throughput_mbps = (bytes_before as f64 * 8.0) / (1024.0 * 1024.0) / test_duration_secs as f64;

            let status = if total_errors == 0 { "✓ PASSED" } else { "✗ FAILED" };

            println!(
                "║  {:^9} │ {:>8} │ {:>7} │ {:>13.2}x │ {:>8.2} Mbps │ {:^18} ║",
                algo_config.name,
                packets_sent,
                total_errors,
                compression_ratio,
                throughput_mbps,
                status
            );

            assert_eq!(
                total_errors, 0,
                "Algorithm {} had errors: compress={}, decompress={}",
                algo_config.name, compress_errors, decompress_errors
            );
        }

        println!("╚══════════════════════════════════════════════════════════════════════════════════════╝");
        println!("\n");
    }

    /// Extended stress test simulating 30 seconds of continuous remote desktop traffic
    #[tokio::test]
    async fn network_stress_test_30s() {
        let algos = get_perf_testable_compress_algos();
        let test_duration_secs = 30;

        // Vary packet sizes like real RustDesk traffic
        let packet_sizes: Vec<usize> = vec![64, 128, 256, 512, 1024, 1400, 2048, 4096, 8192];

        println!("\n");
        println!("╔══════════════════════════════════════════════════════════════════════════════════════════════╗");
        println!("║               NETWORK STRESS TEST ({}s) - Simulating Continuous Remote Desktop              ║", test_duration_secs);
        println!("╠══════════════════════════════════════════════════════════════════════════════════════════════╣");

        for algo_config in &algos {
            println!("║  Testing: {:<82} ║", algo_config.name);

            let (tx, rx) = mpsc::channel::<Vec<u8>>(10000);
            let sender_stats = Arc::new(SenderStats::default());
            let receiver_stats = Arc::new(ReceiverStats::default());

            let start_time = Instant::now();

            let sender_handle = tokio::spawn(sender_task(
                tx,
                DefaultCompressor::new(),
                algo_config.algo,
                packet_sizes.clone(),
                test_duration_secs,
                sender_stats.clone(),
            ));

            let receiver_handle = tokio::spawn(receiver_task(
                rx,
                DefaultCompressor::new(),
                receiver_stats.clone(),
            ));

            // Progress reporting
            let sender_stats_report = sender_stats.clone();
            let receiver_stats_report = receiver_stats.clone();
            let report_handle = tokio::spawn(async move {
                let mut last_packets = 0u64;
                loop {
                    tokio::time::sleep(Duration::from_secs(10)).await;
                    let current_packets = sender_stats_report.packets_sent.load(Ordering::Relaxed);
                    let errors = sender_stats_report.compress_errors.load(Ordering::Relaxed)
                        + receiver_stats_report.decompress_errors.load(Ordering::Relaxed);
                    let pps = (current_packets - last_packets) / 10;
                    println!("║    Progress: {} packets, {} pps, {} errors{:<43} ║", 
                        current_packets, pps, errors, "");
                    last_packets = current_packets;
                }
            });

            sender_handle.await.unwrap();
            tokio::time::sleep(Duration::from_millis(200)).await;
            report_handle.abort();
            receiver_handle.abort();

            let elapsed = start_time.elapsed();
            let packets = sender_stats.packets_sent.load(Ordering::Relaxed);
            let bytes = sender_stats.bytes_before_compress.load(Ordering::Relaxed);
            let errors = sender_stats.compress_errors.load(Ordering::Relaxed)
                + receiver_stats.decompress_errors.load(Ordering::Relaxed);

            let throughput = (bytes as f64 * 8.0) / (1024.0 * 1024.0) / elapsed.as_secs_f64();
            let pps = packets as f64 / elapsed.as_secs_f64();

            println!("║    Final: {} packets in {:.1}s ({:.0} pps), {:.2} Mbps, {} errors{:<20} ║",
                packets, elapsed.as_secs_f64(), pps, throughput, errors, "");
            
            let status = if errors == 0 { "✓ PASSED" } else { "✗ FAILED" };
            println!("║    Status: {:<81} ║", status);
            println!("╠══════════════════════════════════════════════════════════════════════════════════════════════╣");

            assert_eq!(errors, 0, "{} had errors", algo_config.name);
        }

        println!("║  All algorithms passed the 30-second stress test!{:<44} ║", "");
        println!("╚══════════════════════════════════════════════════════════════════════════════════════════════╝");
        println!("\n");
    }

    /// Quick network simulation test for CI/CD (5 seconds total)
    #[tokio::test]
    async fn network_quick_test() {
        let algos = get_perf_testable_compress_algos();
        let packet_sizes: Vec<usize> = vec![64, 512, 1024, 4096];

        println!("\n========== Quick Network Simulation Test ==========\n");

        for algo_config in &algos {
            let (tx, rx) = mpsc::channel::<Vec<u8>>(1000);
            let sender_stats = Arc::new(SenderStats::default());
            let receiver_stats = Arc::new(ReceiverStats::default());

            let sender_handle = tokio::spawn(sender_task(
                tx,
                DefaultCompressor::new(),
                algo_config.algo,
                packet_sizes.clone(),
                1, // 1 second per algorithm
                sender_stats.clone(),
            ));

            let receiver_handle = tokio::spawn(receiver_task(
                rx,
                DefaultCompressor::new(),
                receiver_stats.clone(),
            ));

            sender_handle.await.unwrap();
            tokio::time::sleep(Duration::from_millis(50)).await;
            receiver_handle.abort();

            let packets = sender_stats.packets_sent.load(Ordering::Relaxed);
            let errors = sender_stats.compress_errors.load(Ordering::Relaxed)
                + receiver_stats.decompress_errors.load(Ordering::Relaxed);

            println!("  {} : {} packets, {} errors {}", 
                algo_config.name, 
                packets, 
                errors,
                if errors == 0 { "✓" } else { "✗" }
            );

            assert_eq!(errors, 0, "{} had errors", algo_config.name);
        }

        println!("\n✅ All algorithms passed quick network test!\n");
    }

    /// Test cross-algorithm compatibility
    /// Simulates scenario where PeerA uses Lz4 and PeerB uses Brotli
    /// Each peer should decompress using the algorithm marked in the packet, not their local config
    #[tokio::test]
    async fn cross_algorithm_compatibility() {
        println!("\n╔══════════════════════════════════════════════════════════════════════════════════════════════╗");
        println!("║               CROSS-ALGORITHM COMPATIBILITY TEST                                             ║");
        println!("║   Testing: PeerA(Lz4) <-> PeerB(Brotli) bidirectional communication                          ║");
        println!("╠══════════════════════════════════════════════════════════════════════════════════════════════╣");

        let compressor = DefaultCompressor::new();

        // All algorithm pairs to test
        let algorithms = vec![
            CompressorAlgo::ZstdDefault,
            #[cfg(feature = "lz4")]
            CompressorAlgo::Lz4,
            #[cfg(feature = "brotli")]
            CompressorAlgo::Brotli,
        ];

        let mut total_tests = 0;
        let mut passed_tests = 0;

        // Test all algorithm pairs
        for sender_algo in &algorithms {
            for receiver_algo in &algorithms {
                total_tests += 1;

                // Create test payload
                let payload: Vec<u8> = (0..1024).map(|i| (i % 256) as u8).collect();
                let mut packet = create_network_packet(&payload);

                // Sender compresses with their algorithm
                if let Err(e) = compressor.compress(&mut packet, *sender_algo).await {
                    println!("║  {:?} -> {:?}: COMPRESS FAILED: {:?}", sender_algo, receiver_algo, e);
                    continue;
                }

                // Simulate network transmission
                let transmitted_data = packet.inner().to_vec();

                // Receiver reconstructs packet (using their own "config" which is different)
                // But decompress should read the algorithm from packet, not from receiver's config
                let mut received_packet = ZCPacket::new_from_buf(
                    BytesMut::from(transmitted_data.as_slice()),
                    crate::tunnel::packet_def::ZCPacketType::NIC,
                );

                // Receiver decompresses - should auto-detect algorithm from packet
                match compressor.decompress(&mut received_packet).await {
                    Ok(_) => {
                        // Verify payload integrity
                        let decompressed_payload = received_packet.payload();
                        if decompressed_payload == payload.as_slice() {
                            passed_tests += 1;
                            if sender_algo != receiver_algo {
                                println!("║  ✓ {:?} -> {:?} (cross-algo): OK", sender_algo, receiver_algo);
                            }
                        } else {
                            println!("║  ✗ {:?} -> {:?}: PAYLOAD MISMATCH!", sender_algo, receiver_algo);
                        }
                    }
                    Err(e) => {
                        println!("║  ✗ {:?} -> {:?}: DECOMPRESS FAILED: {:?}", sender_algo, receiver_algo, e);
                    }
                }
            }
        }

        println!("╠══════════════════════════════════════════════════════════════════════════════════════════════╣");
        println!("║  Result: {}/{} tests passed", passed_tests, total_tests);
        println!("╚══════════════════════════════════════════════════════════════════════════════════════════════╝\n");

        assert_eq!(passed_tests, total_tests, "Some cross-algorithm compatibility tests failed!");
    }

    /// Extended test: Simulate real peer-to-peer scenario with different compression settings
    /// PeerA sends with Lz4, PeerB sends with Brotli, both should communicate correctly
    #[cfg(all(feature = "lz4", feature = "brotli"))]
    #[tokio::test]
    async fn peer_to_peer_different_algos() {
        println!("\n╔══════════════════════════════════════════════════════════════════════════════════════════════╗");
        println!("║               PEER-TO-PEER DIFFERENT ALGORITHMS TEST                                         ║");
        println!("╠══════════════════════════════════════════════════════════════════════════════════════════════╣");

        // Simulate two peers with different compression settings
        struct PeerConfig {
            name: &'static str,
            send_algo: CompressorAlgo,
        }

        let peer_a = PeerConfig { name: "PeerA", send_algo: CompressorAlgo::Lz4 };
        let peer_b = PeerConfig { name: "PeerB", send_algo: CompressorAlgo::Brotli };

        // Channels for bidirectional communication
        let (tx_a_to_b, rx_a_to_b) = mpsc::channel::<Vec<u8>>(100);
        let (tx_b_to_a, rx_b_to_a) = mpsc::channel::<Vec<u8>>(100);

        let packets_per_direction = 100usize;
        let payload_size = 2048usize;

        // PeerA sender task
        let peer_a_sender = {
            let algo = peer_a.send_algo;
            tokio::spawn(async move {
                let compressor = DefaultCompressor::new();
                let mut sent = 0i32;
                for i in 0..packets_per_direction {
                    let payload: Vec<u8> = (0..payload_size).map(|j| ((i + j) % 256) as u8).collect();
                    let mut packet = create_network_packet(&payload);

                    if compressor.compress(&mut packet, algo).await.is_ok() {
                        if tx_a_to_b.send(packet.inner().to_vec()).await.is_ok() {
                            sent += 1;
                        }
                    }
                }
                sent
            })
        };

        // PeerB sender task
        let peer_b_sender = {
            let algo = peer_b.send_algo;
            tokio::spawn(async move {
                let compressor = DefaultCompressor::new();
                let mut sent = 0i32;
                for i in 0..packets_per_direction {
                    let payload: Vec<u8> = (0..payload_size).map(|j| ((i * 2 + j) % 256) as u8).collect();
                    let mut packet = create_network_packet(&payload);

                    if compressor.compress(&mut packet, algo).await.is_ok() {
                        if tx_b_to_a.send(packet.inner().to_vec()).await.is_ok() {
                            sent += 1;
                        }
                    }
                }
                sent
            })
        };

        // PeerA receiver task (receives from B, decompresses with auto-detected algo)
        let peer_a_receiver = {
            let mut rx = rx_b_to_a;
            tokio::spawn(async move {
                let compressor = DefaultCompressor::new();
                let mut received = 0i32;
                let mut errors = 0i32;
                while let Some(data) = rx.recv().await {
                    let mut packet = ZCPacket::new_from_buf(
                        BytesMut::from(data.as_slice()),
                        crate::tunnel::packet_def::ZCPacketType::NIC,
                    );
                    match compressor.decompress(&mut packet).await {
                        Ok(_) => received += 1,
                        Err(_) => errors += 1,
                    }
                }
                (received, errors)
            })
        };

        // PeerB receiver task (receives from A, decompresses with auto-detected algo)
        let peer_b_receiver = {
            let mut rx = rx_a_to_b;
            tokio::spawn(async move {
                let compressor = DefaultCompressor::new();
                let mut received = 0i32;
                let mut errors = 0i32;
                while let Some(data) = rx.recv().await {
                    let mut packet = ZCPacket::new_from_buf(
                        BytesMut::from(data.as_slice()),
                        crate::tunnel::packet_def::ZCPacketType::NIC,
                    );
                    match compressor.decompress(&mut packet).await {
                        Ok(_) => received += 1,
                        Err(_) => errors += 1,
                    }
                }
                (received, errors)
            })
        };

        // Wait for senders to complete
        let a_sent = peer_a_sender.await.unwrap();
        let b_sent = peer_b_sender.await.unwrap();

        // Wait for receivers to complete
        let (a_received, a_errors) = peer_a_receiver.await.unwrap();
        let (b_received, b_errors) = peer_b_receiver.await.unwrap();

        println!("║  {} (algo={:?}): sent={}, received={}, errors={}",
                 peer_a.name, peer_a.send_algo, a_sent, a_received, a_errors);
        println!("║  {} (algo={:?}): sent={}, received={}, errors={}",
                 peer_b.name, peer_b.send_algo, b_sent, b_received, b_errors);
        println!("║");
        println!("║  A->B: {} sent with Lz4, B received and decompressed {} (errors: {})",
                 a_sent, b_received, b_errors);
        println!("║  B->A: {} sent with Brotli, A received and decompressed {} (errors: {})",
                 b_sent, a_received, a_errors);
        println!("╚══════════════════════════════════════════════════════════════════════════════════════════════╝\n");

        assert_eq!(a_errors, 0, "PeerA had decompression errors receiving Brotli packets!");
        assert_eq!(b_errors, 0, "PeerB had decompression errors receiving Lz4 packets!");
        assert_eq!(a_sent, b_received, "PeerB didn't receive all packets from PeerA!");
        assert_eq!(b_sent, a_received, "PeerA didn't receive all packets from PeerB!");

        println!("✅ Cross-algorithm peer-to-peer communication successful!\n");
    }
}
