#[cfg(feature = "zstd")]
use anyhow::Context;
#[cfg(feature = "zstd")]
use dashmap::DashMap;
#[cfg(feature = "zstd")]
use std::cell::RefCell;
use std::io::{Read as IoRead, Write as IoWrite};
#[cfg(feature = "zstd")]
use zstd::bulk;

use zerocopy::{AsBytes as _, FromBytes as _};

use crate::tunnel::packet_def::{CompressorAlgo, CompressorTail, ZCPacket, COMPRESSOR_TAIL_SIZE};

type Error = anyhow::Error;

#[async_trait::async_trait]
pub trait Compressor {
    async fn compress(
        &self,
        packet: &mut ZCPacket,
        compress_algo: CompressorAlgo,
    ) -> Result<(), Error>;
    async fn decompress(&self, packet: &mut ZCPacket) -> Result<(), Error>;
}

pub struct DefaultCompressor {}

impl Default for DefaultCompressor {
    fn default() -> Self {
        Self::new()
    }
}

impl DefaultCompressor {
    pub fn new() -> Self {
        DefaultCompressor {}
    }

    pub async fn compress_raw(
        &self,
        data: &[u8],
        compress_algo: CompressorAlgo,
    ) -> Result<Vec<u8>, Error> {
        match compress_algo {
            #[cfg(feature = "zstd")]
            CompressorAlgo::ZstdDefault => CTX_MAP.with(|map_cell| {
                let map = map_cell.borrow();
                let mut ctx_entry = map.entry(compress_algo).or_default();
                ctx_entry.compress(data).with_context(|| {
                    format!(
                        "Failed to compress data with algorithm: {:?}",
                        compress_algo
                    )
                })
            }),

            CompressorAlgo::Lz4 => {
                let compressed = lz4_flex::compress_prepend_size(data);
                Ok(compressed)
            }

            CompressorAlgo::Gzip => {
                let mut encoder =
                    flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
                encoder.write_all(data).with_context(|| {
                    format!(
                        "Failed to compress data with algorithm: {:?}",
                        compress_algo
                    )
                })?;
                encoder.finish().with_context(|| {
                    format!(
                        "Failed to finish compression with algorithm: {:?}",
                        compress_algo
                    )
                })
            }

            CompressorAlgo::Brotli => {
                // Use batch API instead of streaming API to ensure errors are properly returned
                // CompressorWriter's Drop implementation ignores errors, which can cause data loss
                let mut params = brotli::enc::BrotliEncoderParams::default();
                params.quality = 6;  // quality (0-11, 6 is a good balance)
                params.lgwin = 22;   // lgwin (window size, 22 is default)

                let mut compressed = Vec::new();
                let mut input = std::io::Cursor::new(data);
                brotli::BrotliCompress(&mut input, &mut compressed, &params)
                    .with_context(|| {
                        format!(
                            "Failed to compress data with algorithm: {:?}",
                            compress_algo
                        )
                    })?;
                Ok(compressed)
            }

            CompressorAlgo::Lzo => LZO_INSTANCE.with(|lzo_cell| {
                let mut lzo = lzo_cell.borrow_mut();
                let compressed = lzo
                    .compress(data)
                    .map_err(|e| anyhow::anyhow!("Failed to compress with LZO: {:?}", e))?;
                // Prepend original size for decompression (4 bytes, little-endian)
                let mut result = Vec::with_capacity(4 + compressed.len());
                result.extend_from_slice(&(data.len() as u32).to_le_bytes());
                result.extend_from_slice(&compressed);
                Ok(result)
            }),

            CompressorAlgo::None => Ok(data.to_vec()),
        }
    }

    pub async fn decompress_raw(
        &self,
        data: &[u8],
        compress_algo: CompressorAlgo,
    ) -> Result<Vec<u8>, Error> {
        match compress_algo {
            #[cfg(feature = "zstd")]
            CompressorAlgo::ZstdDefault => DCTX_MAP.with(|map_cell| {
                let map = map_cell.borrow();
                let mut ctx_entry = map.entry(compress_algo).or_default();
                for i in 1..=5 {
                    let mut len = data.len() * 2usize.pow(i);
                    if i == 5 && len < 64 * 1024 {
                        len = 64 * 1024; // Ensure a minimum buffer size
                    }
                    match ctx_entry.decompress(data, len) {
                        Ok(buf) => return Ok(buf),
                        Err(e) if e.to_string().contains("buffer is too small") => {
                            continue; // Try with a larger buffer
                        }
                        Err(e) => return Err(e.into()),
                    }
                }
                Err(anyhow::anyhow!(
                    "Failed to decompress data after multiple attempts with algorithm: {:?}",
                    compress_algo
                ))
            }),

            CompressorAlgo::Lz4 => {
                lz4_flex::decompress_size_prepended(data).map_err(|e| {
                    anyhow::anyhow!("Failed to decompress with LZ4: {:?}", e)
                })
            }

            CompressorAlgo::Gzip => {
                let mut decoder = flate2::read::GzDecoder::new(data);
                let mut decompressed = Vec::new();
                decoder.read_to_end(&mut decompressed).with_context(|| {
                    format!(
                        "Failed to decompress data with algorithm: {:?}",
                        compress_algo
                    )
                })?;
                Ok(decompressed)
            }

            CompressorAlgo::Brotli => {
                // Use batch API for consistency with compress and proper error handling
                let mut decompressed = Vec::new();
                let mut input = std::io::Cursor::new(data);
                brotli::BrotliDecompress(&mut input, &mut decompressed)
                    .with_context(|| {
                        format!(
                            "Failed to decompress data with algorithm: {:?}",
                            compress_algo
                        )
                    })?;
                Ok(decompressed)
            }

            CompressorAlgo::Lzo => {
                if data.len() < 4 {
                    return Err(anyhow::anyhow!(
                        "LZO compressed data too short: {} bytes",
                        data.len()
                    ));
                }
                // Read original size from first 4 bytes
                let original_size =
                    u32::from_le_bytes([data[0], data[1], data[2], data[3]]) as usize;
                let compressed_data = &data[4..];

                LZO_INSTANCE.with(|lzo_cell| {
                    let lzo = lzo_cell.borrow();
                    lzo.decompress_safe(compressed_data, original_size)
                        .map_err(|e| anyhow::anyhow!("Failed to decompress with LZO: {:?}", e))
                })
            }

            CompressorAlgo::None => Ok(data.to_vec()),
        }
    }
}

#[async_trait::async_trait]
impl Compressor for DefaultCompressor {
    async fn compress(
        &self,
        zc_packet: &mut ZCPacket,
        compress_algo: CompressorAlgo,
    ) -> Result<(), Error> {
        if matches!(compress_algo, CompressorAlgo::None) {
            return Ok(());
        }

        let pm_header = zc_packet.peer_manager_header().unwrap();
        if pm_header.is_compressed() {
            return Ok(());
        }

        let tail = CompressorTail::new(compress_algo);
        let buf = self
            .compress_raw(zc_packet.payload(), compress_algo)
            .await?;

        if buf.len() + COMPRESSOR_TAIL_SIZE > pm_header.len.get() as usize {
            // Compressed data is larger than original data, don't compress
            return Ok(());
        }

        zc_packet
            .mut_peer_manager_header()
            .unwrap()
            .set_compressed(true);

        let payload_offset = zc_packet.payload_offset();
        zc_packet.mut_inner().truncate(payload_offset);
        zc_packet.mut_inner().extend_from_slice(&buf);
        zc_packet.mut_inner().extend_from_slice(tail.as_bytes());

        Ok(())
    }

    async fn decompress(&self, zc_packet: &mut ZCPacket) -> Result<(), Error> {
        let pm_header = zc_packet.peer_manager_header().unwrap();
        if !pm_header.is_compressed() {
            return Ok(());
        }

        let payload_len = zc_packet.payload().len();
        if payload_len < COMPRESSOR_TAIL_SIZE {
            return Err(anyhow::anyhow!("Packet too short: {}", payload_len));
        }

        let text_len = payload_len - COMPRESSOR_TAIL_SIZE;

        let tail = CompressorTail::ref_from_suffix(zc_packet.payload())
            .unwrap()
            .clone();

        let algo = tail
            .get_algo()
            .ok_or(anyhow::anyhow!("Unknown algo: {:?}", tail))?;

        let buf = self
            .decompress_raw(&zc_packet.payload()[..text_len], algo)
            .await?;

        if buf.len() != pm_header.len.get() as usize {
            anyhow::bail!(
                "Decompressed length mismatch: decompressed len {} != pm header len {}",
                buf.len(),
                pm_header.len.get()
            );
        }

        zc_packet
            .mut_peer_manager_header()
            .unwrap()
            .set_compressed(false);

        let payload_offset = zc_packet.payload_offset();
        zc_packet.mut_inner().truncate(payload_offset);
        zc_packet.mut_inner().extend_from_slice(&buf);

        Ok(())
    }
}

#[cfg(feature = "zstd")]
thread_local! {
    static CTX_MAP: RefCell<DashMap<CompressorAlgo, bulk::Compressor<'static>>> = RefCell::new(DashMap::new());
    static DCTX_MAP: RefCell<DashMap<CompressorAlgo, bulk::Decompressor<'static>>> = RefCell::new(DashMap::new());

    // LZO instance cache - LZO::init() is expensive and should only be called once per thread
    static LZO_INSTANCE: RefCell<minilzo_rs::LZO> = RefCell::new(
        minilzo_rs::LZO::init().expect("Failed to initialize LZO")
    );
}

#[cfg(all(test, feature = "zstd"))]
pub mod tests {
    use super::*;

    #[tokio::test]
    async fn test_compress() {
        let text = b"12345670000000000000000000";
        let mut packet = ZCPacket::new_with_payload(text);
        packet.fill_peer_manager_hdr(0, 0, 0);

        let compressor = DefaultCompressor {};

        println!(
            "Uncompressed packet: {:?}, len: {}",
            packet,
            packet.payload_len()
        );

        compressor
            .compress(&mut packet, CompressorAlgo::ZstdDefault)
            .await
            .unwrap();
        println!(
            "Compressed packet: {:?}, len: {}",
            packet,
            packet.payload_len()
        );
        assert!(packet.peer_manager_header().unwrap().is_compressed());

        compressor.decompress(&mut packet).await.unwrap();
        assert_eq!(packet.payload(), text);
        assert!(!packet.peer_manager_header().unwrap().is_compressed());
    }

    #[tokio::test]
    async fn test_short_text_compress() {
        let text = b"1234";
        let mut packet = ZCPacket::new_with_payload(text);
        packet.fill_peer_manager_hdr(0, 0, 0);

        let compressor = DefaultCompressor {};

        // short text can't be compressed
        compressor
            .compress(&mut packet, CompressorAlgo::ZstdDefault)
            .await
            .unwrap();
        assert!(!packet.peer_manager_header().unwrap().is_compressed());

        compressor.decompress(&mut packet).await.unwrap();
        assert_eq!(packet.payload(), text);
        assert!(!packet.peer_manager_header().unwrap().is_compressed());
    }

    #[tokio::test]
    async fn test_all_algorithms_roundtrip() {
        let algorithms = [
            CompressorAlgo::ZstdDefault,
            CompressorAlgo::Lz4,
            CompressorAlgo::Gzip,
            CompressorAlgo::Brotli,
            CompressorAlgo::Lzo,
        ];

        let text = b"Hello, this is a test message for compression algorithms! ".repeat(10);
        let compressor = DefaultCompressor {};

        for algo in algorithms {
            let mut packet = ZCPacket::new_with_payload(&text);
            packet.fill_peer_manager_hdr(0, 0, 0);

            compressor.compress(&mut packet, algo).await.unwrap();

            if packet.peer_manager_header().unwrap().is_compressed() {
                compressor.decompress(&mut packet).await.unwrap();
                assert_eq!(packet.payload(), text.as_slice(), "Algorithm {:?} failed roundtrip", algo);
            }
        }
    }

    /// Test simulating real network transmission with channel-based communication
    /// This simulates the actual peer_manager data flow: compress -> channel -> decompress
    #[tokio::test]
    async fn test_network_transmission_simulation() {
        use std::sync::atomic::{AtomicU64, Ordering};
        use std::sync::Arc;
        use tokio::sync::mpsc;
        use tokio::time::{Duration, Instant};

        let algorithms = [
            ("Zstd", CompressorAlgo::ZstdDefault),
            ("LZ4", CompressorAlgo::Lz4),
            ("Gzip", CompressorAlgo::Gzip),
            ("Brotli", CompressorAlgo::Brotli),
            ("LZO", CompressorAlgo::Lzo),
        ];

        // Generate test data patterns (similar to screen capture / remote desktop data)
        let mut test_patterns: Vec<Vec<u8>> = Vec::new();

        // Pattern 1: Small packets (like control messages) - 64 bytes
        let pattern1: Vec<u8> = (0..64).map(|i| (i * 3) as u8).collect();
        test_patterns.push(pattern1);

        // Pattern 2: Medium packets (like small screen regions) - 1KB with repetition
        let mut pattern2 = vec![0u8; 1024];
        for i in 0..1024 {
            pattern2[i] = ((i % 256) as u8).wrapping_add((i / 256) as u8);
        }
        test_patterns.push(pattern2);

        // Pattern 3: Larger packets (like image data) - 8KB with mixed patterns
        let mut pattern3 = vec![0u8; 8192];
        let mut seed: u64 = 42;
        for (i, byte) in pattern3.iter_mut().enumerate() {
            if i % 100 < 70 {
                // 70% repetitive (like solid color regions)
                *byte = ((i / 100) % 256) as u8;
            } else {
                // 30% random (like edges/details)
                seed = seed.wrapping_mul(6364136223846793005).wrapping_add(1);
                *byte = (seed >> 33) as u8;
            }
        }
        test_patterns.push(pattern3);

        // Pattern 4: Large packet with high entropy (worst case for compression) - 16KB
        let mut pattern4 = vec![0u8; 16384];
        let mut seed: u64 = 12345;
        for byte in pattern4.iter_mut() {
            seed = seed.wrapping_mul(6364136223846793005).wrapping_add(1);
            *byte = (seed >> 33) as u8;
        }
        test_patterns.push(pattern4);

        println!("\n=== Network Transmission Simulation Test ===");
        println!("Simulating: compress -> channel transfer -> decompress");
        println!("Test duration: 3 seconds per algorithm, concurrent senders\n");

        for (name, algo) in &algorithms {
            // Channel to simulate network transmission (similar to peer_manager)
            let (tx, mut rx) = mpsc::channel::<ZCPacket>(256);

            let success_count = Arc::new(AtomicU64::new(0));
            let fail_count = Arc::new(AtomicU64::new(0));
            let total_bytes_sent = Arc::new(AtomicU64::new(0));
            let total_latency_us = Arc::new(AtomicU64::new(0));

            let algo_clone = *algo;
            let patterns_clone = test_patterns.clone();
            let success_clone = success_count.clone();
            let fail_clone = fail_count.clone();
            let bytes_clone = total_bytes_sent.clone();

            // Sender task (simulates peer sending compressed data)
            let sender_handle = tokio::spawn(async move {
                let compressor = DefaultCompressor {};
                let start = Instant::now();
                let duration = Duration::from_secs(3);
                let mut packet_id: u64 = 0;

                while start.elapsed() < duration {
                    for pattern in &patterns_clone {
                        if start.elapsed() >= duration {
                            break;
                        }

                        let mut packet = ZCPacket::new_with_payload(pattern);
                        packet.fill_peer_manager_hdr(packet_id as u32, 0, 0);
                        packet_id += 1;

                        // Compress (like peer_manager does before sending)
                        if let Err(_e) = compressor.compress(&mut packet, algo_clone).await {
                            fail_clone.fetch_add(1, Ordering::Relaxed);
                            continue;
                        }

                        bytes_clone.fetch_add(packet.buf_len() as u64, Ordering::Relaxed);

                        // Send through channel (simulates network transfer)
                        if tx.send(packet).await.is_err() {
                            break;
                        }
                    }
                }
                // Signal completion
                drop(tx);
            });

            let latency_clone = total_latency_us.clone();
            let success_recv = success_count.clone();
            let fail_recv = fail_count.clone();
            let patterns_for_verify = test_patterns.clone();

            // Receiver task (simulates peer receiving and decompressing)
            let receiver_handle = tokio::spawn(async move {
                let compressor = DefaultCompressor {};

                while let Some(mut packet) = rx.recv().await {
                    let recv_time = Instant::now();
                    let packet_id = packet.peer_manager_header().unwrap().from_peer_id.get();
                    let pattern_idx = (packet_id as usize) % patterns_for_verify.len();
                    let expected_pattern = &patterns_for_verify[pattern_idx];

                    // Decompress (like peer_manager does after receiving)
                    if packet.peer_manager_header().unwrap().is_compressed() {
                        if let Err(_e) = compressor.decompress(&mut packet).await {
                            fail_recv.fetch_add(1, Ordering::Relaxed);
                            continue;
                        }
                    }

                    // Verify data integrity
                    if packet.payload() == expected_pattern.as_slice() {
                        success_recv.fetch_add(1, Ordering::Relaxed);
                    } else {
                        fail_recv.fetch_add(1, Ordering::Relaxed);
                    }

                    latency_clone.fetch_add(recv_time.elapsed().as_micros() as u64, Ordering::Relaxed);
                }
            });

            // Wait for both tasks
            let _ = sender_handle.await;
            let _ = receiver_handle.await;

            let success = success_count.load(Ordering::Relaxed);
            let fail = fail_count.load(Ordering::Relaxed);
            let bytes = total_bytes_sent.load(Ordering::Relaxed);
            let total_latency = total_latency_us.load(Ordering::Relaxed);

            let avg_latency_us = if success > 0 {
                total_latency as f64 / success as f64
            } else {
                0.0
            };

            let throughput_mbps = (bytes as f64 * 8.0) / (3.0 * 1_000_000.0);

            println!(
                "{:8}: {:6} ok, {:4} fail | throughput: {:7.2} Mbps | avg decompress latency: {:8.2} µs",
                name, success, fail, throughput_mbps, avg_latency_us
            );

            // Allow some margin for edge cases, but most should succeed
            let total = success + fail;
            let success_rate = if total > 0 { success as f64 / total as f64 } else { 0.0 };
            assert!(
                success_rate > 0.99,
                "Algorithm {} success rate too low: {:.2}%",
                name,
                success_rate * 100.0
            );
        }

        println!("\n=== Test Complete ===\n");
    }
}
