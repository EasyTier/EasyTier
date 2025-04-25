#[cfg(feature = "zstd")]
use async_compression::tokio::write::{ZstdDecoder, ZstdEncoder};
#[cfg(feature = "brotli")]
use async_compression::tokio::write::{BrotliDecoder, BrotliEncoder};
#[cfg(feature = "lz4")]
use async_compression::tokio::write::{Lz4Decoder, Lz4Encoder};
#[cfg(feature = "gzip")]
use async_compression::tokio::write::{GzipDecoder, GzipEncoder};
#[cfg(feature = "deflate")]
use async_compression::tokio::write::{DeflateDecoder, DeflateEncoder};
#[cfg(feature = "bzip2")]
use async_compression::tokio::write::{BzDecoder, BzEncoder};
#[cfg(feature = "lzma")]
use async_compression::tokio::write::{LzmaDecoder, LzmaEncoder};
#[cfg(feature = "xz")]
use async_compression::tokio::write::{XzDecoder, XzEncoder};
#[cfg(feature = "zlib")]
use async_compression::tokio::write::{ZlibDecoder, ZlibEncoder};

use tokio::io::AsyncWriteExt;

use zerocopy::{AsBytes as _, FromBytes as _};

use crate::tunnel::packet_def::{CompressorAlgo, CompressorTail, ZCPacket, COMPRESSOR_TAIL_SIZE};

type Error = anyhow::Error;

#[async_trait::async_trait]
pub trait Compressor {
    async fn compress(
        &self,
        packet: &mut ZCPacket,
        compress_algo: CompressorAlgo,
        compress_level: i32,
    ) -> Result<(), Error>;
    async fn decompress(&self, packet: &mut ZCPacket) -> Result<(), Error>;
}

pub struct DefaultCompressor {}

impl DefaultCompressor {
    pub fn new() -> Self {
        DefaultCompressor {}
    }

    pub async fn compress_raw(
        &self,
        data: &[u8],
        compress_algo: CompressorAlgo,
        compress_level: i32,
    ) -> Result<Vec<u8>, Error> {
        let buf = match compress_algo {
            #[cfg(feature = "zstd")]
            CompressorAlgo::Zstd => {
                let quality = if compress_level == 0 { 3 } else { compress_level };
                let mut o = ZstdEncoder::with_quality(Vec::new(), async_compression::Level::Precise(quality));
                o.write_all(data).await?;
                o.shutdown().await?;
                o.into_inner()
            }
            #[cfg(feature = "brotli")]
            CompressorAlgo::Brotli => {
                let quality = if compress_level == 0 { 11 } else { compress_level };
                let mut o = BrotliEncoder::with_quality(Vec::new(), async_compression::Level::Precise(quality));
                o.write_all(data).await?;
                o.shutdown().await?;
                o.into_inner()
            }
            #[cfg(feature = "lz4")]
            CompressorAlgo::Lz4 => {
                let quality = if compress_level == 0 { 12 } else { compress_level };
                let mut o = Lz4Encoder::with_quality(Vec::new(), async_compression::Level::Precise(quality));
                o.write_all(data).await?;
                o.shutdown().await?;
                o.into_inner()
            }
            #[cfg(feature = "gzip")]
            CompressorAlgo::Gzip => {
                let mut o = GzipEncoder::new(Vec::new());
                o.write_all(data).await?;
                o.shutdown().await?;
                o.into_inner()
            }
            #[cfg(feature = "deflate")]
            CompressorAlgo::Deflate => {
                let mut o = DeflateEncoder::new(Vec::new());
                o.write_all(data).await?;
                o.shutdown().await?;
                o.into_inner()
            }
            #[cfg(feature = "bzip2")]
            CompressorAlgo::Bzip2 => {
                let quality = if compress_level == 0 { 9 } else { compress_level };
                let mut o = BzEncoder::with_quality(Vec::new(), async_compression::Level::Precise(quality));
                o.write_all(data).await?;
                o.shutdown().await?;
                o.into_inner()
            }
            #[cfg(feature = "lzma")]
            CompressorAlgo::Lzma => {
                let quality = if compress_level == 0 { 9 } else { compress_level };
                let mut o = LzmaEncoder::with_quality(Vec::new(), async_compression::Level::Precise(quality));
                o.write_all(data).await?;
                o.shutdown().await?;
                o.into_inner()
            }
            #[cfg(feature = "xz")]
            CompressorAlgo::Xz => {
                let mut o = XzEncoder::new(Vec::new());
                o.write_all(data).await?;
                o.shutdown().await?;
                o.into_inner()
            }
            #[cfg(feature = "zlib")]
            CompressorAlgo::Zlib => {
                let mut o = ZlibEncoder::new(Vec::new());
                o.write_all(data).await?;
                o.shutdown().await?;
                o.into_inner()
            }
            CompressorAlgo::None => data.to_vec(),
            #[allow(unreachable_patterns)]
            _ => return Err(anyhow::anyhow!("This compression algorithm is not enabled. Please enable the corresponding feature in Cargo.toml!")),
        };
        Ok(buf)
    }

    pub async fn decompress_raw(
        &self,
        data: &[u8],
        compress_algo: CompressorAlgo
    ) -> Result<Vec<u8>, Error> {
        let buf = match compress_algo {
            #[cfg(feature = "zstd")]
            CompressorAlgo::Zstd => {
                let mut o = ZstdDecoder::new(Vec::new());
                o.write_all(data).await?;
                o.shutdown().await?;
                o.into_inner()
            }
            #[cfg(feature = "brotli")]
            CompressorAlgo::Brotli => {
                let mut o = BrotliDecoder::new(Vec::new());
                o.write_all(data).await?;
                o.shutdown().await?;
                o.into_inner()
            }
            #[cfg(feature = "lz4")]
            CompressorAlgo::Lz4 => {
                let mut o = Lz4Decoder::new(Vec::new());
                o.write_all(data).await?;
                o.shutdown().await?;
                o.into_inner()
            }
            #[cfg(feature = "gzip")]
            CompressorAlgo::Gzip => {
                let mut o = GzipDecoder::new(Vec::new());
                o.write_all(data).await?;
                o.shutdown().await?;
                o.into_inner()
            }
            #[cfg(feature = "deflate")]
            CompressorAlgo::Deflate => {
                let mut o = DeflateDecoder::new(Vec::new());
                o.write_all(data).await?;
                o.shutdown().await?;
                o.into_inner()
            }
            #[cfg(feature = "bzip2")]
            CompressorAlgo::Bzip2 => {
                let mut o = BzDecoder::new(Vec::new());
                o.write_all(data).await?;
                o.shutdown().await?;
                o.into_inner()
            }
            #[cfg(feature = "lzma")]
            CompressorAlgo::Lzma => {
                let mut o = LzmaDecoder::new(Vec::new());
                o.write_all(data).await?;
                o.shutdown().await?;
                o.into_inner()
            }
            #[cfg(feature = "xz")]
            CompressorAlgo::Xz => {
                let mut o = XzDecoder::new(Vec::new());
                o.write_all(data).await?;
                o.shutdown().await?;
                o.into_inner()
            }
            #[cfg(feature = "zlib")]
            CompressorAlgo::Zlib => {
                let mut o = ZlibDecoder::new(Vec::new());
                o.write_all(data).await?;
                o.shutdown().await?;
                o.into_inner()
            }
            CompressorAlgo::None => data.to_vec(),
            #[allow(unreachable_patterns)]
            _ => return Err(anyhow::anyhow!("This decompression algorithm is not enabled. Please enable the corresponding feature in Cargo.toml!")),
        };
        Ok(buf)
    }
}

#[async_trait::async_trait]
impl Compressor for DefaultCompressor {
    async fn compress(
        &self,
        zc_packet: &mut ZCPacket,
        compress_algo: CompressorAlgo,
        compress_level: i32,
    ) -> Result<(), Error> {
        if compress_algo.is_none() {
            return Ok(());
        }

        let pm_header = zc_packet.peer_manager_header().unwrap();
        if pm_header.is_compressed() {
            return Ok(());
        }

        let tail = CompressorTail::new(compress_algo);
        let buf = self
            .compress_raw(zc_packet.payload(), compress_algo, compress_level)
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

        let algo = tail.get_algo();

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

#[cfg(test)]
pub mod tests {
    use super::*;

    #[tokio::test]
    async fn test_all_compression_algorithms() {
        let algorithms = [
            CompressorAlgoEx::None,
            CompressorAlgoEx::Zstd,
            CompressorAlgoEx::Brotli,
            // CompressorAlgoEx::Lz4,
            // CompressorAlgoEx::Gzip,
            CompressorAlgoEx::Deflate,
            // CompressorAlgoEx::Bzip2,
            // CompressorAlgoEx::Lzma,
            // CompressorAlgoEx::Xz,
            CompressorAlgoEx::Zlib,
        ];

        let normal_text = b"12345670000000000000000000";
        let short_text = b"1234";
        
        let compressor = DefaultCompressor {};
        

        println!("===== 测试正常文本压缩 =====");
        for &algo in &algorithms {
            let mut packet = ZCPacket::new_with_payload(normal_text);
            packet.fill_peer_manager_hdr(0, 0, 0);
            
            compressor.compress(&mut packet, algo, 0).await.unwrap();
            
            let expected_compressed = !algo.is_none();
            assert_eq!(
                packet.peer_manager_header().unwrap().is_compressed(), 
                expected_compressed,
                "算法 {:?} 压缩状态与预期不符", algo
            );
            
            compressor.decompress(&mut packet).await.unwrap();
            
            assert_eq!(
                packet.payload(), normal_text,
                "算法 {:?} 解压后数据与原始数据不一致", algo
            );
            
            assert_eq!(
                packet.peer_manager_header().unwrap().is_compressed(), false,
                "算法 {:?} 解压后压缩状态标志未正确重置", algo
            );
            
            println!("算法 {:?} 测试通过", algo);
        }
        
        println!("===== 测试短文本压缩 =====");
        for &algo in &algorithms {
            let mut packet = ZCPacket::new_with_payload(short_text);
            packet.fill_peer_manager_hdr(0, 0, 0);
            
            compressor.compress(&mut packet, algo, 0).await.unwrap();
            
            assert_eq!(
                packet.peer_manager_header().unwrap().is_compressed(), false,
                "算法 {:?} 对短文本的压缩结果与预期不符", algo
            );
            
            compressor.decompress(&mut packet).await.unwrap();
            
            assert_eq!(
                packet.payload(), short_text,
                "算法 {:?} 解压后数据与原始数据不一致", algo
            );
            
            assert_eq!(
                packet.peer_manager_header().unwrap().is_compressed(), false,
                "算法 {:?} 解压后压缩状态标志未正确重置", algo
            );
            
            println!("算法 {:?} 短文本测试通过", algo);
        }
    }

    #[tokio::test]
    async fn test_all_compress_ratio() {
        let text = b"12345670000000000000000000abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789".repeat(1000000);
        let compressor = DefaultCompressor {};
        let algos = [
            (CompressorAlgoEx::None, "None", false),
            (CompressorAlgoEx::Zstd, "Zstd", true),
            (CompressorAlgoEx::Brotli, "Brotli", true),
            (CompressorAlgoEx::Lz4, "Lz4", true),
            (CompressorAlgoEx::Gzip, "Gzip", false),
            (CompressorAlgoEx::Deflate, "Deflate", false),
            (CompressorAlgoEx::Bzip2, "Bzip2", true),
            (CompressorAlgoEx::Lzma, "Lzma", true),
            (CompressorAlgoEx::Xz, "Xz", false),
            (CompressorAlgoEx::Zlib, "Zlib", false),
        ];
        let levels = [1u16, 3, 5, 7, 9];
        for (algo, name, has_level) in algos.iter() {
            if *has_level {
                for &level in &levels {
                    let mut packet = ZCPacket::new_with_payload(&text);
                    packet.fill_peer_manager_hdr(0, 0, 0);
                    compressor.compress(&mut packet, *algo, level).await.unwrap();
                    let compressed_len = packet.payload().len();
                    compressor.decompress(&mut packet).await.unwrap();
                    let decompressed = packet.payload();
                    assert_eq!(decompressed, &text[..]);
                    let ratio = compressed_len as f64 / text.len() as f64;
                    println!("{}(level {}) 压缩比: {:.2}% ({} -> {})", name, level, ratio * 100.0, text.len(), compressed_len);
                }
            } else {
                let mut packet = ZCPacket::new_with_payload(&text);
                packet.fill_peer_manager_hdr(0, 0, 0);
                compressor.compress(&mut packet, *algo, 0).await.unwrap();
                let compressed_len = packet.payload().len();
                compressor.decompress(&mut packet).await.unwrap();
                let decompressed = packet.payload();
                assert_eq!(decompressed, &text[..]);
                let ratio = compressed_len as f64 / text.len() as f64;
                println!("{} 压缩比: {:.2}% ({} -> {})", name, ratio * 100.0, text.len(), compressed_len);
            }
        }
    }
}
