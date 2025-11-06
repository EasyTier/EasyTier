use anyhow::Context;
use dashmap::DashMap;
use std::cell::RefCell;
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
            CompressorAlgo::None => Ok(data.to_vec()),
        }
    }

    pub async fn decompress_raw(
        &self,
        data: &[u8],
        compress_algo: CompressorAlgo,
    ) -> Result<Vec<u8>, Error> {
        match compress_algo {
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

thread_local! {
    static CTX_MAP: RefCell<DashMap<CompressorAlgo, bulk::Compressor<'static>>> = RefCell::new(DashMap::new());
    static DCTX_MAP: RefCell<DashMap<CompressorAlgo, bulk::Decompressor<'static>>> = RefCell::new(DashMap::new());
}

#[cfg(test)]
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
}
