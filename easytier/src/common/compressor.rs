use std::io::{Read, Write};

use dashmap::DashMap;
use std::cell::RefCell;
use zstd::stream::read::Decoder;
use zstd::stream::write::Encoder;
use zstd::zstd_safe::{CCtx, DCtx};

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
            CompressorAlgo::ZstdDefault => {
                let ret = CTX_MAP.with(|map_cell| {
                    let map = map_cell.borrow();
                    let mut ctx_entry = map.entry(compress_algo).or_default();
                    let writer = Vec::new();
                    let mut o = Encoder::with_context(writer, ctx_entry.value_mut());
                    o.write_all(data)?;
                    o.finish()
                });
                Ok(ret?)
            }
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
                let mut decoder = Decoder::with_context(data, ctx_entry.value_mut());
                let mut output = Vec::new();
                decoder.read_to_end(&mut output)?;
                Ok(output)
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
    static CTX_MAP: RefCell<DashMap<CompressorAlgo, CCtx<'static>>> = RefCell::new(DashMap::new());
    static DCTX_MAP: RefCell<DashMap<CompressorAlgo, DCtx<'static>>> = RefCell::new(DashMap::new());
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
        assert_eq!(packet.peer_manager_header().unwrap().is_compressed(), true);

        compressor.decompress(&mut packet).await.unwrap();
        assert_eq!(packet.payload(), text);
        assert_eq!(packet.peer_manager_header().unwrap().is_compressed(), false);
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
        assert_eq!(packet.peer_manager_header().unwrap().is_compressed(), false);

        compressor.decompress(&mut packet).await.unwrap();
        assert_eq!(packet.payload(), text);
        assert_eq!(packet.peer_manager_header().unwrap().is_compressed(), false);
    }
}
