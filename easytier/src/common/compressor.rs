use async_compression::tokio::write::{ZstdDecoder, ZstdEncoder};
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
        let buf = match compress_algo {
            CompressorAlgo::ZstdDefault => {
                let mut o = ZstdEncoder::new(Vec::new());
                o.write_all(data).await?;
                o.shutdown().await?;
                o.into_inner()
            }
            CompressorAlgo::None => data.to_vec(),
        };

        Ok(buf)
    }

    pub async fn decompress_raw(
        &self,
        data: &[u8],
        compress_algo: CompressorAlgo,
    ) -> Result<Vec<u8>, Error> {
        let buf = match compress_algo {
            CompressorAlgo::ZstdDefault => {
                let mut o = ZstdDecoder::new(Vec::new());
                o.write_all(data).await?;
                o.shutdown().await?;
                o.into_inner()
            }
            CompressorAlgo::None => data.to_vec(),
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

#[cfg(test)]
pub mod tests {
    use super::*;

    #[tokio::test]
    async fn test_compress() {
        let text = b"12345670000000000000000000";
        let mut packet = ZCPacket::new_with_payload(text);
        packet.fill_peer_manager_hdr(0, 0, 0);

        let compressor = DefaultCompressor {};

        compressor
            .compress(&mut packet, CompressorAlgo::ZstdDefault)
            .await
            .unwrap();
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
