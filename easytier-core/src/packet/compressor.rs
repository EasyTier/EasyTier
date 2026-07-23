use zerocopy::{AsBytes as _, FromBytes as _};

use super::{COMPRESSOR_TAIL_SIZE, CompressorAlgo, CompressorTail, ZCPacket};

#[cfg(feature = "zstd")]
#[path = "compressor/zstd_enabled.rs"]
mod zstd_backend;
#[cfg(not(feature = "zstd"))]
#[path = "compressor/zstd_disabled.rs"]
mod zstd_backend;

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
            CompressorAlgo::ZstdDefault => zstd_backend::compress(data, compress_algo),
            CompressorAlgo::None => Ok(data.to_vec()),
        }
    }

    pub async fn decompress_raw(
        &self,
        data: &[u8],
        compress_algo: CompressorAlgo,
    ) -> Result<Vec<u8>, Error> {
        match compress_algo {
            CompressorAlgo::ZstdDefault => zstd_backend::decompress(data, compress_algo),
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

pub(super) fn zstd_available() -> bool {
    zstd_backend::AVAILABLE
}

#[cfg(test)]
pub mod tests {
    use super::*;

    #[cfg(feature = "zstd")]
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

    #[cfg(feature = "zstd")]
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

    #[cfg(not(feature = "zstd"))]
    #[tokio::test]
    async fn unavailable_zstd_returns_an_explicit_error() {
        let error = DefaultCompressor::new()
            .compress_raw(b"payload", CompressorAlgo::ZstdDefault)
            .await
            .unwrap_err();

        assert_eq!(
            error.to_string(),
            "compression algorithm is unavailable in this build: ZstdDefault"
        );
    }
}
