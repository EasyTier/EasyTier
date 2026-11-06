#[cfg(feature = "lzo")]
use anyhow::Context as _;

use super::CompressorAlgo;

#[cfg(feature = "lzo")]
pub(super) fn compress(data: &[u8], compress_algo: CompressorAlgo) -> anyhow::Result<Vec<u8>> {
    lzokay_native::compress(data).with_context(|| {
        format!(
            "Failed to compress data with algorithm: {:?}",
            compress_algo
        )
    })
}

#[cfg(not(feature = "lzo"))]
pub(super) fn compress(_data: &[u8], compress_algo: CompressorAlgo) -> anyhow::Result<Vec<u8>> {
    Err(super::super::CompressionUnavailableError(compress_algo).into())
}

#[cfg(feature = "lzo")]
pub(super) fn decompress(data: &[u8], compress_algo: CompressorAlgo) -> anyhow::Result<Vec<u8>> {
    // Match the maximum output size allowed by the Zstd path.
    let max_size = data.len().saturating_mul(32).max(64 * 1024);
    lzokay_native::decompress_all_bounded(data, max_size).with_context(|| {
        format!(
            "Failed to decompress data with algorithm: {:?}",
            compress_algo
        )
    })
}

#[cfg(not(feature = "lzo"))]
pub(super) fn decompress(_data: &[u8], compress_algo: CompressorAlgo) -> anyhow::Result<Vec<u8>> {
    Err(super::super::CompressionUnavailableError(compress_algo).into())
}
