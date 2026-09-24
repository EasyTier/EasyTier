#[cfg(feature = "zstd")]
use std::cell::RefCell;

#[cfg(feature = "zstd")]
use anyhow::Context as _;
#[cfg(feature = "zstd")]
use dashmap::DashMap;
#[cfg(feature = "zstd")]
use zstd::bulk;

use super::CompressorAlgo;

#[cfg(feature = "zstd")]
pub(super) const AVAILABLE: bool = true;
#[cfg(not(feature = "zstd"))]
pub(super) const AVAILABLE: bool = false;

#[cfg(feature = "zstd")]
thread_local! {
    static CTX_MAP: RefCell<DashMap<CompressorAlgo, bulk::Compressor<'static>>> =
        RefCell::new(DashMap::new());
    static DCTX_MAP: RefCell<DashMap<CompressorAlgo, bulk::Decompressor<'static>>> =
        RefCell::new(DashMap::new());
}

#[cfg(feature = "zstd")]
pub(super) fn compress(data: &[u8], compress_algo: CompressorAlgo) -> anyhow::Result<Vec<u8>> {
    CTX_MAP.with(|map_cell| {
        let map = map_cell.borrow();
        let mut ctx_entry = map.entry(compress_algo).or_default();
        ctx_entry.compress(data).with_context(|| {
            format!(
                "Failed to compress data with algorithm: {:?}",
                compress_algo
            )
        })
    })
}

#[cfg(not(feature = "zstd"))]
pub(super) fn compress(_data: &[u8], compress_algo: CompressorAlgo) -> anyhow::Result<Vec<u8>> {
    unavailable(compress_algo)
}

#[cfg(feature = "zstd")]
pub(super) fn decompress(data: &[u8], compress_algo: CompressorAlgo) -> anyhow::Result<Vec<u8>> {
    DCTX_MAP.with(|map_cell| {
        let map = map_cell.borrow();
        let mut ctx_entry = map.entry(compress_algo).or_default();
        for i in 1..=5 {
            let mut len = data.len() * 2usize.pow(i);
            if i == 5 && len < 64 * 1024 {
                len = 64 * 1024;
            }
            match ctx_entry.decompress(data, len) {
                Ok(buf) => return Ok(buf),
                Err(error) if error.to_string().contains("buffer is too small") => continue,
                Err(error) => return Err(error.into()),
            }
        }
        Err(anyhow::anyhow!(
            "Failed to decompress data after multiple attempts with algorithm: {:?}",
            compress_algo
        ))
    })
}

#[cfg(not(feature = "zstd"))]
pub(super) fn decompress(_data: &[u8], compress_algo: CompressorAlgo) -> anyhow::Result<Vec<u8>> {
    unavailable(compress_algo)
}

#[cfg(not(feature = "zstd"))]
fn unavailable(compress_algo: CompressorAlgo) -> anyhow::Result<Vec<u8>> {
    Err(super::super::CompressionUnavailableError(compress_algo).into())
}
