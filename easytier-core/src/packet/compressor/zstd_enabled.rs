use std::cell::RefCell;

use anyhow::Context as _;
use dashmap::DashMap;
use zstd::bulk;

use super::CompressorAlgo;

pub(super) const AVAILABLE: bool = true;

thread_local! {
    static CTX_MAP: RefCell<DashMap<CompressorAlgo, bulk::Compressor<'static>>> =
        RefCell::new(DashMap::new());
    static DCTX_MAP: RefCell<DashMap<CompressorAlgo, bulk::Decompressor<'static>>> =
        RefCell::new(DashMap::new());
}

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
