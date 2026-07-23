use super::CompressorAlgo;

pub(super) const AVAILABLE: bool = false;

pub(super) fn compress(_data: &[u8], compress_algo: CompressorAlgo) -> anyhow::Result<Vec<u8>> {
    unavailable(compress_algo)
}

pub(super) fn decompress(_data: &[u8], compress_algo: CompressorAlgo) -> anyhow::Result<Vec<u8>> {
    unavailable(compress_algo)
}

fn unavailable(compress_algo: CompressorAlgo) -> anyhow::Result<Vec<u8>> {
    Err(super::super::CompressionUnavailableError(compress_algo).into())
}
