pub use easytier_core::packet::*;

pub fn compressor_algo_from_pb(
    value: crate::proto::common::CompressionAlgoPb,
) -> anyhow::Result<CompressorAlgo> {
    Ok(CompressorAlgo::try_from(value)?)
}

pub fn compressor_algo_to_pb(value: CompressorAlgo) -> crate::proto::common::CompressionAlgoPb {
    crate::proto::common::CompressionAlgoPb::try_from(value)
        .expect("CompressorAlgo should always map to CompressionAlgoPb")
}
