use serde::{Deserialize, Serialize};

/// Stable configuration vocabulary for every known compression algorithm.
#[derive(
    Debug,
    Default,
    Clone,
    Copy,
    PartialEq,
    Eq,
    Hash,
    strum::Display,
    strum::EnumString,
    Serialize,
    Deserialize,
)]
#[strum(ascii_case_insensitive)]
pub enum CompressionAlgorithm {
    #[default]
    #[strum(to_string = "none", serialize = "none", serialize = "")]
    #[serde(rename = "none", alias = "")]
    None,

    #[strum(to_string = "zstd", serialize = "zstd")]
    #[serde(rename = "zstd")]
    Zstd,
}
