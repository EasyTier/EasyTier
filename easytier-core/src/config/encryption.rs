use std::{fmt, str::FromStr};

use strum::VariantArray;

#[cfg(feature = "aes-gcm")]
#[path = "encryption/default_aes.rs"]
mod selected_default;
#[cfg(not(feature = "aes-gcm"))]
#[path = "encryption/default_xor.rs"]
mod selected_default;

/// Stable configuration vocabulary for every known encryption algorithm.
#[derive(Debug, Clone, Copy, PartialEq, Eq, VariantArray)]
pub enum EncryptionAlgorithm {
    Xor,
    AesGcm,
    Aes256Gcm,
    ChaCha20,
}

impl EncryptionAlgorithm {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Xor => "xor",
            Self::AesGcm => "aes-gcm",
            Self::Aes256Gcm => "aes-256-gcm",
            Self::ChaCha20 => "chacha20",
        }
    }
}

impl Default for EncryptionAlgorithm {
    fn default() -> Self {
        selected_default::DEFAULT
    }
}

impl fmt::Display for EncryptionAlgorithm {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

impl FromStr for EncryptionAlgorithm {
    type Err = ();

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value.to_ascii_lowercase().as_str() {
            "xor" => Ok(Self::Xor),
            "aes-gcm" => Ok(Self::AesGcm),
            "aes-256-gcm" => Ok(Self::Aes256Gcm),
            "chacha20" | "chacha20-poly1305" => Ok(Self::ChaCha20),
            _ => Err(()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn known_algorithm_names_are_stable() {
        let cases = [
            ("xor", EncryptionAlgorithm::Xor),
            ("aes-gcm", EncryptionAlgorithm::AesGcm),
            ("aes-256-gcm", EncryptionAlgorithm::Aes256Gcm),
            ("chacha20", EncryptionAlgorithm::ChaCha20),
            ("chacha20-poly1305", EncryptionAlgorithm::ChaCha20),
        ];

        for (name, expected) in cases {
            assert_eq!(name.parse(), Ok(expected));
        }
        assert_eq!(EncryptionAlgorithm::ChaCha20.to_string(), "chacha20");
    }

    #[cfg(feature = "aes-gcm")]
    #[test]
    fn aes_remains_the_default_when_compiled() {
        assert_eq!(EncryptionAlgorithm::default(), EncryptionAlgorithm::AesGcm);
    }

    #[cfg(not(feature = "aes-gcm"))]
    #[test]
    fn xor_remains_the_default_without_aes() {
        assert_eq!(EncryptionAlgorithm::default(), EncryptionAlgorithm::Xor);
    }
}
