use std::{fmt, str::FromStr};

use strum::VariantArray;

/// Stable configuration vocabulary for every known encryption algorithm.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq, VariantArray)]
pub enum EncryptionAlgorithm {
    Xor,
    #[default]
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
            "aes-gcm" | "openssl-aes-gcm" => Ok(Self::AesGcm),
            "aes-256-gcm" | "openssl-aes-256-gcm" => Ok(Self::Aes256Gcm),
            "chacha20" | "chacha20-poly1305" | "openssl-chacha20" => Ok(Self::ChaCha20),
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
            ("openssl-aes-gcm", EncryptionAlgorithm::AesGcm),
            ("openssl-aes-256-gcm", EncryptionAlgorithm::Aes256Gcm),
            ("openssl-chacha20", EncryptionAlgorithm::ChaCha20),
        ];

        for (name, expected) in cases {
            assert_eq!(name.parse(), Ok(expected));
        }
        assert_eq!(EncryptionAlgorithm::ChaCha20.to_string(), "chacha20");
    }

    #[test]
    fn aes_is_the_stable_default() {
        assert_eq!(EncryptionAlgorithm::default(), EncryptionAlgorithm::AesGcm);
    }
}
