use std::{fmt, str::FromStr};

use anyhow::Context;
use cidr::Ipv4Cidr;
use serde::{Deserialize, Deserializer, Serialize, de};

/// DHCP enablement and an optional subnet used before peers advertise one.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(untagged)]
pub enum DhcpConfig {
    Enabled(bool),
    Cidr(Ipv4Cidr),
}

impl Default for DhcpConfig {
    fn default() -> Self {
        Self::Enabled(false)
    }
}

impl DhcpConfig {
    pub fn enabled(self) -> bool {
        !matches!(self, Self::Enabled(false))
    }

    pub fn cidr(self) -> Option<Ipv4Cidr> {
        match self {
            Self::Enabled(_) => None,
            Self::Cidr(cidr) => Some(cidr),
        }
    }

    pub fn from_cidr(value: &str) -> anyhow::Result<Self> {
        let cidr: Ipv4Cidr = value
            .parse()
            .with_context(|| format!("invalid DHCP IPv4 CIDR: {value}"))?;
        anyhow::ensure!(
            cidr.network_length() <= 30,
            "DHCP IPv4 CIDR must have usable host addresses (prefix length 0..=30)"
        );
        Ok(Self::Cidr(cidr))
    }
}

impl FromStr for DhcpConfig {
    type Err = anyhow::Error;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value.parse::<bool>() {
            Ok(enabled) => Ok(Self::Enabled(enabled)),
            Err(_) => Self::from_cidr(value),
        }
    }
}

impl<'de> Deserialize<'de> for DhcpConfig {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        struct DhcpVisitor;

        impl de::Visitor<'_> for DhcpVisitor {
            type Value = DhcpConfig;

            fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter.write_str("a boolean or an IPv4 CIDR with prefix length 0..=30")
            }

            fn visit_bool<E: de::Error>(self, value: bool) -> Result<Self::Value, E> {
                Ok(DhcpConfig::Enabled(value))
            }

            fn visit_str<E: de::Error>(self, value: &str) -> Result<Self::Value, E> {
                DhcpConfig::from_cidr(value).map_err(E::custom)
            }
        }

        deserializer.deserialize_any(DhcpVisitor)
    }
}
