use std::{fmt, marker::PhantomData, str::FromStr};

use anyhow::Context;
use cidr::{Cidr, Family, Ipv4Cidr, Ipv6Cidr};
use serde::{Deserialize, Deserializer, Serialize, de};

/// DHCP enablement and an optional subnet used before peers advertise one.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(untagged)]
pub enum DhcpConfig<C = Ipv4Cidr> {
    Enabled(bool),
    Cidr(C),
}

impl<C> Default for DhcpConfig<C> {
    fn default() -> Self {
        Self::Enabled(false)
    }
}

impl<C: Cidr> DhcpConfig<C> {
    pub fn enabled(self) -> bool {
        !matches!(self, Self::Enabled(false))
    }

    pub fn cidr(self) -> Option<C> {
        match self {
            Self::Enabled(_) => None,
            Self::Cidr(cidr) => Some(cidr),
        }
    }

    pub fn from_cidr(value: &str) -> anyhow::Result<Self> {
        let cidr: C = value
            .parse()
            .with_context(|| format!("invalid DHCP CIDR: {value}"))?;
        match cidr.family() {
            Family::Ipv4 => anyhow::ensure!(
                cidr.network_length() <= 30,
                "DHCP IPv4 CIDR must have usable host addresses (prefix length 0..=30)"
            ),
            Family::Ipv6 => {
                let subnet: Ipv6Cidr = value.parse()?;
                anyhow::ensure!(
                    valid_ipv6_subnet(subnet),
                    "DHCP IPv6 CIDR must be a unicast subnet within fc00::/7 or 2000::/3, with prefix length at most 126"
                );
            }
        }
        Ok(Self::Cidr(cidr))
    }
}

impl<C: Cidr> FromStr for DhcpConfig<C> {
    type Err = anyhow::Error;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value.parse::<bool>() {
            Ok(enabled) => Ok(Self::Enabled(enabled)),
            Err(_) => Self::from_cidr(value),
        }
    }
}

impl<'de, C: Cidr> Deserialize<'de> for DhcpConfig<C> {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        struct DhcpVisitor<C>(PhantomData<C>);

        impl<C: Cidr> de::Visitor<'_> for DhcpVisitor<C> {
            type Value = DhcpConfig<C>;

            fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter.write_str("a boolean or a usable DHCP CIDR")
            }

            fn visit_bool<E: de::Error>(self, value: bool) -> Result<Self::Value, E> {
                Ok(DhcpConfig::Enabled(value))
            }

            fn visit_str<E: de::Error>(self, value: &str) -> Result<Self::Value, E> {
                DhcpConfig::from_cidr(value).map_err(E::custom)
            }
        }

        deserializer.deserialize_any(DhcpVisitor(PhantomData))
    }
}

// Only overlay unicast subnets are eligible for automatic assignment. Keep at
// least two candidates after reserving the subnet endpoints.
pub(crate) fn valid_ipv6_subnet(subnet: Ipv6Cidr) -> bool {
    let first = subnet.first_address().segments()[0];
    subnet.network_length() <= 126
        && ((subnet.network_length() >= 7 && first & 0xfe00 == 0xfc00)
            || (subnet.network_length() >= 3 && first & 0xe000 == 0x2000))
}
