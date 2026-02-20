use crate::dns::config::policy::{DnsExportPolicy, ZonePolicyConfig};
use crate::dns::utils::NameServerAddrGroup;
use crate::dns::zone::Zone;
use crate::proto::dns::ZoneData;
use derivative::Derivative;
use derive_more::{Deref, DerefMut, Into};
use hickory_proto::rr::LowerName;
use serde::{Deserialize, Serialize};
use std::convert::{TryFrom, TryInto};
use std::net::{Ipv4Addr, Ipv6Addr};
use uuid::Uuid;

#[derive(Derivative, Debug, Clone, Deserialize, Serialize, Default, Deref, DerefMut, Into)]
#[derivative(PartialEq)]
#[serde(try_from = "ZoneConfigInner", into = "ZoneConfigInner")]
pub struct ZoneConfig {
    #[into]
    #[derivative(PartialEq = "ignore")]
    data: ZoneData,
    #[into]
    #[deref]
    #[deref_mut]
    inner: ZoneConfigInner,
}

impl TryFrom<ZoneConfigInner> for ZoneConfig {
    type Error = anyhow::Error;

    fn try_from(value: ZoneConfigInner) -> Result<Self, Self::Error> {
        let data = ZoneData::from(value.clone());
        let _ = Zone::try_from(&data)?;
        Ok(Self { data, inner: value })
    }
}

impl ZoneConfig {
    pub fn dedicated(
        id: Option<Uuid>,
        origin: LowerName,
        ipv4: Option<Ipv4Addr>,
        ipv6: Vec<Ipv6Addr>,
    ) -> Option<Self> {
        let mut records = Vec::new();

        if let Some(ipv4) = ipv4 {
            records.push(format!("@ IN A {}", ipv4));
        }
        for ipv6 in ipv6 {
            records.push(format!("@ IN AAAA {}", ipv6));
        }

        let policy = ZonePolicyConfig {
            export: Some(DnsExportPolicy::default()),
        };

        if records.is_empty() {
            return None;
        }

        let config = ZoneConfigInner {
            id: id.unwrap_or_else(Uuid::new_v4),
            origin,
            records,
            policy,
            ..Default::default()
        };

        config.try_into().ok()
    }
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Default)]
pub struct ZoneConfigInner {
    #[serde(default = "Uuid::new_v4")]
    #[serde(skip_serializing)]
    id: Uuid,
    pub origin: LowerName,
    #[serde(default)]
    pub ttl: u32,
    #[serde(default)]
    pub records: Vec<String>,
    #[serde(default)]
    pub forwarders: NameServerAddrGroup,
    #[serde(flatten)]
    pub policy: ZonePolicyConfig,
}

impl From<ZoneConfigInner> for ZoneData {
    fn from(value: ZoneConfigInner) -> Self {
        Self {
            id: Some(value.id.into()),
            origin: value.origin.to_string(),
            records: value.records,
            forwarders: value.forwarders.into(),
        }
    }
}
