use crate::dns::config::policy::{DnsExportPolicy, ZonePolicyConfig};
use crate::dns::utils::addr::NameServerAddrGroup;
use crate::dns::zone::Zone;
use crate::proto::dns::ZoneData;
use derivative::Derivative;
use derive_more::{Deref, Into};
use hickory_proto::rr::LowerName;
use serde::{Deserialize, Serialize};
use std::convert::{TryFrom, TryInto};
use std::net::{Ipv4Addr, Ipv6Addr};
use uuid::Uuid;

#[derive(Derivative, Debug, Clone, Deserialize, Serialize, Default, Deref, Into)]
#[derivative(PartialEq)]
#[serde(try_from = "ZoneConfigInner", into = "ZoneConfigInner")]
pub struct ZoneConfig {
    #[into]
    #[derivative(PartialEq = "ignore")]
    data: ZoneData,
    // User-facing config source of truth used for serde round-trips.
    // Keep this in sync with `data` by rebuilding a full ZoneConfig via TryFrom.
    // Do not mutate subfields in place and expect `data` to follow.
    #[into]
    #[deref]
    inner: ZoneConfigInner,
}

impl TryFrom<ZoneConfigInner> for ZoneConfig {
    type Error = anyhow::Error;

    fn try_from(value: ZoneConfigInner) -> Result<Self, Self::Error> {
        // Rebuild both representations together and validate zone semantics.
        // Config updates should follow this replacement path.
        let data = ZoneData::from(value.clone());
        let _ = Zone::try_from(&data)?; // validation
        Ok(Self { data, inner: value })
    }
}

impl ZoneConfig {
    pub fn dedicated(
        id: Option<Uuid>,
        origin: LowerName,
        ipv4: Option<Ipv4Addr>,
        ipv6: Vec<Ipv6Addr>,
    ) -> anyhow::Result<Self> {
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

        let config = ZoneConfigInner {
            id: id.unwrap_or_else(Uuid::new_v4),
            origin,
            records,
            policy,
            ..Default::default()
        };

        config.try_into()
    }
}

#[derive(Derivative, Debug, Clone, PartialEq, Deserialize, Serialize)]
#[derivative(Default)]
#[serde(default)]
pub struct ZoneConfigInner {
    #[derivative(Default(value = "Uuid::new_v4()"))]
    #[serde(skip_serializing)]
    id: Uuid,
    pub origin: LowerName,
    pub ttl: u32,
    pub records: Vec<String>,
    pub forwarders: NameServerAddrGroup,
    #[serde(flatten)]
    pub policy: ZonePolicyConfig,
    #[derivative(Default(value = "true"))]
    pub fallthrough: bool,
}

impl From<ZoneConfigInner> for ZoneData {
    fn from(value: ZoneConfigInner) -> Self {
        Self {
            id: Some(value.id.into()),
            origin: value.origin.to_string(),
            ttl: value.ttl,
            records: value.records,
            forwarders: value.forwarders.into(),
            fallthrough: value.fallthrough,
        }
    }
}
