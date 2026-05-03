use crate::common::config::ConfigBase;
use crate::dns::config::policy::{DnsExportPolicy, ZonePolicyConfig};
use crate::dns::utils::addr::NameServerAddrGroup;
use crate::dns::zone::Zone;
use crate::proto::dns::ZoneData;
use derive_more::From;
use hickory_proto::op::ResponseCode;
use hickory_proto::rr::LowerName;
use maplit::hashset;
use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use std::convert::TryFrom;
use std::net::{Ipv4Addr, Ipv6Addr};
use optionize::{optionized, Optionizable};

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Hash, From, Deserialize, Serialize)]
#[serde(untagged)]
pub enum Fallthrough {
    Any,
    ResponseCode(ResponseCode),
}

impl From<Fallthrough> for i32 {
    fn from(value: Fallthrough) -> Self {
        match value {
            Fallthrough::ResponseCode(code) => u16::from(code).into(),
            Fallthrough::Any => -1,
        }
    }
}

impl From<i32> for Fallthrough {
    fn from(value: i32) -> Self {
        match u16::try_from(value) {
            Ok(value) => Self::ResponseCode(value.into()),
            Err(_) => Self::Any,
        }
    }
}

#[optionized]
#[optionize(name = "ZoneConfigRaw")]
#[derive(Debug, Clone, Default, PartialEq, Deserialize, Serialize)]
pub struct ZoneConfigParsed {
    #[optionize(flatten)]
    pub origin: LowerName,
    pub ttl: u32,
    pub records: Vec<String>,
    pub forwarders: NameServerAddrGroup,
    #[optionize(flatten)]
    #[serde(flatten)]
    pub policy: ZonePolicyConfig,
    pub fallthrough: HashSet<Fallthrough>,
}

impl From<&ZoneConfigParsed> for ZoneData {
    fn from(value: &ZoneConfigParsed) -> Self {
        Self::new(
            &value.origin,
            value.ttl,
            &value.records,
            value.forwarders.iter().map(Into::into),
            value.fallthrough.iter().copied(),
        )
    }
}

pub type ZoneConfig = ConfigBase<ZoneConfigRaw, ZoneConfigParsed, ZoneData>;

impl TryFrom<ZoneConfigRaw> for ZoneConfig {
    type Error = anyhow::Error;

    fn try_from(raw: ZoneConfigRaw) -> Result<Self, Self::Error> {
        let mut parsed = ZoneConfigParsed {
            fallthrough: hashset! {Fallthrough::Any},
            ..Default::default()
        };
        parsed.load(raw.clone());
        let data = (&parsed).into();
        let _ = Zone::try_from(&data)?; // validation
        Ok(Self::new(parsed, raw, data))
    }
}

impl ZoneConfig {
    pub fn dedicated(origin: LowerName, ipv4: Option<Ipv4Addr>, ipv6: Vec<Ipv6Addr>) -> Self {
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

        let parsed = ZoneConfigParsed {
            origin,
            records,
            policy,
            ..Default::default()
        };

        let data = (&parsed).into();

        Self::new(parsed, Default::default(), data)
    }
}
