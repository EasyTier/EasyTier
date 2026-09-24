use crate::config::dns::addr::{NameServerAddr, NameServerAddrGroup};
use crate::config::dns::base::ConfigBase;
use crate::config::dns::policy::{DnsExportPolicy, ZonePolicyConfig};
use crate::proto::dns::ZoneData;
use hickory_proto::rr::LowerName;
use maplit::hashset;
use optionize::{Optionizable, optionized};
use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use std::convert::TryFrom;
use std::net::{Ipv4Addr, Ipv6Addr};

pub use easytier_proto::dns::Fallthrough;

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
        let data: ZoneData = (&parsed).into();
        let _ = hickory_proto::serialize::txt::Parser::new(&data.content, None, None)
            .parse()
            .map_err(|e| anyhow::anyhow!("failed to parse zone data: {e}"))?;
        let _ = data
            .forwarders
            .iter()
            .map(NameServerAddr::try_from)
            .collect::<Result<Vec<_>, _>>()?;
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
