use crate::common::config::ConfigBase;
use crate::dns::config::policy::{DnsExportPolicy, ZonePolicyConfig};
use crate::dns::utils::addr::NameServerAddrGroup;
use crate::dns::zone::Zone;
use crate::proto::dns::ZoneData;
use hickory_proto::rr::LowerName;
use optional_struct::{Applicable, optional_struct};
use serde::{Deserialize, Serialize};
use std::convert::TryFrom;
use std::net::{Ipv4Addr, Ipv6Addr};
use url::Url;

#[optional_struct(ZoneConfigRaw)]
#[derive(Debug, Clone, Default, PartialEq, Deserialize, Serialize)]
pub struct ZoneConfigParsed {
    #[optional_skip_wrap]
    pub origin: LowerName,
    pub ttl: u32,
    pub records: Vec<String>,
    pub forwarders: NameServerAddrGroup,
    #[optional_skip_wrap]
    #[serde(flatten)]
    pub policy: ZonePolicyConfig,
    pub fallthrough: bool,
}

impl From<&ZoneConfigParsed> for ZoneData {
    fn from(value: &ZoneConfigParsed) -> Self {
        Self::new(
            &value.origin,
            value.ttl,
            &value.records,
            value.forwarders.iter().map(Url::from),
            value.fallthrough,
        )
    }
}

pub type ZoneConfig = ConfigBase<ZoneConfigRaw, ZoneConfigParsed, ZoneData>;

impl TryFrom<ZoneConfigRaw> for ZoneConfig {
    type Error = anyhow::Error;

    fn try_from(raw: ZoneConfigRaw) -> Result<Self, Self::Error> {
        let default = ZoneConfigParsed {
            fallthrough: true,
            ..Default::default()
        };

        let parsed = raw.clone().build(default);
        let data = (&parsed).into();
        let _ = Zone::try_from(&data)?; // validation

        Ok(Self::new(raw, parsed, data))
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

        Self::new(Default::default(), parsed, data)
    }
}
