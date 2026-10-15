include!(concat!(env!("OUT_DIR"), "/core_config.rs"));
include!(concat!(env!("OUT_DIR"), "/core_config.serde.rs"));

impl From<Vec<DnsZoneConfigRaw>> for RepeatedDnsZoneConfigRaw {
    fn from(items: Vec<DnsZoneConfigRaw>) -> Self {
        Self { items }
    }
}
