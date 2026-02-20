use derive_more::{Deref, DerefMut};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Default)]
#[serde(default)]
pub struct AclPolicy {
    pub whitelist: Option<Vec<String>>,
    pub blacklist: Option<Vec<String>>,
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Default, Deref, DerefMut)]
#[serde(default)]
pub struct FunctionalityPolicy {
    #[serde(flatten)]
    #[deref]
    #[deref_mut]
    acl: AclPolicy, // TODO
    pub disabled: bool,
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Default, Deref, DerefMut)]
#[serde(default)]
pub struct DnsPolicy<P = FunctionalityPolicy> {
    #[serde(flatten)]
    #[deref]
    #[deref_mut]
    policy: P,
    pub recursive: bool, // TODO
}

pub type ZoneExportPolicy = FunctionalityPolicy;
pub type DnsExportPolicy = DnsPolicy<ZoneExportPolicy>;
pub type DnsImportPolicy = DnsPolicy<FunctionalityPolicy>;

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Default)]
#[serde(default)]
pub struct DnsPolicyConfig {
    pub import: DnsImportPolicy,
    pub export: Option<DnsExportPolicy>,
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Default)]
#[serde(default)]
pub struct ZonePolicyConfig {
    #[serde(default)]
    pub export: Option<DnsExportPolicy>,
}
