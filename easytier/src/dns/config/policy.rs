use derive_more::{Deref, DerefMut};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Default, Deserialize, Serialize)]
#[serde(default)]
pub struct AclPolicy {
    pub whitelist: Option<Vec<String>>,
    pub blacklist: Option<Vec<String>>,
}

#[derive(Debug, Clone, PartialEq, Default, Deserialize, Serialize, Deref, DerefMut)]
#[serde(default)]
pub struct FunctionalityPolicy {
    #[serde(flatten)]
    #[deref]
    #[deref_mut]
    acl: AclPolicy, // TODO
    pub disabled: bool,
}

#[derive(Debug, Clone, PartialEq, Default, Deserialize, Serialize, Deref, DerefMut)]
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

#[derive(Debug, Clone, PartialEq, Default, Deserialize, Serialize)]
#[serde(default)]
pub struct DnsPolicyConfig {
    pub import: DnsImportPolicy,
    pub export: Option<DnsExportPolicy>,
}

#[derive(Debug, Clone, PartialEq, Default, Deserialize, Serialize)]
#[serde(default)]
pub struct ZonePolicyConfig {
    pub export: Option<DnsExportPolicy>,
}
