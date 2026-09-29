//! Complete EasyTier TOML configuration model.

use std::net::SocketAddr;

pub use super::{
    EncryptionAlgorithm, InstanceConfig, InstanceConfigRaw, gateway::PortForwardConfig,
};
#[cfg(feature = "rich-config-errors")]
use ariadne::{CharSet, Config as AriadneConfig, IndexType, Label, Report, ReportKind, Source};
use serde::{Deserialize, Serialize};



pub const DEFAULT_ET_DNS_ZONE: &str = "et.net.";

pub use crate::proto::common::{Flags, FlagsPatch};

pub(crate) fn default_instance_name() -> String {
    "default".to_owned()
}

pub trait LoggingConfigLoader {
    fn get_file_logger_config(&self) -> FileLoggerConfig;

    fn get_console_logger_config(&self) -> ConsoleLoggerConfig;
}

pub use super::NetworkIdentity;

#[derive(Debug, Clone, Copy, Deserialize, Serialize, PartialEq, Eq, Default)]
#[serde(rename_all = "snake_case")]
pub enum ConfigSource {
    #[default]
    User,
    Web,
}

impl ConfigSource {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::User => "user",
            Self::Web => "web",
        }
    }
}

impl std::str::FromStr for ConfigSource {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "user" => Ok(Self::User),
            "web" => Ok(Self::Web),
            other => Err(format!("unknown network config source: {other}")),
        }
    }
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq, Default)]
pub struct ConfigSourceConfig {
    pub source: ConfigSource,
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq)]
pub struct PeerConfig {
    pub uri: url::Url,
    pub peer_public_key: Option<String>,
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq)]
pub struct ProxyNetworkConfig {
    pub cidr: cidr::Ipv4Cidr,                // the CIDR of the proxy network
    pub mapped_cidr: Option<cidr::Ipv4Cidr>, // allow remap the proxy CIDR to another CIDR
    pub allow: Option<Vec<String>>,
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Default)]
pub struct FileLoggerConfig {
    pub level: Option<String>,
    pub file: Option<String>,
    pub dir: Option<String>,
    pub size_mb: Option<u64>,
    pub count: Option<usize>,
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Default)]
pub struct ConsoleLoggerConfig {
    pub level: Option<String>,
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, bon::Builder)]
pub struct LoggingConfig {
    #[builder(into)]
    pub file_logger: Option<FileLoggerConfig>,
    #[builder(into)]
    pub console_logger: Option<ConsoleLoggerConfig>,
}

impl LoggingConfigLoader for &LoggingConfig {
    fn get_file_logger_config(&self) -> FileLoggerConfig {
        self.file_logger.clone().unwrap_or_default()
    }

    fn get_console_logger_config(&self) -> ConsoleLoggerConfig {
        self.console_logger.clone().unwrap_or_default()
    }
}

#[derive(Clone, Deserialize, Serialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct VpnPortalConfig {
    pub wireguard_listen: SocketAddr,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub wireguard_private_key: Option<String>,
    #[serde(default)]
    pub clients: Vec<VpnPortalClientConfig>,
}

impl std::fmt::Debug for VpnPortalConfig {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("VpnPortalConfig")
            .field("wireguard_listen", &self.wireguard_listen)
            .field(
                "wireguard_private_key",
                &self.wireguard_private_key.as_ref().map(|_| "<redacted>"),
            )
            .field("clients", &self.clients)
            .finish()
    }
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct VpnPortalClientConfig {
    pub name: String,
    pub virtual_ip: cidr::Ipv4Inet,
    #[serde(default)]
    pub groups: Vec<String>,
}

fn default_true() -> bool {
    true
}

#[optionize::optionized]
#[cfg_attr(any(feature = "web-client", feature = "browser-config"), optionize(object = easytier_proto::api::manage::ManagedCredentialConfig))]
#[derive(Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ManagedCredentialConfig {
    #[optionize(flatten)]
    pub credential_id: String,
    #[optionize(flatten)]
    pub credential_secret: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    #[optionize(flatten)]
    pub groups: Vec<String>,
    #[serde(default)]
    #[optionize(flatten)]
    pub allow_relay: bool,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    #[optionize(flatten)]
    pub allowed_proxy_cidrs: Vec<String>,
    #[optionize(flatten)]
    pub expiry_unix: i64,
    #[serde(default = "default_true")]
    // The mapped field is `Option<bool>` (the protocol spells it `optional bool`),
    // so this document default does not describe it.
    #[optionize(attrs(.., -serde), default = |_| default_true())]
    pub reusable: bool,
}

impl std::fmt::Debug for ManagedCredentialConfig {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("ManagedCredentialConfig")
            .field("credential_id", &self.credential_id)
            .field("credential_secret", &"<redacted>")
            .field("groups", &self.groups)
            .field("allow_relay", &self.allow_relay)
            .field("allowed_proxy_cidrs", &self.allowed_proxy_cidrs)
            .field("expiry_unix", &self.expiry_unix)
            .field("reusable", &self.reusable)
            .finish()
    }
}

#[cfg(feature = "rich-config-errors")]
fn format_toml_parse_error(source_name: &str, config_str: &str, error: &toml::de::Error) -> String {
    let message = format!("failed to parse config TOML from {source_name}");

    let Some(span) = error.span() else {
        return format!("{message}\ndetail: {error}");
    };

    let mut output = Vec::new();
    let report = Report::build(ReportKind::Error, (source_name, span.clone()))
        .with_config(
            AriadneConfig::default()
                .with_color(false)
                .with_char_set(CharSet::Ascii)
                .with_index_type(IndexType::Byte),
        )
        .with_message(&message)
        .with_label(Label::new((source_name, span)).with_message(error.message()))
        .finish();

    if report
        .write((source_name, Source::from(config_str)), &mut output)
        .is_ok()
    {
        String::from_utf8_lossy(&output).into_owned()
    } else {
        format!("{message}\ndetail: {error}")
    }
}

#[cfg(not(feature = "rich-config-errors"))]
fn format_toml_parse_error(
    source_name: &str,
    _config_str: &str,
    error: &toml::de::Error,
) -> String {
    format!("failed to parse config TOML from {source_name}: {error}")
}


pub fn normalize_config_source(config: &mut InstanceConfigRaw) {
    if matches!(
        config.source.as_ref().map(|source| source.source),
        Some(ConfigSource::User)
    ) {
        config.source = None;
    }
}

#[cfg(feature = "config-write")]
pub fn redact_secrets(config: &mut InstanceConfigRaw) {
    const REDACTED: &str = "<redacted>";

    if let Some(secret) = config
        .network_identity
        .as_mut()
        .and_then(|identity| identity.network_secret.as_mut())
        && !secret.is_empty()
    {
        *secret = REDACTED.to_owned();
    }
    if let Some(private_key) = config
        .secure_mode
        .as_mut()
        .and_then(|secure_mode| secure_mode.local_private_key.as_mut())
        && !private_key.is_empty()
    {
        *private_key = REDACTED.to_owned();
    }
    if let Some(private_key) = config
        .vpn_portal_config
        .as_mut()
        .and_then(|portal| portal.wireguard_private_key.as_mut())
        && !private_key.is_empty()
    {
        *private_key = REDACTED.to_owned();
    }
    if let Some(declarations) = config
        .acl
        .as_mut()
        .and_then(|acl| acl.acl_v1.as_mut())
        .and_then(|acl| acl.group.as_mut())
        .map(|group| &mut group.declares)
    {
        for declaration in declarations {
            if !declaration.group_secret.is_empty() {
                declaration.group_secret = REDACTED.to_owned();
            }
        }
    }
    if let Some(credentials) = config.managed_credentials.as_mut() {
        for credential in credentials {
            if !credential.credential_secret.is_empty() {
                credential.credential_secret = REDACTED.to_owned();
            }
        }
    }
}

pub fn parse_instance_config(
    source_name: &str,
    config_str: &str,
) -> anyhow::Result<InstanceConfig> {
    let mut config = toml::de::from_str::<InstanceConfigRaw>(config_str).map_err(|err| {
        let message = format_toml_parse_error(source_name, config_str, &err);
        anyhow::Error::new(err).context(message)
    })?;

    normalize_config_source(&mut config);

    InstanceConfig::try_from(config).map_err(|err| {
        let message = format!("failed to load config from {source_name}: {err}");
        err.context(message)
    })
}

#[cfg(feature = "config-write")]
pub fn serialize_raw_to_toml(raw: &InstanceConfigRaw) -> Result<String, toml::ser::Error> {
    let mut config = raw.clone();
    normalize_config_source(&mut config);
    toml::to_string_pretty(&config)
}

#[cfg(not(feature = "config-write"))]
pub fn serialize_raw_to_toml(_raw: &InstanceConfigRaw) -> Result<String, toml::ser::Error> {
    panic!("this build does not include TOML configuration serialization")
}

#[cfg(feature = "config-write")]
pub fn serialize_raw_to_toml_redacted(raw: &InstanceConfigRaw) -> Result<String, toml::ser::Error> {
    let mut config = raw.clone();
    normalize_config_source(&mut config);
    redact_secrets(&mut config);
    toml::to_string_pretty(&config)
}

#[cfg(not(feature = "config-write"))]
pub fn serialize_raw_to_toml_redacted(
    _raw: &InstanceConfigRaw,
) -> Result<String, toml::ser::Error> {
    panic!("this build does not include TOML configuration serialization")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_error_preserves_source_and_location() {
        let error =
            parse_instance_config("fixture.toml", "dhcp = \"yes\"").unwrap_err();
        let display = error.to_string();

        assert!(display.contains("fixture.toml"));
        assert!(display.contains("dhcp = \"yes\""));
        assert!(display.contains("invalid type: string"));
        assert!(
            error
                .chain()
                .any(|cause| cause.downcast_ref::<toml::de::Error>().is_some())
        );
    }

    #[cfg(feature = "config-write")]
    #[test]
    fn toml_round_trip_preserves_config_and_non_default_flags() {
        let config = parse_instance_config(
            "inline config",
            r#"
instance_name = "node-a"
instance_id = "018f85a8-a9d0-7d4c-b73d-4ab62c048a20"
hostname = "host-a"
listeners = ["tcp://0.0.0.0:11010"]

[network_identity]
network_name = "network-a"
network_secret = "secret-a"

[flags]
mtu = 1420
socket_mark = 0
"#,
        )
        .unwrap();

        let dumped = serialize_raw_to_toml(config.raw()).unwrap();
        let restored = parse_instance_config("inline config", &dumped).unwrap();

        assert_eq!(restored.parsed().instance_id, config.parsed().instance_id);
        assert_eq!(restored.parsed().hostname, "host-a");
        assert_eq!(
            restored.parsed().network_identity,
            config.parsed().network_identity
        );
        assert_eq!(restored.parsed().listeners, config.parsed().listeners);
        assert_eq!(restored.parsed().flags.mtu, 1420);
        assert_eq!(restored.parsed().flags.socket_mark, Some(0));
    }

    #[test]
    fn legacy_vpn_portal_client_cidr_is_rejected_explicitly() {
        let error = parse_instance_config(
            "inline config",
            r#"
[vpn_portal_config]
client_cidr = "10.14.14.0/24"
wireguard_listen = "0.0.0.0:51820"
"#,
        )
        .unwrap_err()
        .to_string();

        assert!(error.contains("client_cidr"), "{error}");
    }

    #[cfg(feature = "config-write")]
    #[test]
    fn vpn_portal_round_trip_and_redacted_dump_preserve_dump_semantics() {
        let config = parse_instance_config(
            "inline config",
            r#"
[network_identity]
network_name = "network-a"
network_secret = "network-secret"

[secure_mode]
enabled = true
local_private_key = "YWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWE="

[vpn_portal_config]
wireguard_listen = "0.0.0.0:51820"
wireguard_private_key = "wireguard-private-key"

[[vpn_portal_config.clients]]
name = "alice"
virtual_ip = "10.144.144.10/24"
groups = ["staff"]

[acl.acl_v1.group]

[[acl.acl_v1.group.declares]]
group_name = "staff"
group_secret = "group-secret"
"#,
        )
        .unwrap();

        let dumped = serialize_raw_to_toml(config.raw()).unwrap();
        assert!(dumped.contains("network-secret"));
        assert!(dumped.contains("YWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWE="));
        assert!(dumped.contains("wireguard-private-key"));
        assert!(dumped.contains("group-secret"));
        assert_eq!(
            parse_instance_config("inline config", &dumped)
                .unwrap()
                .parsed()
                .vpn_portal_config,
            config.parsed().vpn_portal_config
        );

        let redacted = serialize_raw_to_toml_redacted(config.raw()).unwrap();
        assert!(!redacted.contains("network-secret"));
        assert!(!redacted.contains("YWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWE="));
        assert!(!redacted.contains("wireguard-private-key"));
        assert!(!redacted.contains("group-secret"));
        assert_eq!(redacted.matches("<redacted>").count(), 4);
    }

    #[cfg(feature = "config-write")]
    #[test]
    fn managed_credentials_round_trip_and_redact_secret() {
        let config = parse_instance_config(
            "inline config",
            r#"
[[managed_credentials]]
credential_id = "managed-a"
credential_secret = "private-key-material"
groups = ["ops"]
allow_relay = true
allowed_proxy_cidrs = ["10.0.0.0/24"]
expiry_unix = 2000000000
"#,
        )
        .unwrap();

        let dumped = serialize_raw_to_toml(config.raw()).unwrap();
        let restored = parse_instance_config("inline config", &dumped).unwrap();
        assert_eq!(
            restored.parsed().managed_credentials,
            config.parsed().managed_credentials
        );
        assert!(dumped.contains("private-key-material"));

        let redacted = serialize_raw_to_toml_redacted(config.raw()).unwrap();
        assert!(!redacted.contains("private-key-material"));
        assert!(redacted.contains("<redacted>"));
        assert!(!serialize_raw_to_toml(&InstanceConfigRaw::default())
            .unwrap()
            .contains("managed_credentials"));
    }

    #[test]
    fn hostname_normalization_is_portable_and_has_no_host_fallback() {
        let absent = InstanceConfig::try_from(InstanceConfigRaw::default()).unwrap();
        assert_eq!(absent.parsed().hostname, "");

        let configured =
            parse_instance_config("inline config", "hostname = \"node\\u0007-name\"").unwrap();
        assert_eq!(configured.parsed().hostname, "node-name");
    }

    #[test]
    fn credential_mode_does_not_synthesize_a_network_secret() {
        let config = parse_instance_config(
            "inline config",
            r#"
[network_identity]
network_name = "credential-network"

[secure_mode]
enabled = true
"#,
        )
        .unwrap();

        let identity = &config.parsed().network_identity;
        assert_eq!(identity.network_name, "credential-network");
        assert_eq!(identity.network_secret, None);
    }

    #[cfg(feature = "config-write")]
    #[test]
    fn user_source_is_implicit_while_web_source_round_trips() {
        let user = parse_instance_config(
            "inline config",
            r#"
[source]
source = "user"
"#,
        )
        .unwrap();
        assert_eq!(user.raw().source, None);
        assert!(!serialize_raw_to_toml(user.raw()).unwrap().contains("[source]"));

        let web = parse_instance_config(
            "inline config",
            r#"
[source]
source = "web"
"#,
        )
        .unwrap();
        assert_eq!(
            web.raw().source.as_ref().map(|source| source.source),
            Some(ConfigSource::Web)
        );
        assert!(serialize_raw_to_toml(web.raw()).unwrap().contains("source = \"web\""));
    }
}

#[cfg(test)]
mod compatibility_tests {
    use super::*;
    use crate::proto::common::CompressionAlgoPb;
    use base64::{Engine as _, prelude::BASE64_STANDARD};
    use optionize::Optionizable as _;

    #[test]
    fn socket_mark_config_file_roundtrip_none_some_and_zero() {
        // Omitting the flag leaves socket_mark unset (None) -> SO_MARK untouched.
        let cfg = parse_instance_config(
            "inline config",
            r#"
[network_identity]
network_name = "n"
network_secret = "s"
"#,
        )
        .unwrap();
        assert_eq!(cfg.parsed().flags.socket_mark, None);

        // socket_mark = 0 is a legitimate value distinct from "unset".
        let cfg = parse_instance_config(
            "inline config",
            r#"
[network_identity]
network_name = "n"
network_secret = "s"

[flags]
socket_mark = 0
"#,
        )
        .unwrap();
        assert_eq!(cfg.parsed().flags.socket_mark, Some(0));

        // A non-zero mark round-trips as Some(v).
        let cfg = parse_instance_config(
            "inline config",
            r#"
[network_identity]
network_name = "n"
network_secret = "s"

[flags]
socket_mark = 66
"#,
        )
        .unwrap();
        assert_eq!(cfg.parsed().flags.socket_mark, Some(66));

        let mut raw = cfg.into_raw();
        raw.flags.socket_mark = None;
        let updated = InstanceConfig::try_from(raw).unwrap();
        assert_eq!(updated.parsed().flags.socket_mark, None);
        #[cfg(feature = "config-write")]
        assert_eq!(
            parse_instance_config(
                "inline config",
                &serialize_raw_to_toml(updated.raw()).unwrap()
            )
            .unwrap()
            .parsed()
            .flags
            .socket_mark,
            None
        );
    }

    #[cfg(feature = "config-write")]
    #[test]
    fn flags_presence_survives_parse_patch_and_dump() {
        for (input, expected) in [
            ("", None),
            ("enable_encryption = true", Some(true)),
            ("enable_encryption = false", Some(false)),
        ] {
            let config =
                parse_instance_config("inline config", &format!("[flags]\n{input}")).unwrap();
            assert_eq!(
                config.raw().flags.enable_encryption,
                expected
            );
            let mut raw = config.into_raw();
            let patch = FlagsPatch {
                latency_first: Some(false),
                ..Default::default()
            };
            raw.patch_flags(patch);
            let dumped = serialize_raw_to_toml(&raw).unwrap();
            let restored = parse_instance_config("inline config", &dumped).unwrap();
            assert_eq!(
                restored
                    .raw()
                    .flags
                    .enable_encryption,
                expected
            );
            assert_eq!(
                restored.raw().flags.latency_first,
                Some(false)
            );
            assert_eq!(restored.raw().flags.mtu, None);
            assert_eq!(
                restored.parsed().flags.enable_encryption,
                expected.unwrap_or(true)
            );
        }
    }

    #[test]
    fn flags_accept_protobuf_aliases_and_numbers_without_default_collisions() {
        let config = parse_instance_config(
            "inline config",
            r#"[flags]
enableEncryption = false
mtu = "1420"
foreignRelayBpsLimit = "18446744073709551615"
dataCompressAlgo = "Zstd"
socketMark = "0"
"#,
        )
        .unwrap();
        let flags = &config.parsed().flags;
        assert!(!flags.enable_encryption);
        assert_eq!(flags.mtu, 1420);
        assert_eq!(flags.foreign_relay_bps_limit, u64::MAX);
        assert_eq!(flags.data_compress_algo, CompressionAlgoPb::Zstd as i32);
        assert_eq!(flags.socket_mark, Some(0));
        for fields in [
            "enableEncryption = true\nenable_encryption = false",
            "mtu = -1",
            "mtu = 4294967296",
            "unknown_flag = true",
            "data_compress_algo = 99",
        ] {
            assert!(
                parse_instance_config("inline config", &format!("[flags]\n{fields}")).is_err(),
                "{fields}"
            );
        }
    }

    #[cfg(feature = "config-write")]
    #[test]
    fn dump_omits_all_default_flags() {
        let raw = InstanceConfigRaw::default();
        let dumped = serialize_raw_to_toml(&raw).unwrap();
        let document: toml::Table = toml::from_str(&dumped).unwrap();
        assert!(document.get("flags").map(|f| f.as_table().unwrap().is_empty()).unwrap_or(true));
        assert_eq!(
            parse_instance_config("inline config", &dumped)
                .unwrap()
                .parsed()
                .flags,
            Flags::resolve(FlagsPatch::default())
        );
    }

    #[cfg(feature = "config-write")]
    #[test]
    fn dump_preserves_flags_that_differ_from_easytier_defaults() {
        let mut flags = Flags::resolve(FlagsPatch::default());
        flags.dev_name = "et_test".to_string();
        flags.enable_quic_proxy = true;
        flags.disable_tcp_hole_punching = true;
        flags.disable_sym_hole_punching = true;
        flags.multi_thread = false;
        flags.bind_device = false;
        flags.enable_ipv6 = false;
        flags.relay_network_whitelist = "".to_string();
        flags.prefer_peer_relay = true;
        flags.mtu = 0;
        flags.foreign_relay_bps_limit = u64::MAX - 1;
        flags.instance_recv_bps_limit = u64::MAX - 2;
        flags.data_compress_algo = CompressionAlgoPb::Zstd.into();
        flags.socket_mark = Some(0);

        let mut raw = InstanceConfigRaw::default();
        raw.flags = flags.downgrade();

        let dumped = serialize_raw_to_toml(&raw).unwrap();

        assert!(dumped.contains("dev_name = \"et_test\""));
        assert!(dumped.contains("enable_quic_proxy = true"));
        assert!(dumped.contains("disable_tcp_hole_punching = true"));
        assert!(dumped.contains("disable_sym_hole_punching = true"));
        assert!(dumped.contains("multi_thread = false"));
        assert!(dumped.contains("bind_device = false"));
        assert!(dumped.contains("enable_ipv6 = false"));
        assert!(dumped.contains("relay_network_whitelist = \"\""));
        assert!(dumped.contains("mtu = 0"));
        assert!(dumped.contains("foreign_relay_bps_limit = \"18446744073709551614\""));
        assert!(dumped.contains("instance_recv_bps_limit = \"18446744073709551613\""));
        assert!(dumped.contains("data_compress_algo = \"Zstd\""));
        assert!(dumped.contains("socket_mark = 0"));

        let reloaded = parse_instance_config("inline config", &dumped).unwrap();
        let reloaded_flags = &reloaded.parsed().flags;
        assert_eq!(reloaded_flags.dev_name, "et_test");
        assert!(reloaded_flags.enable_quic_proxy);
        assert!(reloaded_flags.disable_tcp_hole_punching);
        assert!(reloaded_flags.disable_sym_hole_punching);
        assert!(!reloaded_flags.multi_thread);
        assert!(!reloaded_flags.bind_device);
        assert!(!reloaded_flags.enable_ipv6);
        assert_eq!(reloaded_flags.relay_network_whitelist, "");
        assert!(reloaded_flags.prefer_peer_relay);
        assert_eq!(reloaded_flags.mtu, 0);
        assert_eq!(reloaded_flags.foreign_relay_bps_limit, u64::MAX - 1);
        assert_eq!(reloaded_flags.instance_recv_bps_limit, u64::MAX - 2);
        assert_eq!(
            reloaded_flags.data_compress_algo,
            i32::from(CompressionAlgoPb::Zstd)
        );
        assert_eq!(reloaded_flags.socket_mark, Some(0));
    }

    #[test]
    fn test_stun_servers_config() {
        let raw = InstanceConfigRaw::default();
        let config = InstanceConfig::try_from(raw).unwrap();
        assert!(config.raw().stun_servers.is_none());
        assert!(config.raw().tcp_stun_servers.is_none());

        let custom_servers = vec!["txt:stun.easytier.cn".to_string()];
        let mut raw = config.into_raw();
        raw.stun_servers = Some(custom_servers.clone());
        let custom_tcp_servers = vec!["tcp-stun.example.com:3478".to_string()];
        raw.tcp_stun_servers = Some(custom_tcp_servers.clone());

        let updated = InstanceConfig::try_from(raw).unwrap();
        assert_eq!(
            updated.raw().stun_servers.as_ref().unwrap(),
            &custom_servers
        );
        assert_eq!(
            updated.raw().tcp_stun_servers.as_ref().unwrap(),
            &custom_tcp_servers
        );
    }

    #[test]
    fn test_stun_servers_toml_parsing() {
        let config_str = r#"
instance_name = "test"
stun_servers = [
    "stun.l.google.com:19302",
    "stun1.l.google.com:19302",
    "txt:stun.easytier.cn"
]
tcp_stun_servers = [
    "tcp-stun.example.com:3478"
]"#;

        let config = parse_instance_config("test", config_str).unwrap();
        let stun_servers = config.parsed().stun_servers.as_ref().unwrap();
        let tcp_stun_servers = config.parsed().tcp_stun_servers.as_ref().unwrap();

        assert_eq!(stun_servers.len(), 3);
        assert_eq!(stun_servers[0], "stun.l.google.com:19302");
        assert_eq!(stun_servers[1], "stun1.l.google.com:19302");
        assert_eq!(stun_servers[2], "txt:stun.easytier.cn");
        assert_eq!(tcp_stun_servers, &["tcp-stun.example.com:3478"]);
    }

    #[test]
    fn test_empty_tcp_stun_servers_toml_parsing() {
        let config = parse_instance_config(
            "test",
            r#"
instance_name = "test"
tcp_stun_servers = []
"#,
        )
        .unwrap();

        assert_eq!(config.parsed().tcp_stun_servers.as_deref(), Some(&[][..]));
    }

    #[cfg(feature = "config-write")]
    #[test]
    fn test_network_config_source_toml_roundtrip() {
        let mut raw = InstanceConfigRaw::default();
        assert_eq!(raw.source, None);

        raw.source = Some(ConfigSourceConfig {
            source: ConfigSource::Web,
        });
        let dumped = serialize_raw_to_toml(&raw).unwrap();

        assert!(dumped.contains("[source]"));
        assert!(dumped.contains("source = \"web\""));

        let loaded = parse_instance_config("test", &dumped).unwrap();
        assert_eq!(
            loaded.raw().source.as_ref().map(|s| s.source),
            Some(ConfigSource::Web)
        );
    }

    #[cfg(feature = "config-write")]
    #[test]
    fn test_toml_credential_mode_omits_network_secret() {
        for network_secret in ["", r#"network_secret = """#] {
            let config = parse_instance_config(
                "test",
                &format!(
                    r#"
[network_identity]
network_name = "credential-network"
{network_secret}

[secure_mode]
enabled = true
"#
                ),
            )
            .unwrap();

            let identity = &config.parsed().network_identity;
            assert_eq!(identity.network_name, "credential-network");
            assert_eq!(identity.network_secret, None);
            assert_eq!(identity.network_secret_digest, None);
            assert!(!serialize_raw_to_toml(config.raw())
                .unwrap()
                .contains("network_secret"));
        }
    }

    #[test]
    fn test_toml_secure_mode_without_network_identity_uses_default_secret() {
        let config = parse_instance_config(
            "test",
            r#"
[secure_mode]
enabled = true
"#,
        )
        .unwrap();

        let identity = &config.parsed().network_identity;
        assert_eq!(identity.network_name, "default");
        assert_eq!(identity.network_secret.as_deref(), Some(""));
        assert!(identity.network_secret_digest.is_some());
    }

    #[test]
    fn test_toml_secure_mode_generates_keypair_when_keys_missing() {
        let config = parse_instance_config(
            "test",
            r#"
[secure_mode]
enabled = true
"#,
        )
        .unwrap();

        let secure_mode = config.parsed().secure_mode.as_ref().unwrap();
        let private_key = secure_mode.private_key().unwrap();
        let public_key = secure_mode.public_key().unwrap();
        assert_eq!(
            x25519_dalek::PublicKey::from(&private_key).as_bytes(),
            public_key.as_bytes()
        );
    }

    #[test]
    fn test_toml_secure_mode_derives_public_key_from_private_key() {
        let private = x25519_dalek::StaticSecret::random_from_rng(rand::rngs::OsRng);
        let config = parse_instance_config(
            "test",
            &format!(
                r#"
[secure_mode]
enabled = true
local_private_key = "{}"
"#,
                BASE64_STANDARD.encode(private.as_bytes())
            ),
        )
        .unwrap();

        let secure_mode = config.parsed().secure_mode.as_ref().unwrap();
        let private_key = secure_mode.private_key().unwrap();
        assert_eq!(private_key.as_bytes(), private.as_bytes());
        assert_eq!(
            secure_mode.public_key().unwrap().as_bytes(),
            x25519_dalek::PublicKey::from(&private).as_bytes()
        );
    }

    #[test]
    fn test_toml_secure_mode_rejects_mismatched_keypair() {
        let private = x25519_dalek::StaticSecret::random_from_rng(rand::rngs::OsRng);
        let other_public = x25519_dalek::PublicKey::from(
            &x25519_dalek::StaticSecret::random_from_rng(rand::rngs::OsRng),
        );
        let error = parse_instance_config(
            "test",
            &format!(
                r#"
[secure_mode]
enabled = true
local_private_key = "{}"
local_public_key = "{}"
"#,
                BASE64_STANDARD.encode(private.as_bytes()),
                BASE64_STANDARD.encode(other_public.as_bytes())
            ),
        )
        .unwrap_err();
        let error = format!("{error:#}");

        assert!(
            error.contains("failed to normalize [secure_mode] config"),
            "{error}"
        );
        assert!(
            error.contains("does not match generated public key"),
            "{error}"
        );
    }

    #[test]
    fn test_toml_secure_mode_disabled_keeps_keys_unset() {
        let config = parse_instance_config(
            "test",
            r#"
[secure_mode]
enabled = false
"#,
        )
        .unwrap();

        let secure_mode = config.parsed().secure_mode.as_ref().unwrap();
        assert!(!secure_mode.enabled);
        assert_eq!(secure_mode.local_private_key, None);
        assert_eq!(secure_mode.local_public_key, None);
    }

    #[cfg(feature = "config-write")]
    #[test]
    fn test_toml_secure_mode_keypair_survives_roundtrip() {
        let config = parse_instance_config(
            "test",
            r#"
[secure_mode]
enabled = true
"#,
        )
        .unwrap();

        let dumped = serialize_raw_to_toml(config.raw()).unwrap();
        let restored = parse_instance_config("test", &dumped).unwrap();

        assert_eq!(config.parsed().secure_mode, restored.parsed().secure_mode);
    }

    #[test]
    fn test_acl_toml_rule_uses_defaults_for_omitted_fields() {
        use crate::proto::acl::{Action, ChainType, Protocol};

        let config_str = r#"
[[acl.acl_v1.chains]]
name = "subnet_proxy_protect"
chain_type = 3
enabled = true
default_action = 2

[[acl.acl_v1.chains.rules]]
name = "allow_my_devices"
priority = 1000
action = 1
source_ips = ["10.172.192.2/32"]
protocol = 5
enabled = true
"#;

        let config = parse_instance_config("test", config_str).unwrap();
        let acl = config.parsed().acl.as_ref().unwrap();
        let acl_v1 = acl.acl_v1.as_ref().unwrap();
        let chain = &acl_v1.chains[0];
        let rule = &chain.rules[0];

        assert_eq!(chain.chain_type, ChainType::Forward as i32);
        assert_eq!(chain.default_action, Action::Drop as i32);
        assert_eq!(rule.action, Action::Allow as i32);
        assert_eq!(rule.protocol, Protocol::Any as i32);
        assert_eq!(rule.source_ips, vec!["10.172.192.2/32"]);
        assert!(rule.ports.is_empty());
        assert!(rule.source_ports.is_empty());
        assert!(rule.destination_ips.is_empty());
        assert!(rule.source_groups.is_empty());
        assert!(rule.destination_groups.is_empty());
        assert_eq!(rule.rate_limit, 0);
        assert_eq!(rule.burst_limit, 0);
        assert!(!rule.stateful);
    }

    #[test]
    fn test_acl_toml_group_can_omit_declares_or_members() {
        let declares_only = r#"
[acl.acl_v1.group]

[[acl.acl_v1.group.declares]]
group_name = "admin"
group_secret = "admin-pw"
"#;
        let config = parse_instance_config("test", declares_only).unwrap();
        let group = config
            .parsed()
            .acl
            .as_ref()
            .unwrap()
            .acl_v1
            .as_ref()
            .unwrap()
            .group
            .as_ref()
            .unwrap();
        assert_eq!(group.declares.len(), 1);
        assert!(group.members.is_empty());

        let members_only = r#"
[acl.acl_v1.group]
members = ["admin"]
"#;
        let config = parse_instance_config("test", members_only).unwrap();
        let group = config
            .parsed()
            .acl
            .as_ref()
            .unwrap()
            .acl_v1
            .as_ref()
            .unwrap()
            .group
            .as_ref()
            .unwrap();
        assert!(group.declares.is_empty());
        assert_eq!(group.members, vec!["admin"]);
    }

    #[cfg(feature = "config-write")]
    #[test]
    fn test_network_config_source_user_is_implicit() {
        let mut raw = InstanceConfigRaw::default();
        raw.source = Some(ConfigSourceConfig {
            source: ConfigSource::User,
        });
        let dumped = serialize_raw_to_toml(&raw).unwrap();

        assert!(!dumped.contains("[source]"));

        let loaded = parse_instance_config("test", &dumped).unwrap();
        assert_eq!(loaded.raw().source, None);

        let explicit_user = parse_instance_config(
            "test",
            r#"
[source]
source = "user"
"#,
        )
        .unwrap();
        assert_eq!(explicit_user.raw().source, None);
        assert!(!serialize_raw_to_toml(explicit_user.raw())
            .unwrap()
            .contains("[source]"));
    }

    #[cfg(feature = "config-write")]
    #[test]
    fn test_ipv6_public_addr_config_roundtrip() {
        let prefix: cidr::Ipv6Cidr = "2001:db8:100::/64".parse().unwrap();
        let raw = InstanceConfigRaw {
            ipv6_public_addr_provider: Some(true),
            ipv6_public_addr_auto: Some(true),
            ipv6_public_addr_prefix: Some(prefix),
            ..Default::default()
        };

        assert!(raw.ipv6_public_addr_provider.unwrap());
        assert!(raw.ipv6_public_addr_auto.unwrap());
        assert_eq!(raw.ipv6_public_addr_prefix, Some(prefix));

        let dumped = serialize_raw_to_toml(&raw).unwrap();
        let loaded = parse_instance_config("test", &dumped).unwrap();
        assert!(loaded.parsed().ipv6_public_addr_provider);
        assert!(loaded.parsed().ipv6_public_addr_auto);
        assert_eq!(loaded.parsed().ipv6_public_addr_prefix, Some(prefix));
    }
}

#[cfg(test)]
mod full_example_tests {
    use super::*;

    #[cfg(feature = "config-write")]
    #[test]
    fn full_example_test() {
        let config_str = r#"
instance_name = "default"
instance_id = "87ede5a2-9c3d-492d-9bbe-989b9d07e742"
ipv4 = "10.144.144.10"
listeners = [ "tcp://0.0.0.0:11010", "udp://0.0.0.0:11010" ]
routes = [ "192.168.0.0/16" ]

[network_identity]
network_name = "default"
network_secret = ""

[[peer]]
uri = "tcp://public.kkrainbow.top:11010"

[[peer]]
uri = "udp://192.168.94.33:11010"

[[proxy_network]]
cidr = "10.147.223.0/24"
allow = ["tcp", "udp", "icmp"]

[[proxy_network]]
cidr = "10.1.1.0/24"
allow = ["tcp", "icmp"]

[file_logger]
level = "info"
file = "easytier"
dir = "/tmp/easytier"

[console_logger]
level = "warn"

[[port_forward]]
bind_addr = "0.0.0.0:11011"
dst_addr = "192.168.94.33:11011"
proto = "tcp"
"#;
        let ret = parse_instance_config("test", config_str);
        if let Err(e) = &ret {
            println!("{}", e);
        } else {
            println!("{:?}", ret.as_ref().unwrap());
        }
        assert!(ret.is_ok());

        let ret = ret.unwrap();
        assert_eq!("10.144.144.10/24", ret.parsed().ipv4.unwrap().to_string());

        assert_eq!(
            vec!["tcp://0.0.0.0:11010", "udp://0.0.0.0:11010"],
            ret.parsed()
                .listeners
                .as_ref()
                .unwrap()
                .iter()
                .map(|u| u.to_string())
                .collect::<Vec<String>>()
        );

        assert_eq!(
            vec![PortForwardConfig {
                bind_addr: "0.0.0.0:11011".parse().unwrap(),
                dst_addr: "192.168.94.33:11011".parse().unwrap(),
                proto: "tcp".to_string(),
            }],
            ret.parsed().port_forward
        );
        println!("{}", serialize_raw_to_toml(ret.raw()).unwrap());
    }
}

#[cfg(test)]
mod diagnostic_compatibility_tests {
    use super::*;

    #[test]
    fn stdin_source_name_and_caret_are_preserved() {
        let error = parse_instance_config("stdin", "dhcp = \"yes\"")
            .unwrap_err()
            .to_string();

        assert!(error.contains("stdin"));
        assert!(error.contains("dhcp = \"yes\""));
        assert!(error.contains('^'));
        assert!(!error.contains("<unknown>"));
    }

    #[test]
    fn non_ascii_before_typed_error_keeps_byte_location() {
        let error = parse_instance_config("inline config", "hostname = \"节点\"\ndhcp = \"yes\"")
            .unwrap_err()
            .to_string();

        assert!(error.contains("dhcp = \"yes\""));
        assert!(error.contains('^'));
        assert!(error.contains("invalid type: string"));
    }

    #[cfg(feature = "rich-config-errors")]
    #[test]
    fn non_ascii_on_syntax_error_line_keeps_source_location() {
        let error = parse_instance_config("inline config", "hostname = \"节点\" dhcp = \"yes\"")
            .unwrap_err()
            .to_string();

        assert!(error.contains("inline config:1:"));
        assert!(error.contains("hostname = \"节点\" dhcp = \"yes\""));
        assert!(error.contains("expected newline"));
        assert!(!error.contains("<unknown>"));
    }

    #[test]
    fn flags_parse_error_keeps_source_span_and_cause_chain() {
        let error = parse_instance_config(
            "flags-fixture.toml",
            "[flags]\nsocket_mark = \"bad\"",
        )
        .unwrap_err();
        let display = error.to_string();

        assert!(display.contains("flags-fixture.toml"));
        assert!(display.contains("failed to parse config TOML"));
        assert!(display.contains("socket_mark = \"bad\""));
        assert!(display.contains('^'));
        assert!(
            error
                .chain()
                .any(|cause| cause.downcast_ref::<toml::de::Error>().is_some())
        );
    }
}
