//! Complete EasyTier TOML configuration model.

use std::{
    net::{IpAddr, SocketAddr},
    path::PathBuf,
    sync::{Arc, Mutex},
};

pub use super::{EncryptionAlgorithm, gateway::PortForwardConfig};
use anyhow::Context;
#[cfg(feature = "rich-config-errors")]
use ariadne::{CharSet, Config as AriadneConfig, IndexType, Label, Report, ReportKind, Source};
use serde::{Deserialize, Serialize};

#[cfg(feature = "config-write")]
use crate::config::{DEFAULT_UDP_STUN_SERVERS, DEFAULT_UDP_V6_STUN_SERVERS, default_stun_servers};
use crate::proto::{
    acl::Acl,
    common::{CompressionAlgoPb, SecureModeConfig},
};

pub const DEFAULT_ET_DNS_ZONE: &str = "et.net.";

pub type Flags = crate::proto::common::FlagsInConfig;

pub(crate) fn default_instance_name() -> String {
    "default".to_owned()
}

#[cfg(feature = "config-write")]
fn default_udp_stun_servers() -> Vec<String> {
    default_stun_servers(DEFAULT_UDP_STUN_SERVERS)
}

#[cfg(feature = "config-write")]
fn default_udp_v6_stun_servers() -> Vec<String> {
    default_stun_servers(DEFAULT_UDP_V6_STUN_SERVERS)
}

pub fn gen_default_flags() -> Flags {
    #[allow(deprecated)]
    Flags {
        default_protocol: "tcp".to_string(),
        dev_name: "".to_string(),
        enable_encryption: true,
        enable_ipv6: true,
        mtu: 1380,
        latency_first: false,
        enable_exit_node: false,
        proxy_forward_by_system: false,
        no_tun: false,
        use_smoltcp: false,
        relay_network_whitelist: "*".to_string(),
        disable_p2p: false,
        p2p_only: false,
        lazy_p2p: false,
        relay_all_peer_rpc: false,
        disable_tcp_hole_punching: false,
        disable_udp_hole_punching: false,
        multi_thread: true,
        data_compress_algo: CompressionAlgoPb::None.into(),
        bind_device: true,
        enable_kcp_proxy: false,
        disable_kcp_input: false,
        disable_relay_kcp: false,
        enable_relay_foreign_network_kcp: false,
        accept_dns: false,
        private_mode: false,
        enable_quic_proxy: false,
        disable_quic_input: false,
        disable_relay_quic: false,
        enable_relay_foreign_network_quic: false,
        foreign_relay_bps_limit: u64::MAX,
        multi_thread_count: 2,
        encryption_algorithm: EncryptionAlgorithm::default().to_string(),
        disable_sym_hole_punching: false,
        tld_dns_zone: DEFAULT_ET_DNS_ZONE.to_string(),

        quic_listen_port: u32::MAX,
        need_p2p: false,
        instance_recv_bps_limit: u64::MAX,
        disable_upnp: false,
        disable_relay_data: false,
        enable_udp_broadcast_relay: false,
        socket_mark: None,
    }
}

#[cfg(feature = "config-write")]
macro_rules! define_flags_diff {
    (
        fields: [$($field:ident),* $(,)?],
        u64s: [$($u64_field:ident),* $(,)?],
        enums: [$($enum_field:ident),* $(,)?]
    ) => {
        #[allow(deprecated)]
        fn flags_diff_from_default(flags: &Flags) -> serde_json::Map<String, serde_json::Value> {
            let defaults = gen_default_flags();
            let mut changed = serde_json::Map::new();
            $(
                if flags.$field != defaults.$field {
                    changed.insert(
                        stringify!($field).to_owned(),
                        serde_json::to_value(&flags.$field)
                            .expect("FlagsInConfig field should serialize to JSON"),
                    );
                }
            )*
            $(
                if flags.$u64_field != defaults.$u64_field {
                    changed.insert(
                        stringify!($u64_field).to_owned(),
                        serde_json::json!(flags.$u64_field.to_string()),
                    );
                }
            )*
            $(
                if flags.$enum_field != defaults.$enum_field {
                    let value = CompressionAlgoPb::try_from(flags.$enum_field)
                        .map(|value| serde_json::to_value(value).expect("enum should serialize"))
                        .unwrap_or_else(|_| serde_json::json!(flags.$enum_field));
                    changed.insert(stringify!($enum_field).to_owned(), value);
                }
            )*
            changed
        }

        #[cfg(all(test, feature = "config-write"))]
        const FLAGS_DIFF_FIELDS: &[&str] = &[
            $(stringify!($field),)*
            $(stringify!($u64_field),)*
            $(stringify!($enum_field),)*
        ];
    };
}

#[cfg(feature = "config-write")]
define_flags_diff! {
    fields: [
        default_protocol,
        dev_name,
        enable_encryption,
        enable_ipv6,
        mtu,
        latency_first,
        enable_exit_node,
        no_tun,
        use_smoltcp,
        relay_network_whitelist,
        disable_p2p,
        relay_all_peer_rpc,
        disable_udp_hole_punching,
        multi_thread,
        bind_device,
        enable_kcp_proxy,
        disable_kcp_input,
        disable_relay_kcp,
        proxy_forward_by_system,
        accept_dns,
        private_mode,
        enable_quic_proxy,
        disable_quic_input,
        disable_relay_quic,
        quic_listen_port,
        multi_thread_count,
        enable_relay_foreign_network_kcp,
        enable_relay_foreign_network_quic,
        encryption_algorithm,
        disable_sym_hole_punching,
        tld_dns_zone,
        p2p_only,
        disable_tcp_hole_punching,
        lazy_p2p,
        need_p2p,
        disable_upnp,
        disable_relay_data,
        enable_udp_broadcast_relay,
        socket_mark,
    ],
    u64s: [foreign_relay_bps_limit, instance_recv_bps_limit],
    enums: [data_compress_algo]
}

#[auto_impl::auto_impl(Box, &)]
pub trait ConfigLoader: Send + Sync {
    fn get_id(&self) -> uuid::Uuid;
    fn set_id(&self, id: uuid::Uuid);

    fn get_hostname(&self) -> String;
    fn set_hostname(&self, name: Option<String>);

    fn get_inst_name(&self) -> String;
    fn set_inst_name(&self, name: String);

    fn get_netns(&self) -> Option<String>;
    fn set_netns(&self, ns: Option<String>);

    fn get_ipv4(&self) -> Option<cidr::Ipv4Inet>;
    fn set_ipv4(&self, addr: Option<cidr::Ipv4Inet>);

    fn get_ipv6(&self) -> Option<cidr::Ipv6Inet>;
    fn set_ipv6(&self, addr: Option<cidr::Ipv6Inet>);

    fn get_ipv6_public_addr_provider(&self) -> bool;
    fn set_ipv6_public_addr_provider(&self, enabled: bool);

    fn get_ipv6_public_addr_auto(&self) -> bool;
    fn set_ipv6_public_addr_auto(&self, enabled: bool);

    fn get_ipv6_public_addr_prefix(&self) -> Option<cidr::Ipv6Cidr>;
    fn set_ipv6_public_addr_prefix(&self, prefix: Option<cidr::Ipv6Cidr>);

    fn get_dhcp(&self) -> bool;
    fn set_dhcp(&self, dhcp: bool);

    fn add_proxy_cidr(
        &self,
        cidr: cidr::Ipv4Cidr,
        mapped_cidr: Option<cidr::Ipv4Cidr>,
    ) -> Result<(), anyhow::Error>;
    fn remove_proxy_cidr(&self, cidr: cidr::Ipv4Cidr);
    fn clear_proxy_cidrs(&self);
    fn get_proxy_cidrs(&self) -> Vec<ProxyNetworkConfig>;

    fn get_network_identity(&self) -> NetworkIdentity;
    fn set_network_identity(&self, identity: NetworkIdentity);

    fn get_listener_uris(&self) -> Vec<url::Url>;

    fn get_peers(&self) -> Vec<PeerConfig>;
    fn set_peers(&self, peers: Vec<PeerConfig>);

    fn get_listeners(&self) -> Option<Vec<url::Url>>;
    fn set_listeners(&self, listeners: Vec<url::Url>);

    fn get_mapped_listeners(&self) -> Vec<url::Url>;
    fn set_mapped_listeners(&self, listeners: Option<Vec<url::Url>>);

    fn get_vpn_portal_config(&self) -> Option<VpnPortalConfig>;
    fn set_vpn_portal_config(&self, config: VpnPortalConfig);

    fn get_flags(&self) -> Flags;
    fn set_flags(&self, flags: Flags);

    fn get_exit_nodes(&self) -> Vec<IpAddr>;
    fn set_exit_nodes(&self, nodes: Vec<IpAddr>);

    fn get_routes(&self) -> Option<Vec<cidr::Ipv4Cidr>>;
    fn set_routes(&self, routes: Option<Vec<cidr::Ipv4Cidr>>);

    fn get_socks5_portal(&self) -> Option<url::Url>;
    fn set_socks5_portal(&self, addr: Option<url::Url>);

    fn get_port_forwards(&self) -> Vec<PortForwardConfig>;
    fn set_port_forwards(&self, forwards: Vec<PortForwardConfig>);

    fn get_acl(&self) -> Option<Acl>;
    fn set_acl(&self, acl: Option<Acl>);

    fn get_tcp_whitelist(&self) -> Vec<String>;
    fn set_tcp_whitelist(&self, whitelist: Vec<String>);

    fn get_udp_whitelist(&self) -> Vec<String>;
    fn set_udp_whitelist(&self, whitelist: Vec<String>);

    fn get_stun_servers(&self) -> Option<Vec<String>>;
    fn set_stun_servers(&self, servers: Option<Vec<String>>);

    fn get_stun_servers_v6(&self) -> Option<Vec<String>>;
    fn set_stun_servers_v6(&self, servers: Option<Vec<String>>);

    fn get_secure_mode(&self) -> Option<SecureModeConfig>;
    fn set_secure_mode(&self, secure_mode: Option<SecureModeConfig>);

    fn get_credential_file(&self) -> Option<std::path::PathBuf> {
        None
    }
    fn set_credential_file(&self, _path: Option<std::path::PathBuf>) {}

    fn get_network_config_source(&self) -> ConfigSource {
        ConfigSource::User
    }
    fn set_network_config_source(&self, _source: Option<ConfigSource>) {}

    fn dump(&self) -> String;
}

pub trait LoggingConfigLoader {
    fn get_file_logger_config(&self) -> FileLoggerConfig;

    fn get_console_logger_config(&self) -> ConsoleLoggerConfig;
}

use super::NetworkSecretDigest;

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct NetworkIdentity {
    pub network_name: String,
    pub network_secret: Option<String>,
    #[serde(skip)]
    pub network_secret_digest: Option<NetworkSecretDigest>,
}

impl From<super::NetworkIdentity> for NetworkIdentity {
    fn from(value: super::NetworkIdentity) -> Self {
        Self {
            network_name: value.network_name,
            network_secret: value.network_secret,
            network_secret_digest: value.network_secret_digest,
        }
    }
}

impl From<&NetworkIdentity> for super::NetworkIdentity {
    fn from(value: &NetworkIdentity) -> Self {
        Self {
            network_name: value.network_name.clone(),
            network_secret: value.network_secret.clone(),
            network_secret_digest: value.network_secret_digest,
        }
    }
}

impl From<NetworkIdentity> for super::NetworkIdentity {
    fn from(value: NetworkIdentity) -> Self {
        Self {
            network_name: value.network_name,
            network_secret: value.network_secret,
            network_secret_digest: value.network_secret_digest,
        }
    }
}

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

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq)]
struct ConfigSourceConfig {
    source: ConfigSource,
}

impl PartialEq for NetworkIdentity {
    fn eq(&self, other: &Self) -> bool {
        super::NetworkIdentity::from(self) == super::NetworkIdentity::from(other)
    }
}

impl Eq for NetworkIdentity {}

impl std::hash::Hash for NetworkIdentity {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        std::hash::Hash::hash(&super::NetworkIdentity::from(self), state);
    }
}

impl NetworkIdentity {
    pub fn new(network_name: String, network_secret: String) -> Self {
        super::NetworkIdentity::new(network_name, network_secret).into()
    }

    /// Create a NetworkIdentity for a credential node (no network_secret).
    /// The node identifies by network_name only and authenticates via credential keypair.
    pub fn new_credential(network_name: String) -> Self {
        super::NetworkIdentity::new_credential(network_name).into()
    }
}

impl Default for NetworkIdentity {
    fn default() -> Self {
        super::NetworkIdentity::default().into()
    }
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

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, derive_builder::Builder)]
pub struct LoggingConfig {
    #[builder(setter(into, strip_option), default = None)]
    pub file_logger: Option<FileLoggerConfig>,
    #[builder(setter(into, strip_option), default = None)]
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

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq)]
pub struct VpnPortalConfig {
    pub client_cidr: cidr::Ipv4Cidr,
    pub wireguard_listen: SocketAddr,
}

#[derive(Debug, Clone, PartialEq, Deserialize)]
#[cfg_attr(feature = "config-write", derive(Serialize))]
struct Config {
    netns: Option<String>,
    hostname: Option<String>,
    instance_name: Option<String>,
    instance_id: Option<uuid::Uuid>,
    ipv4: Option<String>,
    ipv6: Option<String>,
    ipv6_public_addr_provider: Option<bool>,
    ipv6_public_addr_auto: Option<bool>,
    ipv6_public_addr_prefix: Option<String>,
    dhcp: Option<bool>,
    network_identity: Option<NetworkIdentity>,
    listeners: Option<Vec<url::Url>>,
    mapped_listeners: Option<Vec<url::Url>>,
    exit_nodes: Option<Vec<IpAddr>>,

    peer: Option<Vec<PeerConfig>>,
    proxy_network: Option<Vec<ProxyNetworkConfig>>,

    vpn_portal_config: Option<VpnPortalConfig>,

    routes: Option<Vec<cidr::Ipv4Cidr>>,

    socks5_proxy: Option<url::Url>,

    port_forward: Option<Vec<PortForwardConfig>>,

    secure_mode: Option<SecureModeConfig>,

    flags: Option<serde_json::Map<String, serde_json::Value>>,

    #[serde(skip)]
    flags_struct: Option<Flags>,

    acl: Option<Acl>,

    tcp_whitelist: Option<Vec<String>>,
    udp_whitelist: Option<Vec<String>>,
    stun_servers: Option<Vec<String>>,
    stun_servers_v6: Option<Vec<String>>,

    credential_file: Option<PathBuf>,
    source: Option<ConfigSourceConfig>,
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

#[derive(Debug, Clone)]
pub struct TomlConfig {
    config: Arc<Mutex<Config>>,
}

impl Default for TomlConfig {
    fn default() -> Self {
        TomlConfig::new_from_str("").unwrap()
    }
}

impl TomlConfig {
    fn normalize_config_source(config: &mut Config) {
        if matches!(
            config.source.as_ref().map(|source| source.source),
            Some(ConfigSource::User)
        ) {
            config.source = None;
        }
    }

    pub fn new_from_str(config_str: &str) -> Result<Self, anyhow::Error> {
        Self::new_from_str_with_source("inline config", config_str)
    }

    pub fn new_from_str_with_source(
        source_name: &str,
        config_str: &str,
    ) -> Result<Self, anyhow::Error> {
        let mut config = toml::de::from_str::<Config>(config_str).map_err(|err| {
            let message = format_toml_parse_error(source_name, config_str, &err);
            anyhow::Error::new(err).context(message)
        })?;

        Self::normalize_config_source(&mut config);

        Self::new_from_config(config).map_err(|err| {
            let message = format!("failed to load config from {source_name}: {err}");
            err.context(message)
        })
    }

    fn new_from_config(mut config: Config) -> Result<Self, anyhow::Error> {
        config.flags_struct = Some(
            Self::gen_flags(config.flags.clone().unwrap_or_default())
                .context("failed to parse flags")?,
        );
        let has_network_identity = config.network_identity.is_some();

        let config = TomlConfig {
            config: Arc::new(Mutex::new(config)),
        };

        let old_ns = config.get_network_identity();

        // Detect credential mode: secure_mode enabled + no network_secret in TOML
        let is_credential = has_network_identity
            && config
                .get_secure_mode()
                .map(|sm| sm.enabled)
                .unwrap_or(false)
            && old_ns
                .network_secret
                .as_deref()
                .is_none_or(|s| s.is_empty());

        if is_credential {
            config.set_network_identity(NetworkIdentity::new_credential(old_ns.network_name));
        } else {
            config.set_network_identity(NetworkIdentity::new(
                old_ns.network_name,
                old_ns.network_secret.unwrap_or_default(),
            ));
        }

        Ok(config)
    }

    fn gen_flags(
        flags_hashmap: serde_json::Map<String, serde_json::Value>,
    ) -> serde_json::Result<Flags> {
        let mut merged_hashmap = match serde_json::to_value(gen_default_flags()) {
            Ok(serde_json::Value::Object(map)) => map,
            _ => serde_json::Map::new(),
        };
        merged_hashmap.extend(flags_hashmap);
        serde_json::from_value(serde_json::Value::Object(merged_hashmap))
    }
}

#[cfg(feature = "management")]
mod snapshot;

impl ConfigLoader for TomlConfig {
    fn get_inst_name(&self) -> String {
        self.config
            .lock()
            .unwrap()
            .instance_name
            .clone()
            .unwrap_or_else(default_instance_name)
    }

    fn set_inst_name(&self, name: String) {
        self.config.lock().unwrap().instance_name = Some(name);
    }

    fn get_hostname(&self) -> String {
        let hostname = self.config.lock().unwrap().hostname.clone();

        match hostname {
            Some(hostname) => {
                let hostname = hostname
                    .chars()
                    .filter(|c| !c.is_control())
                    .take(32)
                    .collect::<String>();

                if !hostname.is_empty() {
                    self.set_hostname(Some(hostname.clone()));
                    hostname
                } else {
                    self.set_hostname(None);
                    String::new()
                }
            }
            None => String::new(),
        }
    }

    fn set_hostname(&self, name: Option<String>) {
        self.config.lock().unwrap().hostname = name;
    }

    fn get_netns(&self) -> Option<String> {
        self.config.lock().unwrap().netns.clone()
    }

    fn set_netns(&self, ns: Option<String>) {
        self.config.lock().unwrap().netns = ns;
    }

    fn get_ipv4(&self) -> Option<cidr::Ipv4Inet> {
        let locked_config = self.config.lock().unwrap();
        locked_config
            .ipv4
            .as_ref()
            .and_then(|s| s.parse().ok())
            .map(|c: cidr::Ipv4Inet| {
                if c.network_length() == 32 {
                    cidr::Ipv4Inet::new(c.address(), 24).unwrap()
                } else {
                    c
                }
            })
    }

    fn set_ipv4(&self, addr: Option<cidr::Ipv4Inet>) {
        self.config.lock().unwrap().ipv4 = addr.map(|addr| addr.to_string());
    }

    fn get_ipv6(&self) -> Option<cidr::Ipv6Inet> {
        let locked_config = self.config.lock().unwrap();
        locked_config.ipv6.as_ref().and_then(|s| s.parse().ok())
    }

    fn set_ipv6(&self, addr: Option<cidr::Ipv6Inet>) {
        self.config.lock().unwrap().ipv6 = addr.map(|addr| addr.to_string());
    }

    fn get_ipv6_public_addr_provider(&self) -> bool {
        self.config
            .lock()
            .unwrap()
            .ipv6_public_addr_provider
            .unwrap_or_default()
    }

    fn set_ipv6_public_addr_provider(&self, enabled: bool) {
        self.config.lock().unwrap().ipv6_public_addr_provider = Some(enabled);
    }

    fn get_ipv6_public_addr_auto(&self) -> bool {
        self.config
            .lock()
            .unwrap()
            .ipv6_public_addr_auto
            .unwrap_or_default()
    }

    fn set_ipv6_public_addr_auto(&self, enabled: bool) {
        self.config.lock().unwrap().ipv6_public_addr_auto = Some(enabled);
    }

    fn get_ipv6_public_addr_prefix(&self) -> Option<cidr::Ipv6Cidr> {
        let locked_config = self.config.lock().unwrap();
        locked_config
            .ipv6_public_addr_prefix
            .as_ref()
            .and_then(|s| s.parse().ok())
    }

    fn set_ipv6_public_addr_prefix(&self, prefix: Option<cidr::Ipv6Cidr>) {
        self.config.lock().unwrap().ipv6_public_addr_prefix =
            prefix.map(|prefix| prefix.to_string());
    }

    fn get_dhcp(&self) -> bool {
        self.config.lock().unwrap().dhcp.unwrap_or_default()
    }

    fn set_dhcp(&self, dhcp: bool) {
        self.config.lock().unwrap().dhcp = Some(dhcp);
    }

    fn add_proxy_cidr(
        &self,
        cidr: cidr::Ipv4Cidr,
        mapped_cidr: Option<cidr::Ipv4Cidr>,
    ) -> Result<(), anyhow::Error> {
        let mut locked_config = self.config.lock().unwrap();
        if locked_config.proxy_network.is_none() {
            locked_config.proxy_network = Some(vec![]);
        }
        if let Some(mapped_cidr) = mapped_cidr.as_ref()
            && cidr.network_length() != mapped_cidr.network_length()
        {
            return Err(anyhow::anyhow!(
                "Mapped CIDR must have the same network length as the original CIDR: {} != {}",
                cidr.network_length(),
                mapped_cidr.network_length()
            ));
        }
        // insert if no duplicate
        if !locked_config
            .proxy_network
            .as_ref()
            .unwrap()
            .iter()
            .any(|c| c.cidr == cidr && c.mapped_cidr == mapped_cidr)
        {
            locked_config
                .proxy_network
                .as_mut()
                .unwrap()
                .push(ProxyNetworkConfig {
                    cidr,
                    mapped_cidr,
                    allow: None,
                });
        }
        Ok(())
    }

    fn remove_proxy_cidr(&self, cidr: cidr::Ipv4Cidr) {
        let mut locked_config = self.config.lock().unwrap();
        if let Some(proxy_cidrs) = &mut locked_config.proxy_network {
            proxy_cidrs.retain(|c| c.cidr != cidr);
        }
    }

    fn clear_proxy_cidrs(&self) {
        let mut locked_config = self.config.lock().unwrap();
        locked_config.proxy_network = None;
    }

    fn get_proxy_cidrs(&self) -> Vec<ProxyNetworkConfig> {
        self.config
            .lock()
            .unwrap()
            .proxy_network
            .as_ref()
            .cloned()
            .unwrap_or_default()
    }

    fn get_id(&self) -> uuid::Uuid {
        let mut locked_config = self.config.lock().unwrap();
        match locked_config.instance_id {
            Some(id) => id,
            None => {
                let id = uuid::Uuid::new_v4();
                locked_config.instance_id = Some(id);
                id
            }
        }
    }

    fn set_id(&self, id: uuid::Uuid) {
        self.config.lock().unwrap().instance_id = Some(id);
    }

    fn get_network_identity(&self) -> NetworkIdentity {
        self.config
            .lock()
            .unwrap()
            .network_identity
            .clone()
            .unwrap_or_default()
    }

    fn set_network_identity(&self, identity: NetworkIdentity) {
        self.config.lock().unwrap().network_identity = Some(identity);
    }

    fn get_listener_uris(&self) -> Vec<url::Url> {
        self.config
            .lock()
            .unwrap()
            .listeners
            .clone()
            .unwrap_or_default()
    }

    fn get_peers(&self) -> Vec<PeerConfig> {
        self.config.lock().unwrap().peer.clone().unwrap_or_default()
    }

    fn set_peers(&self, peers: Vec<PeerConfig>) {
        self.config.lock().unwrap().peer = Some(peers);
    }

    fn get_listeners(&self) -> Option<Vec<url::Url>> {
        self.config.lock().unwrap().listeners.clone()
    }

    fn set_listeners(&self, listeners: Vec<url::Url>) {
        self.config.lock().unwrap().listeners = Some(listeners);
    }

    fn get_mapped_listeners(&self) -> Vec<url::Url> {
        self.config
            .lock()
            .unwrap()
            .mapped_listeners
            .clone()
            .unwrap_or_default()
    }

    fn set_mapped_listeners(&self, listeners: Option<Vec<url::Url>>) {
        self.config.lock().unwrap().mapped_listeners = listeners;
    }

    fn get_vpn_portal_config(&self) -> Option<VpnPortalConfig> {
        self.config.lock().unwrap().vpn_portal_config.clone()
    }
    fn set_vpn_portal_config(&self, config: VpnPortalConfig) {
        self.config.lock().unwrap().vpn_portal_config = Some(config);
    }

    fn get_flags(&self) -> Flags {
        self.config
            .lock()
            .unwrap()
            .flags_struct
            .clone()
            .unwrap_or_default()
    }

    fn set_flags(&self, flags: Flags) {
        self.config.lock().unwrap().flags_struct = Some(flags);
    }

    fn get_exit_nodes(&self) -> Vec<IpAddr> {
        self.config
            .lock()
            .unwrap()
            .exit_nodes
            .clone()
            .unwrap_or_default()
    }

    fn set_exit_nodes(&self, nodes: Vec<IpAddr>) {
        self.config.lock().unwrap().exit_nodes = Some(nodes);
    }

    fn get_routes(&self) -> Option<Vec<cidr::Ipv4Cidr>> {
        self.config.lock().unwrap().routes.clone()
    }

    fn set_routes(&self, routes: Option<Vec<cidr::Ipv4Cidr>>) {
        self.config.lock().unwrap().routes = routes;
    }

    fn get_socks5_portal(&self) -> Option<url::Url> {
        self.config.lock().unwrap().socks5_proxy.clone()
    }

    fn set_socks5_portal(&self, addr: Option<url::Url>) {
        self.config.lock().unwrap().socks5_proxy = addr;
    }

    fn get_port_forwards(&self) -> Vec<PortForwardConfig> {
        self.config
            .lock()
            .unwrap()
            .port_forward
            .clone()
            .unwrap_or_default()
    }

    fn set_port_forwards(&self, forwards: Vec<PortForwardConfig>) {
        self.config.lock().unwrap().port_forward = Some(forwards);
    }

    fn get_acl(&self) -> Option<Acl> {
        self.config.lock().unwrap().acl.clone()
    }

    fn set_acl(&self, acl: Option<Acl>) {
        self.config.lock().unwrap().acl = acl;
    }

    fn get_tcp_whitelist(&self) -> Vec<String> {
        self.config
            .lock()
            .unwrap()
            .tcp_whitelist
            .clone()
            .unwrap_or_default()
    }

    fn set_tcp_whitelist(&self, whitelist: Vec<String>) {
        self.config.lock().unwrap().tcp_whitelist = Some(whitelist);
    }

    fn get_udp_whitelist(&self) -> Vec<String> {
        self.config
            .lock()
            .unwrap()
            .udp_whitelist
            .clone()
            .unwrap_or_default()
    }

    fn set_udp_whitelist(&self, whitelist: Vec<String>) {
        self.config.lock().unwrap().udp_whitelist = Some(whitelist);
    }

    fn get_stun_servers(&self) -> Option<Vec<String>> {
        self.config.lock().unwrap().stun_servers.clone()
    }

    fn set_stun_servers(&self, servers: Option<Vec<String>>) {
        self.config.lock().unwrap().stun_servers = servers;
    }

    fn get_stun_servers_v6(&self) -> Option<Vec<String>> {
        self.config.lock().unwrap().stun_servers_v6.clone()
    }

    fn set_stun_servers_v6(&self, servers: Option<Vec<String>>) {
        self.config.lock().unwrap().stun_servers_v6 = servers;
    }

    fn get_secure_mode(&self) -> Option<SecureModeConfig> {
        self.config.lock().unwrap().secure_mode.clone()
    }

    fn set_secure_mode(&self, secure_mode: Option<SecureModeConfig>) {
        self.config.lock().unwrap().secure_mode = secure_mode;
    }

    fn get_credential_file(&self) -> Option<PathBuf> {
        self.config.lock().unwrap().credential_file.clone()
    }

    fn set_credential_file(&self, path: Option<PathBuf>) {
        self.config.lock().unwrap().credential_file = path;
    }

    fn get_network_config_source(&self) -> ConfigSource {
        self.config
            .lock()
            .unwrap()
            .source
            .as_ref()
            .map(|source| source.source)
            .unwrap_or(ConfigSource::User)
    }

    fn set_network_config_source(&self, source: Option<ConfigSource>) {
        self.config.lock().unwrap().source = source.and_then(|source| match source {
            ConfigSource::User => None,
            other => Some(ConfigSourceConfig { source: other }),
        });
    }

    fn dump(&self) -> String {
        #[cfg(feature = "config-write")]
        {
            let mut config = self.config.lock().unwrap().clone();
            Self::normalize_config_source(&mut config);
            config.flags = Some(flags_diff_from_default(&self.get_flags()));
            if config.stun_servers == Some(default_udp_stun_servers()) {
                config.stun_servers = None;
            }
            if config.stun_servers_v6 == Some(default_udp_v6_stun_servers()) {
                config.stun_servers_v6 = None;
            }
            toml::to_string_pretty(&config).unwrap()
        }
        #[cfg(not(feature = "config-write"))]
        {
            panic!("this build does not include TOML configuration serialization")
        }
    }
}

/// Transitional name retained while native consumers migrate to [`TomlConfig`].
pub type TomlConfigLoader = TomlConfig;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_error_preserves_source_and_location() {
        let error =
            TomlConfig::new_from_str_with_source("fixture.toml", "dhcp = \"yes\"").unwrap_err();
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

    #[test]
    fn toml_round_trip_preserves_config_and_non_default_flags() {
        let config = TomlConfig::new_from_str(
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

        let dumped = config.dump();
        let restored = TomlConfig::new_from_str(&dumped).unwrap();

        assert_eq!(restored.get_id(), config.get_id());
        assert_eq!(restored.get_hostname(), "host-a");
        assert_eq!(
            restored.get_network_identity(),
            config.get_network_identity()
        );
        assert_eq!(restored.get_listener_uris(), config.get_listener_uris());
        assert_eq!(restored.get_flags().mtu, 1420);
        assert_eq!(restored.get_flags().socket_mark, Some(0));
    }

    #[test]
    fn hostname_normalization_is_portable_and_has_no_host_fallback() {
        let absent = TomlConfig::default();
        assert_eq!(absent.get_hostname(), "");

        let configured = TomlConfig::new_from_str("hostname = \"node\\u0007-name\"").unwrap();
        assert_eq!(configured.get_hostname(), "node-name");
    }

    #[test]
    fn credential_mode_does_not_synthesize_a_network_secret() {
        let config = TomlConfig::new_from_str(
            r#"
[network_identity]
network_name = "credential-network"

[secure_mode]
enabled = true
"#,
        )
        .unwrap();

        let identity = config.get_network_identity();
        assert_eq!(identity.network_name, "credential-network");
        assert_eq!(identity.network_secret, None);
    }

    #[test]
    fn user_source_is_implicit_while_web_source_round_trips() {
        let user = TomlConfig::new_from_str(
            r#"
[source]
source = "user"
"#,
        )
        .unwrap();
        assert_eq!(user.get_network_config_source(), ConfigSource::User);
        assert!(!user.dump().contains("[source]"));

        let web = TomlConfig::new_from_str(
            r#"
[source]
source = "web"
"#,
        )
        .unwrap();
        assert_eq!(web.get_network_config_source(), ConfigSource::Web);
        assert!(web.dump().contains("source = \"web\""));
    }
}

#[cfg(test)]
mod compatibility_tests {
    use super::*;

    #[cfg(feature = "config-write")]
    #[test]
    fn flags_diff_covers_every_protobuf_field() {
        use prost::Message as _;

        let descriptor_set =
            prost_types::FileDescriptorSet::decode(crate::proto::DESCRIPTOR_POOL_BYTES).unwrap();
        let proto_fields = descriptor_set
            .file
            .iter()
            .find(|file| file.package.as_deref() == Some("common"))
            .and_then(|file| {
                file.message_type
                    .iter()
                    .find(|message| message.name.as_deref() == Some("FlagsInConfig"))
            })
            .unwrap()
            .field
            .iter()
            .map(|field| field.name.as_deref().unwrap())
            .collect::<std::collections::BTreeSet<_>>();
        let diff_fields = FLAGS_DIFF_FIELDS
            .iter()
            .copied()
            .collect::<std::collections::BTreeSet<_>>();

        assert_eq!(diff_fields, proto_fields);
    }

    #[test]
    fn socket_mark_config_file_roundtrip_none_some_and_zero() {
        // Omitting the flag leaves socket_mark unset (None) -> SO_MARK untouched.
        let cfg = TomlConfigLoader::new_from_str(
            r#"
[network_identity]
network_name = "n"
network_secret = "s"
"#,
        )
        .unwrap();
        assert_eq!(cfg.get_flags().socket_mark, None);

        // socket_mark = 0 is a legitimate value distinct from "unset".
        let cfg = TomlConfigLoader::new_from_str(
            r#"
[network_identity]
network_name = "n"
network_secret = "s"

[flags]
socket_mark = 0
"#,
        )
        .unwrap();
        assert_eq!(cfg.get_flags().socket_mark, Some(0));

        // A non-zero mark round-trips as Some(v).
        let cfg = TomlConfigLoader::new_from_str(
            r#"
[network_identity]
network_name = "n"
network_secret = "s"

[flags]
socket_mark = 66
"#,
        )
        .unwrap();
        assert_eq!(cfg.get_flags().socket_mark, Some(66));

        // set_flags(None) must serialize back through gen_config without
        // resurrecting a value (guards the gen_flags merge against dropping
        // the key when the serialized default is null).
        cfg.set_flags(Flags {
            socket_mark: None,
            ..cfg.get_flags()
        });
        assert_eq!(cfg.get_flags().socket_mark, None);
    }

    #[test]
    fn dump_preserves_flags_that_differ_from_easytier_defaults() {
        let cfg = TomlConfigLoader::default();
        let mut flags = gen_default_flags();
        flags.dev_name = "et_test".to_string();
        flags.enable_quic_proxy = true;
        flags.disable_tcp_hole_punching = true;
        flags.disable_sym_hole_punching = true;
        flags.multi_thread = false;
        flags.bind_device = false;
        flags.enable_ipv6 = false;
        flags.relay_network_whitelist = "".to_string();
        flags.mtu = 0;
        flags.foreign_relay_bps_limit = u64::MAX - 1;
        flags.instance_recv_bps_limit = u64::MAX - 2;
        flags.data_compress_algo = CompressionAlgoPb::Zstd.into();
        flags.socket_mark = Some(0);
        cfg.set_flags(flags);

        let dumped = cfg.dump();

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

        let reloaded = TomlConfigLoader::new_from_str(&dumped).unwrap();
        let reloaded_flags = reloaded.get_flags();
        assert_eq!(reloaded_flags.dev_name, "et_test");
        assert!(reloaded_flags.enable_quic_proxy);
        assert!(reloaded_flags.disable_tcp_hole_punching);
        assert!(reloaded_flags.disable_sym_hole_punching);
        assert!(!reloaded_flags.multi_thread);
        assert!(!reloaded_flags.bind_device);
        assert!(!reloaded_flags.enable_ipv6);
        assert_eq!(reloaded_flags.relay_network_whitelist, "");
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
        let config = TomlConfigLoader::default();
        let stun_servers = config.get_stun_servers();
        assert!(stun_servers.is_none());

        // Test setting custom stun servers
        let custom_servers = vec!["txt:stun.easytier.cn".to_string()];
        config.set_stun_servers(Some(custom_servers.clone()));

        let retrieved_servers = config.get_stun_servers();
        assert_eq!(retrieved_servers.unwrap(), custom_servers);
    }

    #[test]
    fn test_stun_servers_toml_parsing() {
        let config_str = r#"
instance_name = "test"
stun_servers = [
    "stun.l.google.com:19302",
    "stun1.l.google.com:19302",
    "txt:stun.easytier.cn"
]"#;

        let config = TomlConfigLoader::new_from_str(config_str).unwrap();
        let stun_servers = config.get_stun_servers().unwrap();

        assert_eq!(stun_servers.len(), 3);
        assert_eq!(stun_servers[0], "stun.l.google.com:19302");
        assert_eq!(stun_servers[1], "stun1.l.google.com:19302");
        assert_eq!(stun_servers[2], "txt:stun.easytier.cn");
    }

    #[test]
    fn test_network_config_source_toml_roundtrip() {
        let config = TomlConfigLoader::default();
        assert_eq!(config.get_network_config_source(), ConfigSource::User);

        config.set_network_config_source(Some(ConfigSource::Web));
        let dumped = config.dump();

        assert!(dumped.contains("[source]"));
        assert!(dumped.contains("source = \"web\""));

        let loaded = TomlConfigLoader::new_from_str(&dumped).unwrap();
        assert_eq!(loaded.get_network_config_source(), ConfigSource::Web);
    }

    #[test]
    fn test_toml_credential_mode_omits_network_secret() {
        for network_secret in ["", r#"network_secret = """#] {
            let config = TomlConfigLoader::new_from_str(&format!(
                r#"
[network_identity]
network_name = "credential-network"
{network_secret}

[secure_mode]
enabled = true
"#
            ))
            .unwrap();

            let identity = config.get_network_identity();
            assert_eq!(identity.network_name, "credential-network");
            assert_eq!(identity.network_secret, None);
            assert_eq!(identity.network_secret_digest, None);
            assert!(!config.dump().contains("network_secret"));
        }
    }

    #[test]
    fn test_toml_secure_mode_without_network_identity_uses_default_secret() {
        let config = TomlConfigLoader::new_from_str(
            r#"
[secure_mode]
enabled = true
"#,
        )
        .unwrap();

        let identity = config.get_network_identity();
        assert_eq!(identity.network_name, "default");
        assert_eq!(identity.network_secret.as_deref(), Some(""));
        assert!(identity.network_secret_digest.is_some());
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

        let config = TomlConfigLoader::new_from_str(config_str).unwrap();
        let acl = config.get_acl().unwrap();
        let acl_v1 = acl.acl_v1.unwrap();
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
        let config = TomlConfigLoader::new_from_str(declares_only).unwrap();
        let group = config.get_acl().unwrap().acl_v1.unwrap().group.unwrap();
        assert_eq!(group.declares.len(), 1);
        assert!(group.members.is_empty());

        let members_only = r#"
[acl.acl_v1.group]
members = ["admin"]
"#;
        let config = TomlConfigLoader::new_from_str(members_only).unwrap();
        let group = config.get_acl().unwrap().acl_v1.unwrap().group.unwrap();
        assert!(group.declares.is_empty());
        assert_eq!(group.members, vec!["admin"]);
    }

    #[test]
    fn test_network_config_source_user_is_implicit() {
        let config = TomlConfigLoader::default();
        config.set_network_config_source(Some(ConfigSource::User));
        let dumped = config.dump();

        assert!(!dumped.contains("[source]"));

        let loaded = TomlConfigLoader::new_from_str(&dumped).unwrap();
        assert_eq!(loaded.get_network_config_source(), ConfigSource::User);

        let explicit_user = TomlConfigLoader::new_from_str(
            r#"
[source]
source = "user"
"#,
        )
        .unwrap();
        assert_eq!(
            explicit_user.get_network_config_source(),
            ConfigSource::User
        );
        assert!(!explicit_user.dump().contains("[source]"));
    }

    #[test]
    fn test_ipv6_public_addr_config_roundtrip() {
        let config = TomlConfigLoader::default();
        let prefix: cidr::Ipv6Cidr = "2001:db8:100::/64".parse().unwrap();

        config.set_ipv6_public_addr_provider(true);
        config.set_ipv6_public_addr_auto(true);
        config.set_ipv6_public_addr_prefix(Some(prefix));

        assert!(config.get_ipv6_public_addr_provider());
        assert!(config.get_ipv6_public_addr_auto());
        assert_eq!(config.get_ipv6_public_addr_prefix(), Some(prefix));

        let dumped = config.dump();
        let loaded = TomlConfigLoader::new_from_str(&dumped).unwrap();
        assert!(loaded.get_ipv6_public_addr_provider());
        assert!(loaded.get_ipv6_public_addr_auto());
        assert_eq!(loaded.get_ipv6_public_addr_prefix(), Some(prefix));
    }
}

#[cfg(test)]
mod full_example_tests {
    use super::*;

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
        let ret = TomlConfigLoader::new_from_str(config_str);
        if let Err(e) = &ret {
            println!("{}", e);
        } else {
            println!("{:?}", ret.as_ref().unwrap());
        }
        assert!(ret.is_ok());

        let ret = ret.unwrap();
        assert_eq!("10.144.144.10/24", ret.get_ipv4().unwrap().to_string());

        assert_eq!(
            vec!["tcp://0.0.0.0:11010", "udp://0.0.0.0:11010"],
            ret.get_listener_uris()
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
            ret.get_port_forwards()
        );
        println!("{}", ret.dump());
    }
}

#[cfg(test)]
mod diagnostic_compatibility_tests {
    use super::*;

    #[test]
    fn stdin_source_name_and_caret_are_preserved() {
        let error = TomlConfig::new_from_str_with_source("stdin", "dhcp = \"yes\"")
            .unwrap_err()
            .to_string();

        assert!(error.contains("stdin"));
        assert!(error.contains("dhcp = \"yes\""));
        assert!(error.contains('^'));
        assert!(!error.contains("<unknown>"));
    }

    #[test]
    fn non_ascii_before_typed_error_keeps_byte_location() {
        let error = TomlConfig::new_from_str("hostname = \"节点\"\ndhcp = \"yes\"")
            .unwrap_err()
            .to_string();

        assert!(error.contains("dhcp = \"yes\""));
        assert!(error.contains('^'));
        assert!(error.contains("invalid type: string"));
    }

    #[test]
    fn non_ascii_on_syntax_error_line_keeps_source_location() {
        let error = TomlConfig::new_from_str("hostname = \"节点\" dhcp = \"yes\"")
            .unwrap_err()
            .to_string();

        assert!(error.contains("inline config:1:"));
        assert!(error.contains("hostname = \"节点\" dhcp = \"yes\""));
        assert!(error.contains("expected newline"));
        assert!(!error.contains("<unknown>"));
    }

    #[test]
    fn flags_conversion_error_keeps_source_and_cause_chain() {
        let error = TomlConfig::new_from_str_with_source(
            "flags-fixture.toml",
            "[flags]\nsocket_mark = \"bad\"",
        )
        .unwrap_err();
        let display = error.to_string();

        assert!(display.contains("flags-fixture.toml"));
        assert!(display.contains("failed to load config"));
        assert!(display.contains("failed to parse flags"));
        assert!(
            error
                .chain()
                .any(|cause| cause.to_string().contains("failed to parse flags"))
        );
    }
}
