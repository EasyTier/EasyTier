use std::{
    hash::Hasher,
    net::{IpAddr, SocketAddr},
    path::PathBuf,
    sync::{Arc, Mutex},
};

use anyhow::Context;
use serde::{Deserialize, Serialize};
use tokio::io::AsyncReadExt as _;

use crate::{
    common::stun::StunInfoCollector,
    instance::dns_server::DEFAULT_ET_DNS_ZONE,
    proto::{
        acl::Acl,
        common::{CompressionAlgoPb, PortForwardConfigPb, SocketType},
    },
    tunnel::generate_digest_from_str,
};

use super::env_parser;

pub type Flags = crate::proto::common::FlagsInConfig;

pub fn gen_default_flags() -> Flags {
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
        quic_listen_port: 0,
        foreign_relay_bps_limit: u64::MAX,
        multi_thread_count: 2,
        encryption_algorithm: "aes-gcm".to_string(),
        disable_sym_hole_punching: false,
        tld_dns_zone: DEFAULT_ET_DNS_ZONE.to_string(),
    }
}

pub enum EncryptionAlgorithm {
    AesGcm,
    Aes256Gcm,
    Xor,
    #[cfg(feature = "wireguard")]
    ChaCha20,

    #[cfg(feature = "openssl-crypto")]
    OpensslAesGcm,
    #[cfg(feature = "openssl-crypto")]
    OpensslChacha20,
    #[cfg(feature = "openssl-crypto")]
    OpensslAes256Gcm,
}

impl std::fmt::Display for EncryptionAlgorithm {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::AesGcm => write!(f, "aes-gcm"),
            Self::Aes256Gcm => write!(f, "aes-256-gcm"),
            Self::Xor => write!(f, "xor"),
            #[cfg(feature = "wireguard")]
            Self::ChaCha20 => write!(f, "chacha20"),
            #[cfg(feature = "openssl-crypto")]
            Self::OpensslAesGcm => write!(f, "openssl-aes-gcm"),
            #[cfg(feature = "openssl-crypto")]
            Self::OpensslChacha20 => write!(f, "openssl-chacha20"),
            #[cfg(feature = "openssl-crypto")]
            Self::OpensslAes256Gcm => write!(f, "openssl-aes-256-gcm"),
        }
    }
}

impl TryFrom<&str> for EncryptionAlgorithm {
    type Error = anyhow::Error;

    fn try_from(value: &str) -> Result<Self, Self::Error> {
        match value {
            "aes-gcm" => Ok(Self::AesGcm),
            "aes-256-gcm" => Ok(Self::Aes256Gcm),
            "xor" => Ok(Self::Xor),
            #[cfg(feature = "wireguard")]
            "chacha20" => Ok(Self::ChaCha20),
            #[cfg(feature = "openssl-crypto")]
            "openssl-aes-gcm" => Ok(Self::OpensslAesGcm),
            #[cfg(feature = "openssl-crypto")]
            "openssl-chacha20" => Ok(Self::OpensslChacha20),
            #[cfg(feature = "openssl-crypto")]
            "openssl-aes-256-gcm" => Ok(Self::OpensslAes256Gcm),
            _ => Err(anyhow::anyhow!("invalid encryption algorithm")),
        }
    }
}

pub fn get_avaliable_encrypt_methods() -> Vec<&'static str> {
    let mut r = vec!["aes-gcm", "aes-256-gcm", "xor"];
    if cfg!(feature = "wireguard") {
        r.push("chacha20");
    }
    if cfg!(feature = "openssl-crypto") {
        r.extend(vec![
            "openssl-aes-gcm",
            "openssl-chacha20",
            "openssl-aes-256-gcm",
        ]);
    }
    r
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

    fn dump(&self) -> String;
}

pub trait LoggingConfigLoader {
    fn get_file_logger_config(&self) -> FileLoggerConfig;

    fn get_console_logger_config(&self) -> ConsoleLoggerConfig;
}

pub type NetworkSecretDigest = [u8; 32];

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct NetworkIdentity {
    pub network_name: String,
    pub network_secret: Option<String>,
    #[serde(skip)]
    pub network_secret_digest: Option<NetworkSecretDigest>,
}

#[derive(Eq, PartialEq, Hash)]
struct NetworkIdentityWithOnlyDigest {
    network_name: String,
    network_secret_digest: Option<NetworkSecretDigest>,
}

impl From<NetworkIdentity> for NetworkIdentityWithOnlyDigest {
    fn from(identity: NetworkIdentity) -> Self {
        if identity.network_secret_digest.is_some() {
            Self {
                network_name: identity.network_name,
                network_secret_digest: identity.network_secret_digest,
            }
        } else if identity.network_secret.is_some() {
            let mut network_secret_digest = [0u8; 32];
            generate_digest_from_str(
                &identity.network_name,
                identity.network_secret.as_ref().unwrap(),
                &mut network_secret_digest,
            );
            Self {
                network_name: identity.network_name,
                network_secret_digest: Some(network_secret_digest),
            }
        } else {
            Self {
                network_name: identity.network_name,
                network_secret_digest: None,
            }
        }
    }
}

impl PartialEq for NetworkIdentity {
    fn eq(&self, other: &Self) -> bool {
        let self_with_digest = NetworkIdentityWithOnlyDigest::from(self.clone());
        let other_with_digest = NetworkIdentityWithOnlyDigest::from(other.clone());
        self_with_digest == other_with_digest
    }
}

impl Eq for NetworkIdentity {}

impl std::hash::Hash for NetworkIdentity {
    fn hash<H: Hasher>(&self, state: &mut H) {
        let self_with_digest = NetworkIdentityWithOnlyDigest::from(self.clone());
        self_with_digest.hash(state);
    }
}

impl NetworkIdentity {
    pub fn new(network_name: String, network_secret: String) -> Self {
        let mut network_secret_digest = [0u8; 32];
        generate_digest_from_str(&network_name, &network_secret, &mut network_secret_digest);

        NetworkIdentity {
            network_name,
            network_secret: Some(network_secret),
            network_secret_digest: Some(network_secret_digest),
        }
    }
}

impl Default for NetworkIdentity {
    fn default() -> Self {
        Self::new("default".to_string(), "".to_string())
    }
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq)]
pub struct PeerConfig {
    pub uri: url::Url,
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

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq, Hash)]
pub struct PortForwardConfig {
    pub bind_addr: SocketAddr,
    pub dst_addr: SocketAddr,
    pub proto: String,
}

impl From<PortForwardConfigPb> for PortForwardConfig {
    fn from(config: PortForwardConfigPb) -> Self {
        PortForwardConfig {
            bind_addr: config.bind_addr.unwrap_or_default().into(),
            dst_addr: config.dst_addr.unwrap_or_default().into(),
            proto: match SocketType::try_from(config.socket_type) {
                Ok(SocketType::Tcp) => "tcp".to_string(),
                Ok(SocketType::Udp) => "udp".to_string(),
                _ => "tcp".to_string(),
            },
        }
    }
}

impl From<PortForwardConfig> for PortForwardConfigPb {
    fn from(val: PortForwardConfig) -> Self {
        PortForwardConfigPb {
            bind_addr: Some(val.bind_addr.into()),
            dst_addr: Some(val.dst_addr.into()),
            socket_type: match val.proto.to_lowercase().as_str() {
                "tcp" => SocketType::Tcp as i32,
                "udp" => SocketType::Udp as i32,
                _ => SocketType::Tcp as i32,
            },
        }
    }
}

#[derive(Debug, Clone, PartialEq, Deserialize, Serialize)]
struct Config {
    netns: Option<String>,
    hostname: Option<String>,
    instance_name: Option<String>,
    instance_id: Option<uuid::Uuid>,
    ipv4: Option<String>,
    ipv6: Option<String>,
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

    flags: Option<serde_json::Map<String, serde_json::Value>>,

    #[serde(skip)]
    flags_struct: Option<Flags>,

    acl: Option<Acl>,

    tcp_whitelist: Option<Vec<String>>,
    udp_whitelist: Option<Vec<String>>,
    stun_servers: Option<Vec<String>>,
    stun_servers_v6: Option<Vec<String>>,
}

#[derive(Debug, Clone)]
pub struct TomlConfigLoader {
    config: Arc<Mutex<Config>>,
}

impl Default for TomlConfigLoader {
    fn default() -> Self {
        TomlConfigLoader::new_from_str("").unwrap()
    }
}

impl TomlConfigLoader {
    pub fn new_from_str(config_str: &str) -> Result<Self, anyhow::Error> {
        let mut config = toml::de::from_str::<Config>(config_str)
            .with_context(|| format!("failed to parse config file: {}", config_str))?;

        config.flags_struct = Some(Self::gen_flags(config.flags.clone().unwrap_or_default()));

        let config = TomlConfigLoader {
            config: Arc::new(Mutex::new(config)),
        };

        let old_ns = config.get_network_identity();
        config.set_network_identity(NetworkIdentity::new(
            old_ns.network_name,
            old_ns.network_secret.unwrap_or_default(),
        ));

        Ok(config)
    }

    pub fn new(config_path: &PathBuf) -> Result<Self, anyhow::Error> {
        let config_str = std::fs::read_to_string(config_path)
            .with_context(|| format!("failed to read config file: {:?}", config_path))?;
        let ret = Self::new_from_str(&config_str)?;

        Ok(ret)
    }

    fn gen_flags(mut flags_hashmap: serde_json::Map<String, serde_json::Value>) -> Flags {
        let default_flags_json = serde_json::to_string(&gen_default_flags()).unwrap();
        let default_flags_hashmap =
            serde_json::from_str::<serde_json::Map<String, serde_json::Value>>(&default_flags_json)
                .unwrap();

        let mut merged_hashmap = serde_json::Map::new();
        for (key, value) in default_flags_hashmap {
            if let Some(v) = flags_hashmap.remove(&key) {
                merged_hashmap.insert(key, v);
            } else {
                merged_hashmap.insert(key, value);
            }
        }

        serde_json::from_value(serde_json::Value::Object(merged_hashmap)).unwrap()
    }
}

impl ConfigLoader for TomlConfigLoader {
    fn get_inst_name(&self) -> String {
        self.config
            .lock()
            .unwrap()
            .instance_name
            .clone()
            .unwrap_or("default".to_string())
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
                    gethostname::gethostname().to_string_lossy().to_string()
                }
            }
            None => gethostname::gethostname().to_string_lossy().to_string(),
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
        if let Some(mapped_cidr) = mapped_cidr.as_ref() {
            if cidr.network_length() != mapped_cidr.network_length() {
                return Err(anyhow::anyhow!(
                    "Mapped CIDR must have the same network length as the original CIDR: {} != {}",
                    cidr.network_length(),
                    mapped_cidr.network_length()
                ));
            }
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
        if locked_config.instance_id.is_none() {
            let id = uuid::Uuid::new_v4();
            locked_config.instance_id = Some(id);
            id
        } else {
            *locked_config.instance_id.as_ref().unwrap()
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

    fn dump(&self) -> String {
        let default_flags_json = serde_json::to_string(&gen_default_flags()).unwrap();
        let default_flags_hashmap =
            serde_json::from_str::<serde_json::Map<String, serde_json::Value>>(&default_flags_json)
                .unwrap();

        let cur_flags_json = serde_json::to_string(&self.get_flags()).unwrap();
        let cur_flags_hashmap =
            serde_json::from_str::<serde_json::Map<String, serde_json::Value>>(&cur_flags_json)
                .unwrap();

        let mut flag_map: serde_json::Map<String, serde_json::Value> = Default::default();
        for (key, value) in default_flags_hashmap {
            if let Some(v) = cur_flags_hashmap.get(&key) {
                if *v != value {
                    flag_map.insert(key, v.clone());
                }
            }
        }

        let mut config = self.config.lock().unwrap().clone();
        config.flags = Some(flag_map);
        if config.stun_servers == Some(StunInfoCollector::get_default_servers()) {
            config.stun_servers = None;
        }
        if config.stun_servers_v6 == Some(StunInfoCollector::get_default_servers_v6()) {
            config.stun_servers_v6 = None;
        }
        toml::to_string_pretty(&config).unwrap()
    }
}

#[derive(Clone, Copy, Default)]
pub struct ConfigFilePermission(u8);
impl ConfigFilePermission {
    pub const READ_ONLY: u8 = 1 << 0;
    pub const NO_DELETE: u8 = 1 << 1;

    pub fn with_flag(self, flag: u8) -> Self {
        Self(self.0 | flag)
    }
    pub fn remove_flag(self, flag: u8) -> Self {
        Self(self.0 & !flag)
    }
    pub fn has_flag(&self, flag: u8) -> bool {
        (self.0 & flag) != 0
    }
}
impl From<u8> for ConfigFilePermission {
    fn from(value: u8) -> Self {
        ConfigFilePermission(value)
    }
}
impl From<u32> for ConfigFilePermission {
    fn from(value: u32) -> Self {
        ConfigFilePermission(value as u8)
    }
}
impl From<ConfigFilePermission> for u8 {
    fn from(value: ConfigFilePermission) -> Self {
        value.0
    }
}
impl From<ConfigFilePermission> for u32 {
    fn from(value: ConfigFilePermission) -> Self {
        value.0 as u32
    }
}
impl std::fmt::Debug for ConfigFilePermission {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let mut flags = vec![];
        if self.has_flag(ConfigFilePermission::READ_ONLY) {
            flags.push("READ_ONLY");
        } else {
            flags.push("EDITABLE");
        }
        if self.has_flag(ConfigFilePermission::NO_DELETE) {
            flags.push("NO_DELETE");
        } else {
            flags.push("DELETABLE");
        }
        write!(f, "{}", flags.join("|"))
    }
}

#[derive(Debug, Clone)]
pub struct ConfigFileControl {
    pub path: Option<PathBuf>,
    pub permission: ConfigFilePermission,
}

impl ConfigFileControl {
    pub const STATIC_CONFIG: ConfigFileControl = Self {
        path: None,
        permission: ConfigFilePermission(
            ConfigFilePermission::READ_ONLY | ConfigFilePermission::NO_DELETE,
        ),
    };

    pub fn new(path: Option<PathBuf>, permission: ConfigFilePermission) -> Self {
        ConfigFileControl { path, permission }
    }

    pub async fn from_path(path: PathBuf) -> Self {
        let read_only = if let Ok(metadata) = tokio::fs::metadata(&path).await {
            metadata.permissions().readonly()
        } else {
            true
        };
        Self::new(
            Some(path),
            if read_only {
                ConfigFilePermission(ConfigFilePermission::READ_ONLY)
            } else {
                ConfigFilePermission(0)
            },
        )
    }

    pub fn is_read_only(&self) -> bool {
        self.permission.has_flag(ConfigFilePermission::READ_ONLY)
    }
    pub fn set_read_only(&mut self, read_only: bool) {
        if read_only {
            self.permission = self.permission.with_flag(ConfigFilePermission::READ_ONLY);
        } else {
            self.permission = self.permission.remove_flag(ConfigFilePermission::READ_ONLY);
        }
    }

    pub fn is_no_delete(&self) -> bool {
        self.permission.has_flag(ConfigFilePermission::NO_DELETE)
    }
    pub fn set_no_delete(&mut self, no_delete: bool) {
        if no_delete {
            self.permission = self.permission.with_flag(ConfigFilePermission::NO_DELETE);
        } else {
            self.permission = self.permission.remove_flag(ConfigFilePermission::NO_DELETE);
        }
    }

    pub fn is_deletable(&self) -> bool {
        !self.is_no_delete()
    }
}

pub async fn load_config_from_file(
    config_file: &PathBuf,
    config_dir: Option<&PathBuf>,
    disable_env_parsing: bool,
) -> Result<(TomlConfigLoader, ConfigFileControl), anyhow::Error> {
    if config_file.as_os_str() == "-" {
        let mut stdin = String::new();
        _ = tokio::io::stdin()
            .read_to_string(&mut stdin)
            .await
            .context("failed to read config from stdin")?;
        let config = TomlConfigLoader::new_from_str(&stdin)?;
        return Ok((config, ConfigFileControl::STATIC_CONFIG));
    }

    let config_str = tokio::fs::read_to_string(config_file)
        .await
        .with_context(|| format!("failed to read config file: {:?}", config_file))?;

    let (expanded_config_str, uses_env_vars) = if disable_env_parsing {
        (config_str.clone(), false)
    } else {
        env_parser::expand_env_vars(&config_str)
    };

    if disable_env_parsing {
        tracing::info!(
            "Environment variable parsing is disabled for config file: {:?}",
            config_file
        );
    }

    if uses_env_vars {
        tracing::info!(
            "Environment variables detected and expanded in config file: {:?}",
            config_file
        );
    }

    let config = TomlConfigLoader::new_from_str(&expanded_config_str)
        .with_context(|| format!("failed to load config file: {:?}", config_file))?;

    let mut control = ConfigFileControl::from_path(config_file.clone()).await;

    if uses_env_vars {
        control.set_read_only(true);
        control.set_no_delete(true);
        tracing::info!(
            "Config file {:?} uses environment variables, marked as READ_ONLY and NO_DELETE",
            config_file
        );
    } else if control.is_read_only() {
        control.set_no_delete(true);
    } else if let Some(config_dir) = config_dir {
        if let Some(config_file_dir) = config_file.parent() {
            // if the config file is in the config dir and named as the instance id, it can be saved remotely
            if config_file_dir == config_dir
                && config_file.file_stem() == Some(config.get_id().to_string().as_ref())
                && config_file.extension() == Some(std::ffi::OsStr::new("toml"))
            {
                control.set_no_delete(false);
            } else {
                control.set_no_delete(true);
            }
        }
    } else {
        control.set_no_delete(true);
    }

    Ok((config, control))
}

#[cfg(test)]
pub mod tests {
    use super::*;
    use std::io::Write;
    use std::path::PathBuf;
    use tempfile::NamedTempFile;

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

    #[tokio::test]
    async fn full_example_test() {
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

    /// 配置文件环境变量解析功能的集成测试
    ///
    /// 测试范围：
    /// 1. 配置加载功能测试（环境变量替换、权限标记）
    /// 2. RPC API 安全测试（只读配置保护）
    /// 3. CLI 参数测试（--disable-env-parsing 开关）
    /// 4. 多实例隔离测试
    /// 5. 实际配置字段测试（network_secret、peer.uri 等）
    /// 配置加载功能测试（环境变量替换、权限标记）
    ///
    /// 验证：
    /// - 环境变量能正确替换到配置中
    /// - 包含环境变量的配置文件自动标记为只读和禁止删除
    #[tokio::test]
    async fn test_env_var_expansion_and_readonly_flag() {
        // 设置测试环境变量
        std::env::set_var("TEST_SECRET", "my-test-secret-123");
        std::env::set_var("TEST_NETWORK", "test-network");

        // 创建临时配置文件，包含环境变量占位符
        let mut temp_file = NamedTempFile::new().unwrap();
        let config_content = r#"
instance_name = "test-instance"

[network_identity]
network_name = "${TEST_NETWORK}"
network_secret = "${TEST_SECRET}"
"#;
        temp_file.write_all(config_content.as_bytes()).unwrap();
        temp_file.flush().unwrap();

        let config_path = PathBuf::from(temp_file.path());

        // 加载配置（启用环境变量解析）
        let (config, control) = load_config_from_file(&config_path, None, false)
            .await
            .unwrap();

        // 验证环境变量已被替换
        let network_identity = config.get_network_identity();
        assert_eq!(network_identity.network_name, "test-network");
        assert_eq!(
            network_identity.network_secret.as_ref().unwrap(),
            "my-test-secret-123"
        );

        // 验证权限标记：包含环境变量的配置应被标记为只读和禁止删除
        assert!(
            control.is_read_only(),
            "Config with env vars should be marked as READ_ONLY"
        );
        assert!(
            control.is_no_delete(),
            "Config with env vars should be marked as NO_DELETE"
        );

        // 清理环境变量
        std::env::remove_var("TEST_SECRET");
        std::env::remove_var("TEST_NETWORK");
    }

    /// RPC API 安全测试（只读配置保护）
    ///
    /// 验证：
    /// - 只读配置不会通过 RPC API 暴露给远程调用
    /// - 这需要测试 get_network_instance_config 拒绝返回只读配置
    ///
    /// 注：这个测试验证权限标记的正确设置，实际的 RPC API 保护已在
    /// `easytier/src/rpc_service/instance_manage.rs` 中实现
    #[tokio::test]
    async fn test_readonly_config_api_protection() {
        std::env::set_var("API_TEST_SECRET", "secret-value");

        // 创建包含环境变量的配置
        let mut temp_file = NamedTempFile::new().unwrap();
        let config_content = r#"
instance_name = "api-test"

[network_identity]
network_name = "api-network"
network_secret = "${API_TEST_SECRET}"
"#;
        temp_file.write_all(config_content.as_bytes()).unwrap();
        temp_file.flush().unwrap();

        let config_path = PathBuf::from(temp_file.path());

        // 加载配置
        let (_config, control) = load_config_from_file(&config_path, None, false)
            .await
            .unwrap();

        // 验证只读标记已设置（这是 RPC API 保护的前提）
        assert!(
            control.is_read_only(),
            "Config should be marked as READ_ONLY for RPC protection"
        );
        assert!(
            control.permission.has_flag(ConfigFilePermission::READ_ONLY),
            "Permission flag should be set correctly"
        );

        std::env::remove_var("API_TEST_SECRET");
    }

    /// CLI 参数测试（--disable-env-parsing 开关）
    ///
    /// 验证：
    /// - disable_env_parsing = true 时，环境变量不会被替换
    /// - 配置不会被标记为只读
    #[tokio::test]
    async fn test_disable_env_parsing_flag() {
        std::env::set_var("DISABLED_TEST_VAR", "should-not-expand");

        // 创建包含环境变量占位符的配置
        let mut temp_file = NamedTempFile::new().unwrap();
        let config_content = r#"
instance_name = "disable-test"

[network_identity]
network_name = "test"
network_secret = "${DISABLED_TEST_VAR}"
"#;
        temp_file.write_all(config_content.as_bytes()).unwrap();
        temp_file.flush().unwrap();

        let config_path = PathBuf::from(temp_file.path());

        // 以 disable_env_parsing = true 加载配置
        let (config, control) = load_config_from_file(&config_path, None, true)
            .await
            .unwrap();

        // 验证环境变量未被替换（保持原样）
        let network_identity = config.get_network_identity();
        assert_eq!(
            network_identity.network_secret.as_ref().unwrap(),
            "${DISABLED_TEST_VAR}",
            "Env var should not be expanded when parsing is disabled"
        );

        // 验证配置不因环境变量而被标记为只读
        // 注：文件系统权限可能使其只读，但不应因环境变量而只读
        // 这里我们主要验证 NO_DELETE 标记的逻辑
        // 由于没有 config_dir，文件会被标记为 NO_DELETE，但不是因为环境变量
        assert!(
            control.is_no_delete(),
            "Config should be NO_DELETE due to no config_dir, not env vars"
        );

        std::env::remove_var("DISABLED_TEST_VAR");
    }

    /// 多实例隔离测试
    ///
    /// 验证：
    /// - 不同实例可以使用不同的环境变量值
    /// - 环境变量在运行时被解析，支持动态切换
    #[tokio::test]
    async fn test_multiple_instances_with_different_env_vars() {
        // 实例1：使用第一组环境变量
        std::env::set_var("INSTANCE_SECRET", "instance1-secret");
        std::env::set_var("INSTANCE_NAME", "instance-one");

        let mut temp_file1 = NamedTempFile::new().unwrap();
        let config_content = r#"
instance_name = "${INSTANCE_NAME}"

[network_identity]
network_name = "multi-test"
network_secret = "${INSTANCE_SECRET}"
"#;
        temp_file1.write_all(config_content.as_bytes()).unwrap();
        temp_file1.flush().unwrap();

        let config_path1 = PathBuf::from(temp_file1.path());
        let (config1, _) = load_config_from_file(&config_path1, None, false)
            .await
            .unwrap();

        // 验证实例1的配置
        assert_eq!(config1.get_inst_name(), "instance-one");
        assert_eq!(
            config1
                .get_network_identity()
                .network_secret
                .as_ref()
                .unwrap(),
            "instance1-secret"
        );

        // 实例2：修改环境变量后加载同一模板
        std::env::set_var("INSTANCE_SECRET", "instance2-secret");
        std::env::set_var("INSTANCE_NAME", "instance-two");

        let mut temp_file2 = NamedTempFile::new().unwrap();
        temp_file2.write_all(config_content.as_bytes()).unwrap();
        temp_file2.flush().unwrap();

        let config_path2 = PathBuf::from(temp_file2.path());
        let (config2, _) = load_config_from_file(&config_path2, None, false)
            .await
            .unwrap();

        // 验证实例2使用了不同的环境变量值
        assert_eq!(config2.get_inst_name(), "instance-two");
        assert_eq!(
            config2
                .get_network_identity()
                .network_secret
                .as_ref()
                .unwrap(),
            "instance2-secret"
        );

        // 验证两个实例的配置确实不同
        assert_ne!(config1.get_inst_name(), config2.get_inst_name());
        assert_ne!(
            config1.get_network_identity().network_secret,
            config2.get_network_identity().network_secret
        );

        // 清理
        std::env::remove_var("INSTANCE_SECRET");
        std::env::remove_var("INSTANCE_NAME");
    }

    /// 实际配置字段测试（network_secret、peer.uri 等）
    ///
    /// 验证：
    /// - network_secret 字段支持环境变量
    /// - peer.uri 字段支持环境变量
    /// - listeners 字段支持环境变量
    /// - 其他实际使用的配置字段
    #[tokio::test]
    async fn test_real_config_fields_expansion() {
        // 设置各种实际场景的环境变量
        std::env::set_var("ET_SECRET", "production-secret-key");
        std::env::set_var("PEER_HOST", "peer.example.com");
        std::env::set_var("PEER_PORT", "11011");
        std::env::set_var("LISTEN_PORT", "11010");
        std::env::set_var("NETWORK_NAME", "prod-network");

        // 创建包含多个实际字段的完整配置
        let mut temp_file = NamedTempFile::new().unwrap();
        let config_content = r#"
instance_name = "production"
ipv4 = "10.144.144.1"
listeners = ["tcp://0.0.0.0:${LISTEN_PORT}"]

[network_identity]
network_name = "${NETWORK_NAME}"
network_secret = "${ET_SECRET}"

[[peer]]
uri = "tcp://${PEER_HOST}:${PEER_PORT}"
"#;
        temp_file.write_all(config_content.as_bytes()).unwrap();
        temp_file.flush().unwrap();

        let config_path = PathBuf::from(temp_file.path());

        let (config, control) = load_config_from_file(&config_path, None, false)
            .await
            .unwrap();

        // 验证 network_identity 字段
        let identity = config.get_network_identity();
        assert_eq!(identity.network_name, "prod-network");
        assert_eq!(
            identity.network_secret.as_ref().unwrap(),
            "production-secret-key"
        );

        // 验证 listeners 字段
        let listeners = config.get_listener_uris();
        assert_eq!(listeners.len(), 1);
        assert_eq!(listeners[0].to_string(), "tcp://0.0.0.0:11010");

        // 验证 peer 字段
        let peers = config.get_peers();
        assert_eq!(peers.len(), 1);
        assert_eq!(peers[0].uri.to_string(), "tcp://peer.example.com:11011");

        // 验证配置被正确标记
        assert!(control.is_read_only());
        assert!(control.is_no_delete());

        // 清理环境变量
        std::env::remove_var("ET_SECRET");
        std::env::remove_var("PEER_HOST");
        std::env::remove_var("PEER_PORT");
        std::env::remove_var("LISTEN_PORT");
        std::env::remove_var("NETWORK_NAME");
    }

    /// 带默认值的环境变量
    ///
    /// 验证：
    /// - ${VAR:-default} 语法在变量未定义时使用默认值
    #[tokio::test]
    async fn test_env_var_with_default_value() {
        // 确保变量未定义
        std::env::remove_var("UNDEFINED_PORT");
        std::env::remove_var("UNDEFINED_SECRET");

        let mut temp_file = NamedTempFile::new().unwrap();
        let config_content = r#"
instance_name = "default-test"
listeners = ["tcp://0.0.0.0:${UNDEFINED_PORT:-11010}"]

[network_identity]
network_name = "test"
network_secret = "${UNDEFINED_SECRET:-default-secret}"
"#;
        temp_file.write_all(config_content.as_bytes()).unwrap();
        temp_file.flush().unwrap();

        let config_path = PathBuf::from(temp_file.path());

        let (config, _) = load_config_from_file(&config_path, None, false)
            .await
            .unwrap();

        // 验证使用了默认值
        assert_eq!(
            config
                .get_network_identity()
                .network_secret
                .as_ref()
                .unwrap(),
            "default-secret"
        );
        assert_eq!(
            config.get_listener_uris()[0].to_string(),
            "tcp://0.0.0.0:11010"
        );
    }

    /// 环境变量未定义且无默认值的情况
    ///
    /// 验证：
    /// - 未定义的环境变量保持原样（shellexpand 的默认行为）
    #[tokio::test]
    async fn test_undefined_env_var_without_default() {
        std::env::remove_var("COMPLETELY_UNDEFINED");

        let mut temp_file = NamedTempFile::new().unwrap();
        let config_content = r#"
instance_name = "undefined-test"

[network_identity]
network_name = "test"
network_secret = "${COMPLETELY_UNDEFINED}"
"#;
        temp_file.write_all(config_content.as_bytes()).unwrap();
        temp_file.flush().unwrap();

        let config_path = PathBuf::from(temp_file.path());
        let (config, control) = load_config_from_file(&config_path, None, false)
            .await
            .unwrap();

        // 验证变量保持原样
        assert_eq!(
            config
                .get_network_identity()
                .network_secret
                .as_ref()
                .unwrap(),
            "${COMPLETELY_UNDEFINED}"
        );

        // 注意：由于没有实际替换发生，控制标记不应因环境变量而设置
        // 但会因为其他原因（如没有 config_dir）被标记为 NO_DELETE
        assert!(control.is_no_delete());
    }

    /// 布尔类型环境变量
    ///
    /// 验证：
    /// - 布尔类型的环境变量能正确解析和反序列化
    /// - TOML 解析器能将字符串 "true"/"false" 转换为布尔值
    #[tokio::test]
    async fn test_boolean_type_env_vars() {
        // 设置布尔类型的环境变量
        std::env::set_var("ENABLE_DHCP", "true");
        std::env::set_var("ENABLE_ENCRYPTION", "false");
        std::env::set_var("ENABLE_IPV6", "true");

        let mut temp_file = NamedTempFile::new().unwrap();
        let config_content = r#"
instance_name = "bool-test"
dhcp = ${ENABLE_DHCP}

[network_identity]
network_name = "test"
network_secret = "secret"

[flags]
enable_encryption = ${ENABLE_ENCRYPTION}
enable_ipv6 = ${ENABLE_IPV6}
"#;
        temp_file.write_all(config_content.as_bytes()).unwrap();
        temp_file.flush().unwrap();

        let config_path = PathBuf::from(temp_file.path());
        let (config, control) = load_config_from_file(&config_path, None, false)
            .await
            .unwrap();

        // 验证布尔值被正确解析
        assert!(config.get_dhcp(), "dhcp should be true");

        let flags = config.get_flags();
        assert!(
            !flags.enable_encryption,
            "enable_encryption should be false"
        );
        assert!(flags.enable_ipv6, "enable_ipv6 should be true");

        // 验证使用环境变量的配置被标记为只读
        assert!(control.is_read_only());
        assert!(control.is_no_delete());

        // 清理
        std::env::remove_var("ENABLE_DHCP");
        std::env::remove_var("ENABLE_ENCRYPTION");
        std::env::remove_var("ENABLE_IPV6");
    }

    /// 数字类型环境变量
    ///
    /// 验证：
    /// - 数字类型（整数、端口号）的环境变量能正确解析和反序列化
    /// - TOML 解析器能将字符串 "1380" 转换为整数
    #[tokio::test]
    async fn test_numeric_type_env_vars() {
        // 设置数字类型的环境变量
        std::env::set_var("MTU_VALUE", "1400");
        std::env::set_var("QUIC_PORT", "8080");
        std::env::set_var("THREAD_COUNT", "4");

        let mut temp_file = NamedTempFile::new().unwrap();
        let config_content = r#"
instance_name = "numeric-test"

[network_identity]
network_name = "test"
network_secret = "secret"

[flags]
mtu = ${MTU_VALUE}
quic_listen_port = ${QUIC_PORT}
multi_thread_count = ${THREAD_COUNT}
"#;
        temp_file.write_all(config_content.as_bytes()).unwrap();
        temp_file.flush().unwrap();

        let config_path = PathBuf::from(temp_file.path());
        let (config, control) = load_config_from_file(&config_path, None, false)
            .await
            .unwrap();

        // 验证数字值被正确解析
        let flags = config.get_flags();
        assert_eq!(flags.mtu, 1400, "mtu should be 1400");
        assert_eq!(
            flags.quic_listen_port, 8080,
            "quic_listen_port should be 8080"
        );
        assert_eq!(
            flags.multi_thread_count, 4,
            "multi_thread_count should be 4"
        );

        // 验证使用环境变量的配置被标记为只读
        assert!(control.is_read_only());
        assert!(control.is_no_delete());

        // 清理
        std::env::remove_var("MTU_VALUE");
        std::env::remove_var("QUIC_PORT");
        std::env::remove_var("THREAD_COUNT");
    }

    /// 混合类型环境变量
    ///
    /// 验证：
    /// - 字符串、布尔、数字类型的环境变量可以同时使用
    /// - 所有类型都能正确解析和反序列化
    /// - 模拟真实的复杂配置场景
    #[tokio::test]
    async fn test_mixed_type_env_vars() {
        // 设置不同类型的环境变量
        std::env::set_var("MIXED_SECRET", "mixed-secret-key");
        std::env::set_var("MIXED_NETWORK", "production");
        std::env::set_var("MIXED_DHCP", "true");
        std::env::set_var("MIXED_MTU", "1500");
        std::env::set_var("MIXED_ENCRYPTION", "false");
        std::env::set_var("MIXED_LISTEN_PORT", "12345");

        let mut temp_file = NamedTempFile::new().unwrap();
        let config_content = r#"
instance_name = "mixed-test"
ipv4 = "10.0.0.1"
dhcp = ${MIXED_DHCP}
listeners = ["tcp://0.0.0.0:${MIXED_LISTEN_PORT}"]

[network_identity]
network_name = "${MIXED_NETWORK}"
network_secret = "${MIXED_SECRET}"

[flags]
mtu = ${MIXED_MTU}
enable_encryption = ${MIXED_ENCRYPTION}
"#;
        temp_file.write_all(config_content.as_bytes()).unwrap();
        temp_file.flush().unwrap();

        let config_path = PathBuf::from(temp_file.path());
        let (config, control) = load_config_from_file(&config_path, None, false)
            .await
            .unwrap();

        // 验证字符串类型
        let identity = config.get_network_identity();
        assert_eq!(identity.network_name, "production");
        assert_eq!(
            identity.network_secret.as_ref().unwrap(),
            "mixed-secret-key"
        );

        // 验证布尔类型
        assert!(config.get_dhcp());

        let flags = config.get_flags();
        assert!(!flags.enable_encryption);

        // 验证数字类型
        assert_eq!(flags.mtu, 1500);

        // 验证 URL 中的端口号（数字）
        let listeners = config.get_listener_uris();
        assert_eq!(listeners.len(), 1);
        assert_eq!(listeners[0].to_string(), "tcp://0.0.0.0:12345");

        // 验证配置被标记为只读
        assert!(control.is_read_only());
        assert!(control.is_no_delete());

        // 清理
        std::env::remove_var("MIXED_SECRET");
        std::env::remove_var("MIXED_NETWORK");
        std::env::remove_var("MIXED_DHCP");
        std::env::remove_var("MIXED_MTU");
        std::env::remove_var("MIXED_ENCRYPTION");
        std::env::remove_var("MIXED_LISTEN_PORT");
    }
}
