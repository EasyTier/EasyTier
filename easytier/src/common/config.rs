use std::{
    net::{IpAddr, SocketAddr},
    path::PathBuf,
    sync::{Arc, Mutex},
    u64,
};

use anyhow::Context;
use cidr::IpCidr;
use serde::{Deserialize, Serialize};

use crate::{
    proto::{
        acl::Acl,
        common::{CompressionAlgoPb, PortForwardConfigPb, SocketType},
    },
    tunnel::generate_digest_from_str,
};

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
        relay_all_peer_rpc: false,
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
        foreign_relay_bps_limit: u64::MAX,
        multi_thread_count: 2,
        encryption_algorithm: "".to_string(), // 空字符串表示使用默认的 AES-GCM
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

    fn get_rpc_portal(&self) -> Option<SocketAddr>;
    fn set_rpc_portal(&self, addr: SocketAddr);

    fn get_rpc_portal_whitelist(&self) -> Option<Vec<IpCidr>>;
    fn set_rpc_portal_whitelist(&self, whitelist: Option<Vec<IpCidr>>);

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

    fn dump(&self) -> String;
}

pub trait LoggingConfigLoader {
    fn get_file_logger_config(&self) -> FileLoggerConfig;

    fn get_console_logger_config(&self) -> ConsoleLoggerConfig;
}

pub type NetworkSecretDigest = [u8; 32];

#[derive(Debug, Clone, Deserialize, Serialize, Default, Eq, Hash)]
pub struct NetworkIdentity {
    pub network_name: String,
    pub network_secret: Option<String>,
    #[serde(skip)]
    pub network_secret_digest: Option<NetworkSecretDigest>,
}

impl PartialEq for NetworkIdentity {
    fn eq(&self, other: &Self) -> bool {
        if self.network_name != other.network_name {
            return false;
        }

        if self.network_secret.is_some()
            && other.network_secret.is_some()
            && self.network_secret != other.network_secret
        {
            return false;
        }

        if self.network_secret_digest.is_some()
            && other.network_secret_digest.is_some()
            && self.network_secret_digest != other.network_secret_digest
        {
            return false;
        }

        return true;
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

    pub fn default() -> Self {
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
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Default)]
pub struct ConsoleLoggerConfig {
    pub level: Option<String>,
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, derive_builder::Builder)]
pub struct LoggingConfig {
    #[builder(setter(into, strip_option), default = None)]
    file_logger: Option<FileLoggerConfig>,
    #[builder(setter(into, strip_option), default = None)]
    console_logger: Option<ConsoleLoggerConfig>,
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

impl Into<PortForwardConfigPb> for PortForwardConfig {
    fn into(self) -> PortForwardConfigPb {
        PortForwardConfigPb {
            bind_addr: Some(self.bind_addr.into()),
            dst_addr: Some(self.dst_addr.into()),
            socket_type: match self.proto.to_lowercase().as_str() {
                "tcp" => SocketType::Tcp as i32,
                "udp" => SocketType::Udp as i32,
                _ => SocketType::Tcp as i32,
            },
        }
    }
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq)]
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

    rpc_portal: Option<SocketAddr>,
    rpc_portal_whitelist: Option<Vec<IpCidr>>,

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
            .map(|s| s.parse().ok())
            .flatten()
            .map(|c: cidr::Ipv4Inet| {
                if c.network_length() == 32 {
                    cidr::Ipv4Inet::new(c.address(), 24).unwrap()
                } else {
                    c
                }
            })
    }

    fn set_ipv4(&self, addr: Option<cidr::Ipv4Inet>) {
        self.config.lock().unwrap().ipv4 = if let Some(addr) = addr {
            Some(addr.to_string())
        } else {
            None
        };
    }

    fn get_ipv6(&self) -> Option<cidr::Ipv6Inet> {
        let locked_config = self.config.lock().unwrap();
        locked_config
            .ipv6
            .as_ref()
            .map(|s| s.parse().ok())
            .flatten()
    }

    fn set_ipv6(&self, addr: Option<cidr::Ipv6Inet>) {
        self.config.lock().unwrap().ipv6 = if let Some(addr) = addr {
            Some(addr.to_string())
        } else {
            None
        };
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
            locked_config.instance_id.as_ref().unwrap().clone()
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
            .unwrap_or_else(NetworkIdentity::default)
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

    fn get_rpc_portal(&self) -> Option<SocketAddr> {
        self.config.lock().unwrap().rpc_portal
    }

    fn set_rpc_portal(&self, addr: SocketAddr) {
        self.config.lock().unwrap().rpc_portal = Some(addr);
    }

    fn get_rpc_portal_whitelist(&self) -> Option<Vec<IpCidr>> {
        self.config.lock().unwrap().rpc_portal_whitelist.clone()
    }

    fn set_rpc_portal_whitelist(&self, whitelist: Option<Vec<IpCidr>>) {
        self.config.lock().unwrap().rpc_portal_whitelist = whitelist;
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
        toml::to_string_pretty(&config).unwrap()
    }
}

#[cfg(test)]
pub mod tests {
    use super::*;

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
}
