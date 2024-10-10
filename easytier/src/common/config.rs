use std::{
    net::{Ipv4Addr, SocketAddr},
    path::PathBuf,
    sync::{Arc, Mutex},
};

use anyhow::Context;
use serde::{Deserialize, Serialize};

use crate::tunnel::generate_digest_from_str;

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

    fn get_dhcp(&self) -> bool;
    fn set_dhcp(&self, dhcp: bool);

    fn add_proxy_cidr(&self, cidr: cidr::IpCidr);
    fn remove_proxy_cidr(&self, cidr: cidr::IpCidr);
    fn get_proxy_cidrs(&self) -> Vec<cidr::IpCidr>;

    fn get_network_identity(&self) -> NetworkIdentity;
    fn set_network_identity(&self, identity: NetworkIdentity);

    fn get_listener_uris(&self) -> Vec<url::Url>;

    fn get_file_logger_config(&self) -> FileLoggerConfig;
    fn set_file_logger_config(&self, config: FileLoggerConfig);
    fn get_console_logger_config(&self) -> ConsoleLoggerConfig;
    fn set_console_logger_config(&self, config: ConsoleLoggerConfig);

    fn get_peers(&self) -> Vec<PeerConfig>;
    fn set_peers(&self, peers: Vec<PeerConfig>);

    fn get_listeners(&self) -> Vec<url::Url>;
    fn set_listeners(&self, listeners: Vec<url::Url>);

    fn get_rpc_portal(&self) -> Option<SocketAddr>;
    fn set_rpc_portal(&self, addr: SocketAddr);

    fn get_vpn_portal_config(&self) -> Option<VpnPortalConfig>;
    fn set_vpn_portal_config(&self, config: VpnPortalConfig);

    fn get_flags(&self) -> Flags;
    fn set_flags(&self, flags: Flags);

    fn get_exit_nodes(&self) -> Vec<Ipv4Addr>;
    fn set_exit_nodes(&self, nodes: Vec<Ipv4Addr>);

    fn get_routes(&self) -> Option<Vec<cidr::Ipv4Cidr>>;
    fn set_routes(&self, routes: Option<Vec<cidr::Ipv4Cidr>>);

    fn get_socks5_portal(&self) -> Option<url::Url>;
    fn set_socks5_portal(&self, addr: Option<url::Url>);

    fn dump(&self) -> String;
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
pub struct NetworkConfig {
    pub cidr: String,
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

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq)]
pub struct VpnPortalConfig {
    pub client_cidr: cidr::Ipv4Cidr,
    pub wireguard_listen: SocketAddr,
}

// Flags is used to control the behavior of the program
#[derive(derivative::Derivative, Deserialize, Serialize)]
#[derivative(Debug, Clone, PartialEq, Default)]
pub struct Flags {
    #[derivative(Default(value = "\"tcp\".to_string()"))]
    pub default_protocol: String,
    #[derivative(Default(value = "\"\".to_string()"))]
    pub dev_name: String,
    #[derivative(Default(value = "true"))]
    pub enable_encryption: bool,
    #[derivative(Default(value = "true"))]
    pub enable_ipv6: bool,
    #[derivative(Default(value = "1380"))]
    pub mtu: u16,
    #[derivative(Default(value = "true"))]
    pub latency_first: bool,
    #[derivative(Default(value = "false"))]
    pub enable_exit_node: bool,
    #[derivative(Default(value = "false"))]
    pub no_tun: bool,
    #[derivative(Default(value = "false"))]
    pub use_smoltcp: bool,
    #[derivative(Default(value = "\"*\".to_string()"))]
    pub foreign_network_whitelist: String,
    #[derivative(Default(value = "false"))]
    pub disable_p2p: bool,
    #[derivative(Default(value = "false"))]
    pub relay_all_peer_rpc: bool,
    #[derivative(Default(value = "false"))]
    pub disable_udp_hole_punching: bool,
    #[derivative(Default(value = "\"udp://[::]:0\".to_string()"))]
    pub ipv6_listener: String,
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq)]
struct Config {
    netns: Option<String>,
    hostname: Option<String>,
    instance_name: Option<String>,
    instance_id: Option<uuid::Uuid>,
    ipv4: Option<String>,
    dhcp: Option<bool>,
    network_identity: Option<NetworkIdentity>,
    listeners: Option<Vec<url::Url>>,
    exit_nodes: Option<Vec<Ipv4Addr>>,

    peer: Option<Vec<PeerConfig>>,
    proxy_network: Option<Vec<NetworkConfig>>,

    file_logger: Option<FileLoggerConfig>,
    console_logger: Option<ConsoleLoggerConfig>,

    rpc_portal: Option<SocketAddr>,

    vpn_portal_config: Option<VpnPortalConfig>,

    routes: Option<Vec<cidr::Ipv4Cidr>>,

    socks5_proxy: Option<url::Url>,

    flags: Option<serde_json::Map<String, serde_json::Value>>,

    #[serde(skip)]
    flags_struct: Option<Flags>,
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
        let mut config = toml::de::from_str::<Config>(config_str).with_context(|| {
            format!(
                "failed to parse config file: {}\n{}",
                config_str, config_str
            )
        })?;

        config.flags_struct = Some(Self::gen_flags(config.flags.clone().unwrap_or_default()));

        Ok(TomlConfigLoader {
            config: Arc::new(Mutex::new(config)),
        })
    }

    pub fn new(config_path: &PathBuf) -> Result<Self, anyhow::Error> {
        let config_str = std::fs::read_to_string(config_path)
            .with_context(|| format!("failed to read config file: {:?}", config_path))?;
        let ret = Self::new_from_str(&config_str)?;
        let old_ns = ret.get_network_identity();
        ret.set_network_identity(NetworkIdentity::new(
            old_ns.network_name,
            old_ns.network_secret.unwrap_or_default(),
        ));

        Ok(ret)
    }

    fn gen_flags(mut flags_hashmap: serde_json::Map<String, serde_json::Value>) -> Flags {
        let default_flags_json = serde_json::to_string(&Flags::default()).unwrap();
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

    fn get_dhcp(&self) -> bool {
        self.config.lock().unwrap().dhcp.unwrap_or_default()
    }

    fn set_dhcp(&self, dhcp: bool) {
        self.config.lock().unwrap().dhcp = Some(dhcp);
    }

    fn add_proxy_cidr(&self, cidr: cidr::IpCidr) {
        let mut locked_config = self.config.lock().unwrap();
        if locked_config.proxy_network.is_none() {
            locked_config.proxy_network = Some(vec![]);
        }
        let cidr_str = cidr.to_string();
        // insert if no duplicate
        if !locked_config
            .proxy_network
            .as_ref()
            .unwrap()
            .iter()
            .any(|c| c.cidr == cidr_str)
        {
            locked_config
                .proxy_network
                .as_mut()
                .unwrap()
                .push(NetworkConfig {
                    cidr: cidr_str,
                    allow: None,
                });
        }
    }

    fn remove_proxy_cidr(&self, cidr: cidr::IpCidr) {
        let mut locked_config = self.config.lock().unwrap();
        if let Some(proxy_cidrs) = &mut locked_config.proxy_network {
            let cidr_str = cidr.to_string();
            proxy_cidrs.retain(|c| c.cidr != cidr_str);
        }
    }

    fn get_proxy_cidrs(&self) -> Vec<cidr::IpCidr> {
        self.config
            .lock()
            .unwrap()
            .proxy_network
            .as_ref()
            .map(|v| {
                v.iter()
                    .map(|c| c.cidr.parse().unwrap())
                    .collect::<Vec<cidr::IpCidr>>()
            })
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

    fn get_file_logger_config(&self) -> FileLoggerConfig {
        self.config
            .lock()
            .unwrap()
            .file_logger
            .clone()
            .unwrap_or_default()
    }

    fn set_file_logger_config(&self, config: FileLoggerConfig) {
        self.config.lock().unwrap().file_logger = Some(config);
    }

    fn get_console_logger_config(&self) -> ConsoleLoggerConfig {
        self.config
            .lock()
            .unwrap()
            .console_logger
            .clone()
            .unwrap_or_default()
    }

    fn set_console_logger_config(&self, config: ConsoleLoggerConfig) {
        self.config.lock().unwrap().console_logger = Some(config);
    }

    fn get_peers(&self) -> Vec<PeerConfig> {
        self.config.lock().unwrap().peer.clone().unwrap_or_default()
    }

    fn set_peers(&self, peers: Vec<PeerConfig>) {
        self.config.lock().unwrap().peer = Some(peers);
    }

    fn get_listeners(&self) -> Vec<url::Url> {
        self.config
            .lock()
            .unwrap()
            .listeners
            .clone()
            .unwrap_or_default()
    }

    fn set_listeners(&self, listeners: Vec<url::Url>) {
        self.config.lock().unwrap().listeners = Some(listeners);
    }

    fn get_rpc_portal(&self) -> Option<SocketAddr> {
        self.config.lock().unwrap().rpc_portal
    }

    fn set_rpc_portal(&self, addr: SocketAddr) {
        self.config.lock().unwrap().rpc_portal = Some(addr);
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

    fn get_exit_nodes(&self) -> Vec<Ipv4Addr> {
        self.config
            .lock()
            .unwrap()
            .exit_nodes
            .clone()
            .unwrap_or_default()
    }

    fn set_exit_nodes(&self, nodes: Vec<Ipv4Addr>) {
        self.config.lock().unwrap().exit_nodes = Some(nodes);
    }

    fn dump(&self) -> String {
        toml::to_string_pretty(&*self.config.lock().unwrap()).unwrap()
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

        println!("{}", ret.dump());
    }
}
