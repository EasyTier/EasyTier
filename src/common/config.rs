use std::{
    net::SocketAddr,
    sync::{Arc, Mutex},
};

use anyhow::Context;
use serde::{Deserialize, Serialize};

#[auto_impl::auto_impl(Box, &)]
pub trait ConfigLoader: Send + Sync {
    fn get_id(&self) -> uuid::Uuid;

    fn get_inst_name(&self) -> String;
    fn set_inst_name(&self, name: String);

    fn get_netns(&self) -> Option<String>;
    fn set_netns(&self, ns: Option<String>);

    fn get_ipv4(&self) -> Option<std::net::Ipv4Addr>;
    fn set_ipv4(&self, addr: std::net::Ipv4Addr);

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

    fn dump(&self) -> String;
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq)]
pub struct NetworkIdentity {
    pub network_name: String,
    pub network_secret: String,
}

impl NetworkIdentity {
    pub fn new(network_name: String, network_secret: String) -> Self {
        NetworkIdentity {
            network_name,
            network_secret,
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
struct Config {
    netns: Option<String>,
    instance_name: Option<String>,
    instance_id: Option<String>,
    ipv4: Option<String>,
    network_identity: Option<NetworkIdentity>,
    listeners: Option<Vec<url::Url>>,

    peer: Option<Vec<PeerConfig>>,
    proxy_network: Option<Vec<NetworkConfig>>,

    file_logger: Option<FileLoggerConfig>,
    console_logger: Option<ConsoleLoggerConfig>,

    rpc_portal: Option<SocketAddr>,
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
        let config = toml::de::from_str::<Config>(config_str).with_context(|| {
            format!(
                "failed to parse config file: {}\n{}",
                config_str, config_str
            )
        })?;
        Ok(TomlConfigLoader {
            config: Arc::new(Mutex::new(config)),
        })
    }

    pub fn new(config_path: &str) -> Result<Self, anyhow::Error> {
        let config_str = std::fs::read_to_string(config_path)
            .with_context(|| format!("failed to read config file: {}", config_path))?;
        Self::new_from_str(&config_str)
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

    fn get_netns(&self) -> Option<String> {
        self.config.lock().unwrap().netns.clone()
    }

    fn set_netns(&self, ns: Option<String>) {
        self.config.lock().unwrap().netns = ns;
    }

    fn get_ipv4(&self) -> Option<std::net::Ipv4Addr> {
        let locked_config = self.config.lock().unwrap();
        locked_config
            .ipv4
            .as_ref()
            .map(|s| s.parse().ok())
            .flatten()
    }

    fn set_ipv4(&self, addr: std::net::Ipv4Addr) {
        self.config.lock().unwrap().ipv4 = Some(addr.to_string());
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
            locked_config.instance_id = Some(id.to_string());
            id
        } else {
            uuid::Uuid::parse_str(locked_config.instance_id.as_ref().unwrap())
                .with_context(|| {
                    format!(
                        "failed to parse instance id as uuid: {}, you can use this id: {}",
                        locked_config.instance_id.as_ref().unwrap(),
                        uuid::Uuid::new_v4()
                    )
                })
                .unwrap()
        }
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

    fn dump(&self) -> String {
        toml::to_string_pretty(&*self.config.lock().unwrap()).unwrap()
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
        assert_eq!("10.144.144.10", ret.get_ipv4().unwrap().to_string());

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
