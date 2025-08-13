#![allow(dead_code)]

#[macro_use]
extern crate rust_i18n;

use std::{
    net::{IpAddr, SocketAddr},
    path::PathBuf,
    process::ExitCode,
    sync::Arc,
};

use anyhow::Context;
use cidr::IpCidr;
use clap::{CommandFactory, Parser};

use clap_complete::Shell;
use easytier::{
    common::{
        config::{
            get_avaliable_encrypt_methods, ConfigLoader, ConsoleLoggerConfig, FileLoggerConfig,
            LoggingConfigLoader, NetworkIdentity, PeerConfig, PortForwardConfig, TomlConfigLoader,
            VpnPortalConfig,
        },
        constants::EASYTIER_VERSION,
        global_ctx::GlobalCtx,
        set_default_machine_id,
        stun::MockStunInfoCollector,
    },
    connector::create_connector_by_url,
    instance_manager::NetworkInstanceManager,
    launcher::{add_proxy_network_to_config, ConfigSource},
    proto::common::{CompressionAlgoPb, NatType},
    tunnel::{IpVersion, PROTO_PORT_OFFSET},
    utils::{init_logger, setup_panic_handler},
    web_client,
};

#[cfg(target_os = "windows")]
windows_service::define_windows_service!(ffi_service_main, win_service_main);

#[cfg(all(feature = "mimalloc", not(feature = "jemalloc")))]
use mimalloc::MiMalloc;

#[cfg(all(feature = "mimalloc", not(feature = "jemalloc")))]
#[global_allocator]
static GLOBAL_MIMALLOC: MiMalloc = MiMalloc;

#[cfg(feature = "jemalloc-prof")]
use jemalloc_ctl::{epoch, stats, Access as _, AsName as _};

#[cfg(feature = "jemalloc")]
#[global_allocator]
static ALLOC: jemallocator::Jemalloc = jemallocator::Jemalloc;

#[cfg(feature = "jemalloc-prof")]
#[allow(non_upper_case_globals)]
#[export_name = "malloc_conf"]
pub static malloc_conf: &[u8] = b"prof:true,prof_active:true,lg_prof_sample:19\0";

fn set_prof_active(_active: bool) {
    #[cfg(feature = "jemalloc-prof")]
    {
        const PROF_ACTIVE: &[u8] = b"prof.active\0";
        let name = PROF_ACTIVE.name();
        name.write(_active).expect("Should succeed to set prof");
    }
}

fn dump_profile(_cur_allocated: usize) {
    #[cfg(feature = "jemalloc-prof")]
    {
        const PROF_DUMP: &[u8] = b"prof.dump\0";
        static mut PROF_DUMP_FILE_NAME: [u8; 128] = [0; 128];
        let file_name_str = format!(
            "profile-{}-{}.out",
            _cur_allocated,
            chrono::Local::now().format("%Y-%m-%d-%H-%M-%S")
        );
        // copy file name to PROF_DUMP
        let file_name = file_name_str.as_bytes();
        let len = file_name.len();
        if len > 127 {
            panic!("file name too long");
        }
        unsafe {
            PROF_DUMP_FILE_NAME[..len].copy_from_slice(file_name);
            // set the last byte to 0
            PROF_DUMP_FILE_NAME[len] = 0;

            let name = PROF_DUMP.name();
            name.write(&PROF_DUMP_FILE_NAME[..len + 1])
                .expect("Should succeed to dump profile");
            println!("dump profile to: {}", file_name_str);
        }
    }
}

#[derive(Parser, Debug)]
#[command(name = "easytier-core", author, version = EASYTIER_VERSION , about, long_about = None)]
struct Cli {
    #[arg(
        short = 'w',
        long,
        env = "ET_CONFIG_SERVER",
        help = t!("core_clap.config_server").to_string()
    )]
    config_server: Option<String>,

    #[arg(
        long,
        env = "ET_MACHINE_ID",
        help = t!("core_clap.machine_id").to_string()
    )]
    machine_id: Option<String>,

    #[arg(
        short,
        long,
        env = "ET_CONFIG_FILE",
        value_delimiter = ',',
        help = t!("core_clap.config_file").to_string(),
        num_args = 1..,
    )]
    config_file: Option<Vec<PathBuf>>,

    #[command(flatten)]
    network_options: NetworkOptions,

    #[command(flatten)]
    logging_options: LoggingOptions,

    #[clap(long, help = t!("core_clap.generate_completions").to_string())]
    gen_autocomplete: Option<Shell>,
}

#[derive(Parser, Debug)]
struct NetworkOptions {
    #[arg(
        long,
        env = "ET_NETWORK_NAME",
        help = t!("core_clap.network_name").to_string(),
    )]
    network_name: Option<String>,

    #[arg(
        long,
        env = "ET_NETWORK_SECRET",
        help = t!("core_clap.network_secret").to_string(),
    )]
    network_secret: Option<String>,

    #[arg(
        short,
        long,
        env = "ET_IPV4",
        help = t!("core_clap.ipv4").to_string()
    )]
    ipv4: Option<String>,

    #[arg(
        long,
        env = "ET_IPV6",
        help = t!("core_clap.ipv6").to_string()
    )]
    ipv6: Option<String>,

    #[arg(
        short,
        long,
        env = "ET_DHCP",
        help = t!("core_clap.dhcp").to_string(),
        num_args = 0..=1,
        default_missing_value = "true"
    )]
    dhcp: Option<bool>,

    #[arg(
        short,
        long,
        env = "ET_PEERS",
        value_delimiter = ',',
        help = t!("core_clap.peers").to_string(),
        num_args = 0..
    )]
    peers: Vec<String>,

    #[arg(
        short,
        long,
        env = "ET_EXTERNAL_NODE",
        help = t!("core_clap.external_node").to_string()
    )]
    external_node: Option<String>,

    #[arg(
        short = 'n',
        long,
        env = "ET_PROXY_NETWORKS",
        value_delimiter = ',',
        help = t!("core_clap.proxy_networks").to_string()
    )]
    proxy_networks: Vec<String>,

    #[arg(
        short,
        long,
        env = "ET_RPC_PORTAL",
        help = t!("core_clap.rpc_portal").to_string(),
    )]
    rpc_portal: Option<String>,

    #[arg(
        long,
        env = "ET_RPC_PORTAL_WHITELIST",
        value_delimiter = ',',
        help = t!("core_clap.rpc_portal_whitelist").to_string(),
    )]
    rpc_portal_whitelist: Option<Vec<IpCidr>>,

    #[arg(
        short,
        long,
        env = "ET_LISTENERS",
        value_delimiter = ',',
        help = t!("core_clap.listeners").to_string(),
        num_args = 0..
    )]
    listeners: Vec<String>,

    #[arg(
        long,
        env = "ET_MAPPED_LISTENERS",
        value_delimiter = ',',
        help = t!("core_clap.mapped_listeners").to_string(),
        num_args = 0..
    )]
    mapped_listeners: Vec<String>,

    #[arg(
        long,
        env = "ET_NO_LISTENER",
        help = t!("core_clap.no_listener").to_string(),
        default_value = "false",
    )]
    no_listener: bool,

    #[arg(
        long,
        env = "ET_HOSTNAME",
        help = t!("core_clap.hostname").to_string()
    )]
    hostname: Option<String>,

    #[arg(
        short = 'm',
        long,
        env = "ET_INSTANCE_NAME",
        help = t!("core_clap.instance_name").to_string(),
    )]
    instance_name: Option<String>,

    #[arg(
        long,
        env = "ET_VPN_PORTAL",
        help = t!("core_clap.vpn_portal").to_string()
    )]
    vpn_portal: Option<String>,

    #[arg(
        long,
        env = "ET_DEFAULT_PROTOCOL",
        help = t!("core_clap.default_protocol").to_string()
    )]
    default_protocol: Option<String>,

    #[arg(
        short = 'u',
        long,
        env = "ET_DISABLE_ENCRYPTION",
        help = t!("core_clap.disable_encryption").to_string(),
        num_args = 0..=1,
        default_missing_value = "true"
    )]
    disable_encryption: Option<bool>,

    #[arg(
        long,
        env = "ET_ENCRYPTION_ALGORITHM",
        help = t!("core_clap.encryption_algorithm").to_string(),
        default_value = "aes-gcm",
        value_parser = get_avaliable_encrypt_methods()
    )]
    encryption_algorithm: Option<String>,

    #[arg(
        long,
        env = "ET_MULTI_THREAD",
        help = t!("core_clap.multi_thread").to_string(),
        num_args = 0..=1,
        default_missing_value = "true"
    )]
    multi_thread: Option<bool>,

    #[arg(
        long,
        env = "ET_MULTI_THREAD_COUNT",
        help = t!("core_clap.multi_thread_count").to_string(),
    )]
    multi_thread_count: Option<u32>,

    #[arg(
        long,
        env = "ET_DISABLE_IPV6",
        help = t!("core_clap.disable_ipv6").to_string(),
        num_args = 0..=1,
        default_missing_value = "true"
    )]
    disable_ipv6: Option<bool>,

    #[arg(
        long,
        env = "ET_DEV_NAME",
        help = t!("core_clap.dev_name").to_string()
    )]
    dev_name: Option<String>,

    #[arg(
        long,
        env = "ET_MTU",
        help = t!("core_clap.mtu").to_string()
    )]
    mtu: Option<u16>,

    #[arg(
        long,
        env = "ET_LATENCY_FIRST",
        help = t!("core_clap.latency_first").to_string(),
        num_args = 0..=1,
        default_missing_value = "true"
    )]
    latency_first: Option<bool>,

    #[arg(
        long,
        env = "ET_EXIT_NODES",
        value_delimiter = ',',
        help = t!("core_clap.exit_nodes").to_string(),
        num_args = 0..
    )]
    exit_nodes: Vec<IpAddr>,

    #[arg(
        long,
        env = "ET_ENABLE_EXIT_NODE",
        help = t!("core_clap.enable_exit_node").to_string(),
        num_args = 0..=1,
        default_missing_value = "true"
    )]
    enable_exit_node: Option<bool>,

    #[arg(
        long,
        env = "ET_PROXY_FORWARD_BY_SYSTEM",
        help = t!("core_clap.proxy_forward_by_system").to_string(),
        num_args = 0..=1,
        default_missing_value = "true"
    )]
    proxy_forward_by_system: Option<bool>,

    #[arg(
        long,
        env = "ET_NO_TUN",
        help = t!("core_clap.no_tun").to_string(),
        num_args = 0..=1,
        default_missing_value = "true"
    )]
    no_tun: Option<bool>,

    #[arg(
        long,
        env = "ET_USE_SMOLTCP",
        help = t!("core_clap.use_smoltcp").to_string(),
        num_args = 0..=1,
        default_missing_value = "true"
    )]
    use_smoltcp: Option<bool>,

    #[arg(
        long,
        env = "ET_MANUAL_ROUTES",
        value_delimiter = ',',
        help = t!("core_clap.manual_routes").to_string(),
        num_args = 0..
    )]
    manual_routes: Option<Vec<String>>,

    // if not in relay_network_whitelist:
    // for foreign virtual network, will refuse the incoming connection
    // for local virtual network, will refuse relaying tun packet
    #[arg(
        long,
        env = "ET_RELAY_NETWORK_WHITELIST",
        value_delimiter = ',',
        help = t!("core_clap.relay_network_whitelist").to_string(),
        num_args = 0..
    )]
    relay_network_whitelist: Option<Vec<String>>,

    #[arg(
        long,
        env = "ET_DISABLE_P2P",
        help = t!("core_clap.disable_p2p").to_string(),
        num_args = 0..=1,
        default_missing_value = "true"
    )]
    disable_p2p: Option<bool>,

    #[arg(
        long,
        env = "ET_DISABLE_UDP_HOLE_PUNCHING",
        help = t!("core_clap.disable_udp_hole_punching").to_string(),
        num_args = 0..=1,
        default_missing_value = "true"
    )]
    disable_udp_hole_punching: Option<bool>,

    #[arg(
        long,
        env = "ET_RELAY_ALL_PEER_RPC",
        help = t!("core_clap.relay_all_peer_rpc").to_string(),
        num_args = 0..=1,
        default_missing_value = "true"
    )]
    relay_all_peer_rpc: Option<bool>,

    #[cfg(feature = "socks5")]
    #[arg(
        long,
        env = "ET_SOCKS5",
        help = t!("core_clap.socks5").to_string()
    )]
    socks5: Option<u16>,

    #[arg(
        long,
        env = "ET_COMPRESSION",
        help = t!("core_clap.compression").to_string(),
    )]
    compression: Option<String>,

    #[arg(
        long,
        env = "ET_BIND_DEVICE",
        help = t!("core_clap.bind_device").to_string()
    )]
    bind_device: Option<bool>,

    #[arg(
        long,
        env = "ET_ENABLE_KCP_PROXY",
        help = t!("core_clap.enable_kcp_proxy").to_string(),
        num_args = 0..=1,
        default_missing_value = "true"
    )]
    enable_kcp_proxy: Option<bool>,

    #[arg(
        long,
        env = "ET_DISABLE_KCP_INPUT",
        help = t!("core_clap.disable_kcp_input").to_string(),
        num_args = 0..=1,
        default_missing_value = "true"
    )]
    disable_kcp_input: Option<bool>,

    #[arg(
        long,
        env = "ET_ENABLE_QUIC_PROXY",
        help = t!("core_clap.enable_quic_proxy").to_string(),
        num_args = 0..=1,
        default_missing_value = "true"
    )]
    enable_quic_proxy: Option<bool>,

    #[arg(
        long,
        env = "ET_DISABLE_QUIC_INPUT",
        help = t!("core_clap.disable_quic_input").to_string(),
        num_args = 0..=1,
        default_missing_value = "true"
    )]
    disable_quic_input: Option<bool>,

    #[arg(
        long,
        env = "ET_PORT_FORWARD",
        value_delimiter = ',',
        help = t!("core_clap.port_forward").to_string(),
        num_args = 1..
    )]
    port_forward: Vec<url::Url>,

    #[arg(
        long,
        env = "ET_ACCEPT_DNS",
        help = t!("core_clap.accept_dns").to_string(),
    )]
    accept_dns: Option<bool>,

    #[arg(
        long,
        env = "ET_PRIVATE_MODE",
        help = t!("core_clap.private_mode").to_string(),
    )]
    private_mode: Option<bool>,

    #[arg(
        long,
        env = "ET_FOREIGN_RELAY_BPS_LIMIT",
        help = t!("core_clap.foreign_relay_bps_limit").to_string(),
    )]
    foreign_relay_bps_limit: Option<u64>,

    #[arg(
        long,
        value_delimiter = ',',
        help = t!("core_clap.tcp_whitelist").to_string(),
        num_args = 0..
    )]
    tcp_whitelist: Vec<String>,

    #[arg(
        long,
        value_delimiter = ',',
        help = t!("core_clap.udp_whitelist").to_string(),
        num_args = 0..
    )]
    udp_whitelist: Vec<String>,

    #[arg(
        long,
        env = "ET_DISABLE_RELAY_KCP",
        help = t!("core_clap.disable_relay_kcp").to_string(),
        num_args = 0..=1,
        default_missing_value = "true"
    )]
    disable_relay_kcp: Option<bool>,

    #[arg(
        long,
        env = "ET_ENABLE_RELAY_FOREIGN_NETWORK_KCP",
        help = t!("core_clap.enable_relay_foreign_network_kcp").to_string(),
        num_args = 0..=1,
        default_missing_value = "true"
    )]
    enable_relay_foreign_network_kcp: Option<bool>,

    #[arg(
        long,
        env = "ET_STUN_SERVERS",
        value_delimiter = ',',
        help = t!("core_clap.stun_servers").to_string(),
        num_args = 0..
    )]
    stun_servers: Option<Vec<String>>,
}

#[derive(Parser, Debug)]
struct LoggingOptions {
    #[arg(
        long,
        env = "ET_CONSOLE_LOG_LEVEL",
        help = t!("core_clap.console_log_level").to_string()
    )]
    console_log_level: Option<String>,

    #[arg(
        long,
        env = "ET_FILE_LOG_LEVEL",
        help = t!("core_clap.file_log_level").to_string()
    )]
    file_log_level: Option<String>,

    #[arg(
        long,
        env = "ET_FILE_LOG_DIR",
        help = t!("core_clap.file_log_dir").to_string()
    )]
    file_log_dir: Option<String>,
}

rust_i18n::i18n!("locales", fallback = "en");

impl Cli {
    fn parse_listeners(no_listener: bool, listeners: Vec<String>) -> anyhow::Result<Vec<String>> {
        if no_listener || listeners.is_empty() {
            return Ok(vec![]);
        }

        let origin_listners = listeners;
        let mut listeners: Vec<String> = Vec::new();
        if origin_listners.len() == 1 {
            if let Ok(port) = origin_listners[0].parse::<u16>() {
                for (proto, offset) in PROTO_PORT_OFFSET {
                    listeners.push(format!("{}://0.0.0.0:{}", proto, port + *offset));
                }
                return Ok(listeners);
            }
        }

        for l in &origin_listners {
            let proto_port: Vec<&str> = l.split(':').collect();
            if proto_port.len() > 2 {
                if let Ok(url) = l.parse::<url::Url>() {
                    listeners.push(url.to_string());
                } else {
                    panic!("failed to parse listener: {}", l);
                }
            } else {
                let Some((proto, offset)) = PROTO_PORT_OFFSET
                    .iter()
                    .find(|(proto, _)| *proto == proto_port[0])
                else {
                    return Err(anyhow::anyhow!("unknown protocol: {}", proto_port[0]));
                };

                let port = if proto_port.len() == 2 {
                    proto_port[1].parse::<u16>().unwrap()
                } else {
                    11010 + offset
                };

                listeners.push(format!("{}://0.0.0.0:{}", proto, port));
            }
        }

        Ok(listeners)
    }

    fn parse_rpc_portal(rpc_portal: String) -> anyhow::Result<SocketAddr> {
        if let Ok(port) = rpc_portal.parse::<u16>() {
            return Ok(format!("0.0.0.0:{}", port).parse().unwrap());
        }

        Ok(rpc_portal.parse()?)
    }
}

impl NetworkOptions {
    fn can_merge(&self, cfg: &TomlConfigLoader, config_file_count: usize) -> bool {
        if config_file_count == 1 {
            return true;
        }
        let Some(network_name) = &self.network_name else {
            return false;
        };
        if cfg.get_network_identity().network_name == *network_name {
            return true;
        }
        false
    }

    fn merge_into(&self, cfg: &mut TomlConfigLoader) -> anyhow::Result<()> {
        if self.hostname.is_some() {
            cfg.set_hostname(self.hostname.clone());
        }

        let old_ns = cfg.get_network_identity();
        let network_name = self.network_name.clone().unwrap_or(old_ns.network_name);
        let network_secret = self
            .network_secret
            .clone()
            .unwrap_or(old_ns.network_secret.unwrap_or_default());
        cfg.set_network_identity(NetworkIdentity::new(network_name, network_secret));

        if let Some(dhcp) = self.dhcp {
            cfg.set_dhcp(dhcp);
        }

        if let Some(ipv4) = &self.ipv4 {
            cfg.set_ipv4(Some(ipv4.parse().with_context(|| {
                format!("failed to parse ipv4 address: {}", ipv4)
            })?))
        }

        if let Some(ipv6) = &self.ipv6 {
            cfg.set_ipv6(Some(ipv6.parse().with_context(|| {
                format!("failed to parse ipv6 address: {}", ipv6)
            })?))
        }

        if !self.peers.is_empty() {
            let mut peers = cfg.get_peers();
            peers.reserve(peers.len() + self.peers.len());
            for p in &self.peers {
                peers.push(PeerConfig {
                    uri: p
                        .parse()
                        .with_context(|| format!("failed to parse peer uri: {}", p))?,
                });
            }
            cfg.set_peers(peers);
        }

        if self.no_listener || !self.listeners.is_empty() {
            cfg.set_listeners(
                Cli::parse_listeners(self.no_listener, self.listeners.clone())?
                    .into_iter()
                    .map(|s| s.parse().unwrap())
                    .collect(),
            );
        } else if cfg.get_listeners().is_none() {
            cfg.set_listeners(
                Cli::parse_listeners(false, vec!["11010".to_string()])?
                    .into_iter()
                    .map(|s| s.parse().unwrap())
                    .collect(),
            );
        }

        if !self.mapped_listeners.is_empty() {
            let mut errs = Vec::new();
            cfg.set_mapped_listeners(Some(
                self.mapped_listeners
                    .iter()
                    .map(|s| {
                        s.parse()
                            .with_context(|| format!("mapped listener is not a valid url: {}", s))
                            .unwrap()
                    })
                    .map(|s: url::Url| {
                        if s.port().is_none() {
                            errs.push(anyhow::anyhow!("mapped listener port is missing: {}", s));
                        }
                        s
                    })
                    .collect::<Vec<_>>(),
            ));
            if !errs.is_empty() {
                return Err(anyhow::anyhow!(
                    "{}",
                    errs.iter()
                        .map(|x| format!("{}", x))
                        .collect::<Vec<_>>()
                        .join("\n")
                ));
            }
        }

        for n in self.proxy_networks.iter() {
            add_proxy_network_to_config(n, cfg)?;
        }

        let rpc_portal = if let Some(r) = &self.rpc_portal {
            Cli::parse_rpc_portal(r.clone())
                .with_context(|| format!("failed to parse rpc portal: {}", r))?
        } else if let Some(r) = cfg.get_rpc_portal() {
            r
        } else {
            Cli::parse_rpc_portal("0".into())?
        };
        cfg.set_rpc_portal(rpc_portal);

        if let Some(rpc_portal_whitelist) = &self.rpc_portal_whitelist {
            let mut whitelist = cfg.get_rpc_portal_whitelist().unwrap_or_default();
            for cidr in rpc_portal_whitelist {
                whitelist.push(*cidr);
            }
            cfg.set_rpc_portal_whitelist(Some(whitelist));
        }

        if let Some(external_nodes) = self.external_node.as_ref() {
            let mut old_peers = cfg.get_peers();
            old_peers.push(PeerConfig {
                uri: external_nodes.parse().with_context(|| {
                    format!("failed to parse external node uri: {}", external_nodes)
                })?,
            });
            cfg.set_peers(old_peers);
        }

        if let Some(inst_name) = &self.instance_name {
            cfg.set_inst_name(inst_name.clone());
        }

        if let Some(vpn_portal) = self.vpn_portal.as_ref() {
            let url: url::Url = vpn_portal
                .parse()
                .with_context(|| format!("failed to parse vpn portal url: {}", vpn_portal))?;
            let host = url
                .host_str()
                .ok_or_else(|| anyhow::anyhow!("vpn portal url missing host"))?;
            let port = url
                .port()
                .ok_or_else(|| anyhow::anyhow!("vpn portal url missing port"))?;
            let client_cidr = url.path()[1..].parse().with_context(|| {
                format!("failed to parse vpn portal client cidr: {}", url.path())
            })?;
            let wireguard_listen: SocketAddr = format!("{}:{}", host, port).parse().unwrap();
            cfg.set_vpn_portal_config(VpnPortalConfig {
                wireguard_listen,
                client_cidr,
            });
        }

        if let Some(manual_routes) = self.manual_routes.as_ref() {
            let mut routes = Vec::<cidr::Ipv4Cidr>::with_capacity(manual_routes.len());
            for r in manual_routes {
                routes.push(
                    r.parse()
                        .with_context(|| format!("failed to parse route: {}", r))?,
                );
            }
            cfg.set_routes(Some(routes));
        }

        #[cfg(feature = "socks5")]
        if let Some(socks5_proxy) = self.socks5 {
            cfg.set_socks5_portal(Some(
                format!("socks5://0.0.0.0:{}", socks5_proxy)
                    .parse()
                    .unwrap(),
            ));
        }

        #[cfg(feature = "socks5")]
        for port_forward in self.port_forward.iter() {
            let example_str = ", example: udp://0.0.0.0:12345/10.126.126.1:12345";

            let bind_addr = format!(
                "{}:{}",
                port_forward.host_str().expect("local bind host is missing"),
                port_forward.port().expect("local bind port is missing")
            )
            .parse()
            .unwrap_or_else(|_| panic!("failed to parse local bind addr {}", example_str));

            let dst_addr = port_forward
                .path_segments()
                .unwrap_or_else(|| panic!("remote destination addr is missing {}", example_str))
                .next()
                .unwrap_or_else(|| panic!("remote destination addr is missing {}", example_str))
                .to_string()
                .parse()
                .unwrap_or_else(|_| {
                    panic!("failed to parse remote destination addr {}", example_str)
                });

            let port_forward_item = PortForwardConfig {
                bind_addr,
                dst_addr,
                proto: port_forward.scheme().to_string(),
            };

            let mut old = cfg.get_port_forwards();
            old.push(port_forward_item);
            cfg.set_port_forwards(old);
        }

        let mut f = cfg.get_flags();
        if let Some(default_protocol) = &self.default_protocol {
            f.default_protocol = default_protocol.clone()
        };
        if let Some(v) = self.disable_encryption {
            f.enable_encryption = !v;
        }
        if let Some(algorithm) = &self.encryption_algorithm {
            f.encryption_algorithm = algorithm.clone();
        }
        if let Some(v) = self.disable_ipv6 {
            f.enable_ipv6 = !v;
        }
        f.latency_first = self.latency_first.unwrap_or(f.latency_first);
        if let Some(dev_name) = &self.dev_name {
            f.dev_name = dev_name.clone()
        }
        if let Some(mtu) = self.mtu {
            f.mtu = mtu as u32;
        }
        f.enable_exit_node = self.enable_exit_node.unwrap_or(f.enable_exit_node);
        f.proxy_forward_by_system = self
            .proxy_forward_by_system
            .unwrap_or(f.proxy_forward_by_system);
        f.no_tun = self.no_tun.unwrap_or(f.no_tun) || cfg!(not(feature = "tun"));
        f.use_smoltcp = self.use_smoltcp.unwrap_or(f.use_smoltcp);
        if let Some(wl) = self.relay_network_whitelist.as_ref() {
            f.relay_network_whitelist = wl.join(" ");
        }
        f.disable_p2p = self.disable_p2p.unwrap_or(f.disable_p2p);
        f.disable_udp_hole_punching = self
            .disable_udp_hole_punching
            .unwrap_or(f.disable_udp_hole_punching);
        f.relay_all_peer_rpc = self.relay_all_peer_rpc.unwrap_or(f.relay_all_peer_rpc);
        f.multi_thread = self.multi_thread.unwrap_or(f.multi_thread);
        if let Some(compression) = &self.compression {
            f.data_compress_algo = match compression.as_str() {
                "none" => CompressionAlgoPb::None,
                "zstd" => CompressionAlgoPb::Zstd,
                _ => panic!(
                    "unknown compression algorithm: {}, supported: none, zstd",
                    compression
                ),
            }
            .into();
        }
        f.bind_device = self.bind_device.unwrap_or(f.bind_device);
        f.enable_kcp_proxy = self.enable_kcp_proxy.unwrap_or(f.enable_kcp_proxy);
        f.disable_kcp_input = self.disable_kcp_input.unwrap_or(f.disable_kcp_input);
        f.enable_quic_proxy = self.enable_quic_proxy.unwrap_or(f.enable_quic_proxy);
        f.disable_quic_input = self.disable_quic_input.unwrap_or(f.disable_quic_input);
        f.accept_dns = self.accept_dns.unwrap_or(f.accept_dns);
        f.private_mode = self.private_mode.unwrap_or(f.private_mode);
        f.foreign_relay_bps_limit = self
            .foreign_relay_bps_limit
            .unwrap_or(f.foreign_relay_bps_limit);
        f.multi_thread_count = self.multi_thread_count.unwrap_or(f.multi_thread_count);
        f.disable_relay_kcp = self.disable_relay_kcp.unwrap_or(f.disable_relay_kcp);
        f.enable_relay_foreign_network_kcp = self
            .enable_relay_foreign_network_kcp
            .unwrap_or(f.enable_relay_foreign_network_kcp);
        cfg.set_flags(f);

        if !self.exit_nodes.is_empty() {
            cfg.set_exit_nodes(self.exit_nodes.clone());
        }

        let mut old_tcp_whitelist = cfg.get_tcp_whitelist();
        old_tcp_whitelist.extend(self.tcp_whitelist.clone());
        cfg.set_tcp_whitelist(old_tcp_whitelist);

        let mut old_udp_whitelist = cfg.get_udp_whitelist();
        old_udp_whitelist.extend(self.udp_whitelist.clone());
        cfg.set_udp_whitelist(old_udp_whitelist);

        if let Some(stun_servers) = &self.stun_servers {
            cfg.set_stun_servers(stun_servers.clone());
        }

        Ok(())
    }
}

impl LoggingConfigLoader for &LoggingOptions {
    fn get_console_logger_config(&self) -> ConsoleLoggerConfig {
        ConsoleLoggerConfig {
            level: self.console_log_level.clone(),
        }
    }

    fn get_file_logger_config(&self) -> FileLoggerConfig {
        FileLoggerConfig {
            level: self.file_log_level.clone(),
            dir: self.file_log_dir.clone(),
            file: None,
        }
    }
}

#[cfg(target_os = "windows")]
fn win_service_set_work_dir(service_name: &std::ffi::OsString) -> anyhow::Result<()> {
    use easytier::common::constants::WIN_SERVICE_WORK_DIR_REG_KEY;
    use winreg::enums::*;
    use winreg::RegKey;

    let hklm = RegKey::predef(HKEY_LOCAL_MACHINE);
    let key = hklm.open_subkey_with_flags(WIN_SERVICE_WORK_DIR_REG_KEY, KEY_READ)?;
    let dir_pat_str = key.get_value::<std::ffi::OsString, _>(service_name)?;
    let dir_path = std::fs::canonicalize(dir_pat_str)?;

    std::env::set_current_dir(dir_path)?;

    Ok(())
}

#[cfg(target_os = "windows")]
fn win_service_event_loop(
    stop_notify: std::sync::Arc<tokio::sync::Notify>,
    cli: Cli,
    status_handle: windows_service::service_control_handler::ServiceStatusHandle,
) {
    use std::time::Duration;
    use tokio::runtime::Runtime;
    use windows_service::service::*;

    let normal_status = ServiceStatus {
        service_type: ServiceType::OWN_PROCESS,
        current_state: ServiceState::Running,
        controls_accepted: ServiceControlAccept::STOP,
        exit_code: ServiceExitCode::Win32(0),
        checkpoint: 0,
        wait_hint: Duration::default(),
        process_id: None,
    };
    let error_status = ServiceStatus {
        service_type: ServiceType::OWN_PROCESS,
        current_state: ServiceState::Stopped,
        controls_accepted: ServiceControlAccept::empty(),
        exit_code: ServiceExitCode::ServiceSpecific(1u32),
        checkpoint: 0,
        wait_hint: Duration::default(),
        process_id: None,
    };

    std::thread::spawn(move || {
        let rt = Runtime::new().unwrap();
        rt.block_on(async move {
            tokio::select! {
                res = run_main(cli) => {
                    match res {
                        Ok(_) => {
                            status_handle.set_service_status(normal_status).unwrap();
                            std::process::exit(0);
                        }
                        Err(e) => {
                            status_handle.set_service_status(error_status).unwrap();
                            eprintln!("error: {}", e);
                        }
                    }
                },
                _ = stop_notify.notified() => {
                    _ = status_handle.set_service_status(normal_status);
                    std::process::exit(0);
                }
            }
        });
    });
}

#[cfg(target_os = "windows")]
fn win_service_main(arg: Vec<std::ffi::OsString>) {
    use std::sync::Arc;
    use std::time::Duration;
    use tokio::sync::Notify;
    use windows_service::service::*;
    use windows_service::service_control_handler::*;

    _ = win_service_set_work_dir(&arg[0]);

    let cli = Cli::parse();

    let stop_notify_send = Arc::new(Notify::new());
    let stop_notify_recv = Arc::clone(&stop_notify_send);
    let event_handler = move |control_event| -> ServiceControlHandlerResult {
        match control_event {
            ServiceControl::Interrogate => ServiceControlHandlerResult::NoError,
            ServiceControl::Stop => {
                stop_notify_send.notify_one();
                ServiceControlHandlerResult::NoError
            }
            _ => ServiceControlHandlerResult::NotImplemented,
        }
    };
    let status_handle = register(String::new(), event_handler).expect("register service fail");
    let next_status = ServiceStatus {
        service_type: ServiceType::OWN_PROCESS,
        current_state: ServiceState::Running,
        controls_accepted: ServiceControlAccept::STOP,
        exit_code: ServiceExitCode::Win32(0),
        checkpoint: 0,
        wait_hint: Duration::default(),
        process_id: None,
    };
    status_handle
        .set_service_status(next_status)
        .expect("set service status fail");

    win_service_event_loop(stop_notify_recv, cli, status_handle);
}

async fn run_main(cli: Cli) -> anyhow::Result<()> {
    init_logger(&cli.logging_options, false)?;

    if cli.config_server.is_some() {
        set_default_machine_id(cli.machine_id);
        let config_server_url_s = cli.config_server.clone().unwrap();
        let config_server_url = match url::Url::parse(&config_server_url_s) {
            Ok(u) => u,
            Err(_) => format!(
                "udp://config-server.easytier.cn:22020/{}",
                config_server_url_s
            )
            .parse()
            .unwrap(),
        };

        let mut c_url = config_server_url.clone();
        c_url.set_path("");
        let token = config_server_url
            .path_segments()
            .and_then(|mut x| x.next())
            .map(|x| x.to_string())
            .unwrap_or_default();

        println!(
            "Entering config client mode...\n  server: {}\n  token: {}",
            c_url, token,
        );

        println!("Official config website: https://easytier.cn/web");

        if token.is_empty() {
            panic!("empty token");
        }

        let config = TomlConfigLoader::default();
        let global_ctx = Arc::new(GlobalCtx::new(config));
        global_ctx.replace_stun_info_collector(Box::new(MockStunInfoCollector {
            udp_nat_type: NatType::Unknown,
        }));
        let mut flags = global_ctx.get_flags();
        flags.bind_device = false;
        global_ctx.set_flags(flags);
        let hostname = match cli.network_options.hostname {
            None => gethostname::gethostname().to_string_lossy().to_string(),
            Some(hostname) => hostname.to_string(),
        };
        let _wc = web_client::WebClient::new(
            create_connector_by_url(c_url.as_str(), &global_ctx, IpVersion::Both).await?,
            token.to_string(),
            hostname,
        );
        tokio::signal::ctrl_c().await.unwrap();
        return Ok(());
    }
    let manager = NetworkInstanceManager::new();
    let mut crate_cli_network =
        cli.config_file.is_none() || cli.network_options.network_name.is_some();
    if let Some(config_files) = cli.config_file {
        let config_file_count = config_files.len();
        for config_file in config_files {
            let mut cfg = TomlConfigLoader::new(&config_file)
                .with_context(|| format!("failed to load config file: {:?}", config_file))?;

            if cli.network_options.can_merge(&cfg, config_file_count) {
                cli.network_options.merge_into(&mut cfg).with_context(|| {
                    format!("failed to merge config from cli: {:?}", config_file)
                })?;
                crate_cli_network = false;
            }

            println!(
                "Starting easytier from config file {:?} with config:",
                config_file
            );
            println!("############### TOML ###############\n");
            println!("{}", cfg.dump());
            println!("-----------------------------------");
            manager.run_network_instance(cfg, ConfigSource::File)?;
        }
    }

    if crate_cli_network {
        let mut cfg = TomlConfigLoader::default();
        cli.network_options
            .merge_into(&mut cfg)
            .with_context(|| "failed to create config from cli".to_string())?;
        println!("Starting easytier from cli with config:");
        println!("############### TOML ###############\n");
        println!("{}", cfg.dump());
        println!("-----------------------------------");
        manager.run_network_instance(cfg, ConfigSource::Cli)?;
    }

    tokio::select! {
        _ = manager.wait() => {
            let infos = manager.collect_network_infos()?;
            let errs = infos
                .into_values()
                .filter_map(|info| info.error_msg)
                .collect::<Vec<_>>();
            if !errs.is_empty() {
                return Err(anyhow::anyhow!("some instances stopped with errors"));
            }
        }
        _ = tokio::signal::ctrl_c() => {
            println!("ctrl-c received, exiting...");
        }
    }
    Ok(())
}

fn memory_monitor() {
    #[cfg(feature = "jemalloc-prof")]
    {
        let mut last_peak_size = 0;
        let e = epoch::mib().unwrap();
        let allocated_stats = stats::allocated::mib().unwrap();

        loop {
            e.advance().unwrap();
            let new_heap_size = allocated_stats.read().unwrap();

            println!(
                "heap size: {} bytes, time: {}",
                new_heap_size,
                chrono::Local::now().format("%Y-%m-%d %H:%M:%S")
            );

            // dump every 75MB
            if last_peak_size > 0
                && new_heap_size > last_peak_size
                && new_heap_size - last_peak_size > 75 * 1024 * 1024
            {
                println!(
                    "heap size increased: {} bytes, time: {}",
                    new_heap_size - last_peak_size,
                    chrono::Local::now().format("%Y-%m-%d %H:%M:%S")
                );
                dump_profile(new_heap_size);
                last_peak_size = new_heap_size;
            }

            if last_peak_size == 0 {
                last_peak_size = new_heap_size;
            }

            std::thread::sleep(std::time::Duration::from_secs(5));
        }
    }
}

#[tokio::main(flavor = "current_thread")]
async fn main() -> ExitCode {
    let locale = sys_locale::get_locale().unwrap_or_else(|| String::from("en-US"));
    rust_i18n::set_locale(&locale);
    setup_panic_handler();

    #[cfg(target_os = "windows")]
    match windows_service::service_dispatcher::start(String::new(), ffi_service_main) {
        Ok(_) => std::thread::park(),
        Err(e) => {
            let should_panic = if let windows_service::Error::Winapi(ref io_error) = e {
                io_error.raw_os_error() != Some(0x427) // ERROR_FAILED_SERVICE_CONTROLLER_CONNECT
            } else {
                true
            };

            if should_panic {
                panic!("SCM start an error: {}", e);
            }
        }
    };

    set_prof_active(true);
    let _monitor = std::thread::spawn(memory_monitor);

    let cli = Cli::parse();
    if let Some(shell) = cli.gen_autocomplete {
        let mut cmd = Cli::command();
        easytier::print_completions(shell, &mut cmd, "easytier-core");
        return ExitCode::SUCCESS;
    }
    let mut ret_code = 0;

    if let Err(e) = run_main(cli).await {
        eprintln!("error: {:?}", e);
        ret_code = 1;
    }

    println!("Stopping easytier...");

    dump_profile(0);
    set_prof_active(false);

    ExitCode::from(ret_code)
}
