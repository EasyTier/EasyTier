#![allow(dead_code)]

#[macro_use]
extern crate rust_i18n;

use std::{
    net::{Ipv4Addr, SocketAddr},
    path::PathBuf,
    process::ExitCode,
    sync::Arc,
};

use anyhow::Context;
use cidr::IpCidr;
use clap::Parser;

use easytier::{
    common::{
        config::{
            ConfigLoader, ConsoleLoggerConfig, FileLoggerConfig, NetworkIdentity, PeerConfig,
            PortForwardConfig, TomlConfigLoader, VpnPortalConfig,
        },
        constants::EASYTIER_VERSION,
        global_ctx::{EventBusSubscriber, GlobalCtx, GlobalCtxEvent},
        scoped_task::ScopedTask,
        stun::MockStunInfoCollector,
    },
    connector::create_connector_by_url,
    launcher,
    proto::{
        self,
        common::{CompressionAlgoPb, NatType},
    },
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

#[cfg(feature = "jemalloc")]
use jemalloc_ctl::{epoch, stats, Access as _, AsName as _};

#[cfg(feature = "jemalloc")]
#[global_allocator]
static ALLOC: jemallocator::Jemalloc = jemallocator::Jemalloc;

fn set_prof_active(_active: bool) {
    #[cfg(feature = "jemalloc")]
    {
        const PROF_ACTIVE: &'static [u8] = b"prof.active\0";
        let name = PROF_ACTIVE.name();
        name.write(_active).expect("Should succeed to set prof");
    }
}

fn dump_profile(_cur_allocated: usize) {
    #[cfg(feature = "jemalloc")]
    {
        const PROF_DUMP: &'static [u8] = b"prof.dump\0";
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
        short,
        long,
        env = "ET_CONFIG_FILE",
        help = t!("core_clap.config_file").to_string()
    )]
    config_file: Option<PathBuf>,

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
        env = "ET_MULTI_THREAD",
        help = t!("core_clap.multi_thread").to_string(),
        num_args = 0..=1,
        default_missing_value = "true"
    )]
    multi_thread: Option<bool>,

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
    exit_nodes: Vec<Ipv4Addr>,

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

impl TryFrom<&Cli> for TomlConfigLoader {
    type Error = anyhow::Error;

    fn try_from(cli: &Cli) -> Result<Self, Self::Error> {
        let cfg = if let Some(config_file) = &cli.config_file {
            TomlConfigLoader::new(config_file)
                .with_context(|| format!("failed to load config file: {:?}", cli.config_file))?
        } else {
            TomlConfigLoader::default()
        };

        if cli.hostname.is_some() {
            cfg.set_hostname(cli.hostname.clone());
        }

        let old_ns = cfg.get_network_identity();
        let network_name = cli.network_name.clone().unwrap_or(old_ns.network_name);
        let network_secret = cli
            .network_secret
            .clone()
            .unwrap_or(old_ns.network_secret.unwrap_or_default());
        cfg.set_network_identity(NetworkIdentity::new(network_name, network_secret));

        if let Some(dhcp) = cli.dhcp {
            cfg.set_dhcp(dhcp);
        }

        if let Some(ipv4) = &cli.ipv4 {
            cfg.set_ipv4(Some(ipv4.parse().with_context(|| {
                format!("failed to parse ipv4 address: {}", ipv4)
            })?))
        }

        if !cli.peers.is_empty() {
            let mut peers = cfg.get_peers();
            peers.reserve(peers.len() + cli.peers.len());
            for p in &cli.peers {
                peers.push(PeerConfig {
                    uri: p
                        .parse()
                        .with_context(|| format!("failed to parse peer uri: {}", p))?,
                });
            }
            cfg.set_peers(peers);
        }

        if cli.no_listener || !cli.listeners.is_empty() {
            cfg.set_listeners(
                Cli::parse_listeners(cli.no_listener, cli.listeners.clone())?
                    .into_iter()
                    .map(|s| s.parse().unwrap())
                    .collect(),
            );
        } else if cfg.get_listeners() == None {
            cfg.set_listeners(
                Cli::parse_listeners(false, vec!["11010".to_string()])?
                    .into_iter()
                    .map(|s| s.parse().unwrap())
                    .collect(),
            );
        }

        if !cli.mapped_listeners.is_empty() {
            cfg.set_mapped_listeners(Some(
                cli.mapped_listeners
                    .iter()
                    .map(|s| {
                        s.parse()
                            .with_context(|| format!("mapped listener is not a valid url: {}", s))
                            .unwrap()
                    })
                    .map(|s: url::Url| {
                        if s.port().is_none() {
                            panic!("mapped listener port is missing: {}", s);
                        }
                        s
                    })
                    .collect(),
            ));
        }

        for n in cli.proxy_networks.iter() {
            cfg.add_proxy_cidr(
                n.parse()
                    .with_context(|| format!("failed to parse proxy network: {}", n))?,
            );
        }

        let rpc_portal = if let Some(r) = &cli.rpc_portal {
            Cli::parse_rpc_portal(r.clone())
                .with_context(|| format!("failed to parse rpc portal: {}", r))?
        } else if let Some(r) = cfg.get_rpc_portal() {
            r
        } else {
            Cli::parse_rpc_portal("0".into())?
        };
        cfg.set_rpc_portal(rpc_portal);

        cfg.set_rpc_portal_whitelist(cli.rpc_portal_whitelist.clone());

        if let Some(external_nodes) = cli.external_node.as_ref() {
            let mut old_peers = cfg.get_peers();
            old_peers.push(PeerConfig {
                uri: external_nodes.parse().with_context(|| {
                    format!("failed to parse external node uri: {}", external_nodes)
                })?,
            });
            cfg.set_peers(old_peers);
        }

        if cli.console_log_level.is_some() {
            cfg.set_console_logger_config(ConsoleLoggerConfig {
                level: cli.console_log_level.clone(),
            });
        }

        if let Some(inst_name) = &cli.instance_name {
            cfg.set_inst_name(inst_name.clone());
        }

        if cli.file_log_dir.is_some() || cli.file_log_level.is_some() {
            let inst_name = cfg.get_inst_name();
            let old_fl = cfg.get_file_logger_config();
            let file_log_dir = if cli.file_log_dir.is_some() {
                &cli.file_log_dir
            } else {
                &old_fl.dir
            };
            let file_log_level = if cli.file_log_level.is_some() {
                &cli.file_log_level
            } else {
                &old_fl.level
            };
            cfg.set_file_logger_config(FileLoggerConfig {
                level: file_log_level.clone(),
                dir: file_log_dir.clone(),
                file: Some(format!("easytier-{}", inst_name)),
            });
        }

        if let Some(vpn_portal) = cli.vpn_portal.as_ref() {
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

        if let Some(manual_routes) = cli.manual_routes.as_ref() {
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
        if let Some(socks5_proxy) = cli.socks5 {
            cfg.set_socks5_portal(Some(
                format!("socks5://0.0.0.0:{}", socks5_proxy)
                    .parse()
                    .unwrap(),
            ));
        }

        #[cfg(feature = "socks5")]
        for port_forward in cli.port_forward.iter() {
            let example_str = ", example: udp://0.0.0.0:12345/10.126.126.1:12345";

            let bind_addr = format!(
                "{}:{}",
                port_forward.host_str().expect("local bind host is missing"),
                port_forward.port().expect("local bind port is missing")
            )
            .parse()
            .expect(format!("failed to parse local bind addr {}", example_str).as_str());

            let dst_addr = format!(
                "{}",
                port_forward
                    .path_segments()
                    .expect(format!("remote destination addr is missing {}", example_str).as_str())
                    .next()
                    .expect(format!("remote destination addr is missing {}", example_str).as_str())
            )
            .parse()
            .expect(format!("failed to parse remote destination addr {}", example_str).as_str());

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
        if let Some(default_protocol) = &cli.default_protocol {
            f.default_protocol = default_protocol.clone()
        };
        if let Some(v) = cli.disable_encryption {
            f.enable_encryption = !v;
        }
        if let Some(v) = cli.disable_ipv6 {
            f.enable_ipv6 = !v;
        }
        f.latency_first = cli.latency_first.unwrap_or(f.latency_first);
        if let Some(dev_name) = &cli.dev_name {
            f.dev_name = dev_name.clone()
        }
        if let Some(mtu) = cli.mtu {
            f.mtu = mtu as u32;
        }
        f.enable_exit_node = cli.enable_exit_node.unwrap_or(f.enable_exit_node);
        f.proxy_forward_by_system = cli
            .proxy_forward_by_system
            .unwrap_or(f.proxy_forward_by_system);
        f.no_tun = cli.no_tun.unwrap_or(f.no_tun) || cfg!(not(feature = "tun"));
        f.use_smoltcp = cli.use_smoltcp.unwrap_or(f.use_smoltcp);
        if let Some(wl) = cli.relay_network_whitelist.as_ref() {
            f.relay_network_whitelist = wl.join(" ");
        }
        f.disable_p2p = cli.disable_p2p.unwrap_or(f.disable_p2p);
        f.disable_udp_hole_punching = cli
            .disable_udp_hole_punching
            .unwrap_or(f.disable_udp_hole_punching);
        f.relay_all_peer_rpc = cli.relay_all_peer_rpc.unwrap_or(f.relay_all_peer_rpc);
        f.multi_thread = cli.multi_thread.unwrap_or(f.multi_thread);
        if let Some(compression) = &cli.compression {
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
        f.bind_device = cli.bind_device.unwrap_or(f.bind_device);
        f.enable_kcp_proxy = cli.enable_kcp_proxy.unwrap_or(f.enable_kcp_proxy);
        f.disable_kcp_input = cli.disable_kcp_input.unwrap_or(f.disable_kcp_input);
        f.accept_dns = cli.accept_dns.unwrap_or(f.accept_dns);
        f.private_mode = cli.private_mode.unwrap_or(f.private_mode);
        cfg.set_flags(f);

        if !cli.exit_nodes.is_empty() {
            cfg.set_exit_nodes(cli.exit_nodes.clone());
        }

        Ok(cfg)
    }
}

fn print_event(msg: String) {
    println!(
        "{}: {}",
        chrono::Local::now().format("%Y-%m-%d %H:%M:%S"),
        msg
    );
}

fn peer_conn_info_to_string(p: proto::cli::PeerConnInfo) -> String {
    format!(
        "my_peer_id: {}, dst_peer_id: {}, tunnel_info: {:?}",
        p.my_peer_id, p.peer_id, p.tunnel
    )
}

#[tracing::instrument]
pub fn handle_event(mut events: EventBusSubscriber) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        loop {
            if let Ok(e) = events.recv().await {
                match e {
                    GlobalCtxEvent::PeerAdded(p) => {
                        print_event(format!("new peer added. peer_id: {}", p));
                    }

                    GlobalCtxEvent::PeerRemoved(p) => {
                        print_event(format!("peer removed. peer_id: {}", p));
                    }

                    GlobalCtxEvent::PeerConnAdded(p) => {
                        print_event(format!(
                            "new peer connection added. conn_info: {}",
                            peer_conn_info_to_string(p)
                        ));
                    }

                    GlobalCtxEvent::PeerConnRemoved(p) => {
                        print_event(format!(
                            "peer connection removed. conn_info: {}",
                            peer_conn_info_to_string(p)
                        ));
                    }

                    GlobalCtxEvent::ListenerAddFailed(p, msg) => {
                        print_event(format!(
                            "listener add failed. listener: {}, msg: {}",
                            p, msg
                        ));
                    }

                    GlobalCtxEvent::ListenerAcceptFailed(p, msg) => {
                        print_event(format!(
                            "listener accept failed. listener: {}, msg: {}",
                            p, msg
                        ));
                    }

                    GlobalCtxEvent::ListenerAdded(p) => {
                        if p.scheme() == "ring" {
                            continue;
                        }
                        print_event(format!("new listener added. listener: {}", p));
                    }

                    GlobalCtxEvent::ConnectionAccepted(local, remote) => {
                        print_event(format!(
                            "new connection accepted. local: {}, remote: {}",
                            local, remote
                        ));
                    }

                    GlobalCtxEvent::ConnectionError(local, remote, err) => {
                        print_event(format!(
                            "connection error. local: {}, remote: {}, err: {}",
                            local, remote, err
                        ));
                    }

                    GlobalCtxEvent::TunDeviceReady(dev) => {
                        print_event(format!("tun device ready. dev: {}", dev));
                    }

                    GlobalCtxEvent::TunDeviceError(err) => {
                        print_event(format!("tun device error. err: {}", err));
                    }

                    GlobalCtxEvent::Connecting(dst) => {
                        print_event(format!("connecting to peer. dst: {}", dst));
                    }

                    GlobalCtxEvent::ConnectError(dst, ip_version, err) => {
                        print_event(format!(
                            "connect to peer error. dst: {}, ip_version: {}, err: {}",
                            dst, ip_version, err
                        ));
                    }

                    GlobalCtxEvent::VpnPortalClientConnected(portal, client_addr) => {
                        print_event(format!(
                            "vpn portal client connected. portal: {}, client_addr: {}",
                            portal, client_addr
                        ));
                    }

                    GlobalCtxEvent::VpnPortalClientDisconnected(portal, client_addr) => {
                        print_event(format!(
                            "vpn portal client disconnected. portal: {}, client_addr: {}",
                            portal, client_addr
                        ));
                    }

                    GlobalCtxEvent::DhcpIpv4Changed(old, new) => {
                        print_event(format!("dhcp ip changed. old: {:?}, new: {:?}", old, new));
                    }

                    GlobalCtxEvent::DhcpIpv4Conflicted(ip) => {
                        print_event(format!("dhcp ip conflict. ip: {:?}", ip));
                    }

                    GlobalCtxEvent::PortForwardAdded(cfg) => {
                        print_event(format!(
                            "port forward added. local: {}, remote: {}, proto: {}",
                            cfg.bind_addr.unwrap().to_string(),
                            cfg.dst_addr.unwrap().to_string(),
                            cfg.socket_type().as_str_name()
                        ));
                    }
                }
            } else {
                events = events.resubscribe();
            }
        }
    })
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
    let cfg = TomlConfigLoader::try_from(&cli)?;
    init_logger(&cfg, false)?;

    if cli.config_server.is_some() {
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
        let hostname = match cli.hostname {
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

    println!("Starting easytier with config:");
    println!("############### TOML ###############\n");
    println!("{}", cfg.dump());
    println!("-----------------------------------");

    let mut l = launcher::NetworkInstance::new(cfg).set_fetch_node_info(false);
    let _t = ScopedTask::from(handle_event(l.start().unwrap()));
    tokio::select! {
        e = l.wait() => {
            if let Some(e) = e {
                eprintln!("launcher error: {}", e);
            }
        }
        _ = tokio::signal::ctrl_c() => {
            println!("ctrl-c received, exiting...");
        }
    }
    Ok(())
}

fn memory_monitor() {
    #[cfg(feature = "jemalloc")]
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
