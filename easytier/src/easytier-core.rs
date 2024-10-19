#![allow(dead_code)]

#[cfg(test)]
mod tests;

use std::{
    net::{Ipv4Addr, SocketAddr},
    path::PathBuf,
};

#[macro_use]
extern crate rust_i18n;

use anyhow::Context;
use clap::Parser;

mod arch;
mod common;
mod connector;
mod gateway;
mod instance;
mod launcher;
mod peer_center;
mod peers;
mod proto;
mod tunnel;
mod utils;
mod vpn_portal;

use common::{
    config::{ConsoleLoggerConfig, FileLoggerConfig, NetworkIdentity, PeerConfig, VpnPortalConfig},
    constants::EASYTIER_VERSION,
    global_ctx::EventBusSubscriber,
    scoped_task::ScopedTask,
};
use tokio::net::TcpSocket;
use utils::setup_panic_handler;

use crate::{
    common::{
        config::{ConfigLoader, TomlConfigLoader},
        global_ctx::GlobalCtxEvent,
    },
    utils::init_logger,
};

#[cfg(feature = "mimalloc")]
use mimalloc_rust::*;

#[cfg(feature = "mimalloc")]
#[global_allocator]
static GLOBAL_MIMALLOC: GlobalMiMalloc = GlobalMiMalloc;

#[derive(Parser, Debug)]
#[command(name = "easytier-core", author, version = EASYTIER_VERSION , about, long_about = None)]
struct Cli {
    #[arg(
        short,
        long,
        help = t!("core_clap.config_file").to_string()
    )]
    config_file: Option<PathBuf>,

    #[arg(
        long,
        help = t!("core_clap.network_name").to_string(),
        default_value = "default"
    )]
    network_name: String,

    #[arg(
        long,
        help = t!("core_clap.network_secret").to_string(),
        default_value = ""
    )]
    network_secret: String,

    #[arg(
        short,
        long,
        help = t!("core_clap.ipv4").to_string()
    )]
    ipv4: Option<String>,

    #[arg(
        short,
        long,
        help = t!("core_clap.dhcp").to_string()
    )]
    dhcp: bool,

    #[arg(
        short,
        long,
        help = t!("core_clap.peers").to_string(),
        num_args = 0..
    )]
    peers: Vec<String>,

    #[arg(
        short,
        long,
        help = t!("core_clap.external_node").to_string()
    )]
    external_node: Option<String>,

    #[arg(
        short = 'n',
        long,
        help = t!("core_clap.proxy_networks").to_string()
    )]
    proxy_networks: Vec<String>,

    #[arg(
        short,
        long,
        help = t!("core_clap.rpc_portal").to_string(),
        default_value = "0"
    )]
    rpc_portal: String,

    #[arg(
        short,
        long,
        help = t!("core_clap.listeners").to_string(),
        default_values_t = ["11010".to_string()],
        num_args = 0..
    )]
    listeners: Vec<String>,

    #[arg(
        long,
        help = t!("core_clap.no_listener").to_string(),
        default_value = "false"
    )]
    no_listener: bool,

    #[arg(
        long,
        help = t!("core_clap.console_log_level").to_string()
    )]
    console_log_level: Option<String>,

    #[arg(
        long,
        help = t!("core_clap.file_log_level").to_string()
    )]
    file_log_level: Option<String>,

    #[arg(
        long,
        help = t!("core_clap.file_log_dir").to_string()
    )]
    file_log_dir: Option<String>,

    #[arg(
        long,
        help = t!("core_clap.hostname").to_string()
    )]
    hostname: Option<String>,

    #[arg(
        short = 'm',
        long,
        help = t!("core_clap.instance_name").to_string(),
        default_value = "default"
    )]
    instance_name: String,

    #[arg(
        long,
        help = t!("core_clap.vpn_portal").to_string()
    )]
    vpn_portal: Option<String>,

    #[arg(
        long,
        help = t!("core_clap.default_protocol").to_string()
    )]
    default_protocol: Option<String>,

    #[arg(
        short = 'u',
        long,
        help = t!("core_clap.disable_encryption").to_string(),
        default_value = "false"
    )]
    disable_encryption: bool,

    #[arg(
        long,
        help = t!("core_clap.multi_thread").to_string(),
        default_value = "false"
    )]
    multi_thread: bool,

    #[arg(
        long,
        help = t!("core_clap.disable_ipv6").to_string(),
        default_value = "false"
    )]
    disable_ipv6: bool,

    #[arg(
        long,
        help = t!("core_clap.dev_name").to_string()
    )]
    dev_name: Option<String>,

    #[arg(
        long,
        help = t!("core_clap.mtu").to_string()
    )]
    mtu: Option<u16>,

    #[arg(
        long,
        help = t!("core_clap.latency_first").to_string(),
        default_value = "false"
    )]
    latency_first: bool,

    #[arg(
        long,
        help = t!("core_clap.exit_nodes").to_string(),
        num_args = 0..
    )]
    exit_nodes: Vec<Ipv4Addr>,

    #[arg(
        long,
        help = t!("core_clap.enable_exit_node").to_string(),
        default_value = "false"
    )]
    enable_exit_node: bool,

    #[arg(
        long,
        help = t!("core_clap.no_tun").to_string(),
        default_value = "false"
    )]
    no_tun: bool,

    #[arg(
        long,
        help = t!("core_clap.use_smoltcp").to_string(),
        default_value = "false"
    )]
    use_smoltcp: bool,

    #[arg(
        long,
        help = t!("core_clap.manual_routes").to_string(),
        num_args = 0..
    )]
    manual_routes: Option<Vec<String>>,

    #[arg(
        long,
        help = t!("core_clap.relay_network_whitelist").to_string(),
        num_args = 0..
    )]
    relay_network_whitelist: Option<Vec<String>>,

    #[arg(
        long,
        help = t!("core_clap.disable_p2p").to_string(),
        default_value = "false"
    )]
    disable_p2p: bool,

    #[arg(
        long,
        help = t!("core_clap.disable_udp_hole_punching").to_string(),
        default_value = "false"
    )]
    disable_udp_hole_punching: bool,

    #[arg(
        long,
        help = t!("core_clap.relay_all_peer_rpc").to_string(),
        default_value = "false"
    )]
    relay_all_peer_rpc: bool,

    #[cfg(feature = "socks5")]
    #[arg(
        long,
        help = t!("core_clap.socks5").to_string()
    )]
    socks5: Option<u16>,

    #[arg(
        long,
        help = t!("core_clap.ipv6_listener").to_string()
    )]
    ipv6_listener: Option<String>,
}

rust_i18n::i18n!("locales", fallback = "en");

impl Cli {
    fn parse_listeners(no_listener: bool, listeners: Vec<String>) -> Vec<String> {
        let proto_port_offset = vec![("tcp", 0), ("udp", 0), ("wg", 1), ("ws", 1), ("wss", 2)];

        if no_listener || listeners.is_empty() {
            return vec![];
        }

        let origin_listners = listeners;
        let mut listeners: Vec<String> = Vec::new();
        if origin_listners.len() == 1 {
            if let Ok(port) = origin_listners[0].parse::<u16>() {
                for (proto, offset) in proto_port_offset {
                    listeners.push(format!("{}://0.0.0.0:{}", proto, port + offset));
                }
                return listeners;
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
                let Some((proto, offset)) = proto_port_offset
                    .iter()
                    .find(|(proto, _)| *proto == proto_port[0])
                else {
                    panic!("unknown protocol: {}", proto_port[0]);
                };

                let port = if proto_port.len() == 2 {
                    proto_port[1].parse::<u16>().unwrap()
                } else {
                    11010 + offset
                };

                listeners.push(format!("{}://0.0.0.0:{}", proto, port));
            }
        }

        listeners
    }

    fn check_tcp_available(port: u16) -> Option<SocketAddr> {
        let s = format!("0.0.0.0:{}", port).parse::<SocketAddr>().unwrap();
        TcpSocket::new_v4().unwrap().bind(s).map(|_| s).ok()
    }

    fn parse_rpc_portal(rpc_portal: String) -> SocketAddr {
        if let Ok(port) = rpc_portal.parse::<u16>() {
            if port == 0 {
                // check tcp 15888 first
                for i in 15888..15900 {
                    if let Some(s) = Cli::check_tcp_available(i) {
                        return s;
                    }
                }
                return "0.0.0.0:0".parse().unwrap();
            }
            return format!("0.0.0.0:{}", port).parse().unwrap();
        }

        rpc_portal.parse().unwrap()
    }
}

impl From<Cli> for TomlConfigLoader {
    fn from(cli: Cli) -> Self {
        if let Some(config_file) = &cli.config_file {
            println!(
                "NOTICE: loading config file: {:?}, will ignore all command line flags\n",
                config_file
            );
            return TomlConfigLoader::new(config_file)
                .with_context(|| format!("failed to load config file: {:?}", cli.config_file))
                .unwrap();
        }

        let cfg = TomlConfigLoader::default();

        cfg.set_hostname(cli.hostname);

        cfg.set_network_identity(NetworkIdentity::new(cli.network_name, cli.network_secret));

        cfg.set_dhcp(cli.dhcp);

        if let Some(ipv4) = &cli.ipv4 {
            cfg.set_ipv4(Some(
                ipv4.parse()
                    .with_context(|| format!("failed to parse ipv4 address: {}", ipv4))
                    .unwrap(),
            ))
        }

        cfg.set_peers(
            cli.peers
                .iter()
                .map(|s| PeerConfig {
                    uri: s
                        .parse()
                        .with_context(|| format!("failed to parse peer uri: {}", s))
                        .unwrap(),
                })
                .collect(),
        );

        cfg.set_listeners(
            Cli::parse_listeners(cli.no_listener, cli.listeners)
                .into_iter()
                .map(|s| s.parse().unwrap())
                .collect(),
        );

        for n in cli.proxy_networks.iter() {
            cfg.add_proxy_cidr(
                n.parse()
                    .with_context(|| format!("failed to parse proxy network: {}", n))
                    .unwrap(),
            );
        }

        cfg.set_rpc_portal(Cli::parse_rpc_portal(cli.rpc_portal));

        if let Some(external_nodes) = cli.external_node {
            let mut old_peers = cfg.get_peers();
            old_peers.push(PeerConfig {
                uri: external_nodes
                    .parse()
                    .with_context(|| {
                        format!("failed to parse external node uri: {}", external_nodes)
                    })
                    .unwrap(),
            });
            cfg.set_peers(old_peers);
        }

        if cli.console_log_level.is_some() {
            cfg.set_console_logger_config(ConsoleLoggerConfig {
                level: cli.console_log_level,
            });
        }

        if cli.file_log_dir.is_some() || cli.file_log_level.is_some() {
            cfg.set_file_logger_config(FileLoggerConfig {
                level: cli.file_log_level.clone(),
                dir: cli.file_log_dir.clone(),
                file: Some(format!("easytier-{}", cli.instance_name)),
            });
        }

        cfg.set_inst_name(cli.instance_name);

        if let Some(vpn_portal) = cli.vpn_portal {
            let url: url::Url = vpn_portal
                .parse()
                .with_context(|| format!("failed to parse vpn portal url: {}", vpn_portal))
                .unwrap();
            cfg.set_vpn_portal_config(VpnPortalConfig {
                client_cidr: url.path()[1..]
                    .parse()
                    .with_context(|| {
                        format!("failed to parse vpn portal client cidr: {}", url.path())
                    })
                    .unwrap(),
                wireguard_listen: format!("{}:{}", url.host_str().unwrap(), url.port().unwrap())
                    .parse()
                    .with_context(|| {
                        format!(
                            "failed to parse vpn portal wireguard listen address: {}",
                            url.host_str().unwrap()
                        )
                    })
                    .unwrap(),
            });
        }

        if let Some(manual_routes) = cli.manual_routes {
            cfg.set_routes(Some(
                manual_routes
                    .iter()
                    .map(|s| {
                        s.parse()
                            .with_context(|| format!("failed to parse route: {}", s))
                            .unwrap()
                    })
                    .collect(),
            ));
        }

        #[cfg(feature = "socks5")]
        if let Some(socks5_proxy) = cli.socks5 {
            cfg.set_socks5_portal(Some(
                format!("socks5://0.0.0.0:{}", socks5_proxy)
                    .parse()
                    .unwrap(),
            ));
        }

        let mut f = cfg.get_flags();
        if cli.default_protocol.is_some() {
            f.default_protocol = cli.default_protocol.as_ref().unwrap().clone();
        }
        f.enable_encryption = !cli.disable_encryption;
        f.enable_ipv6 = !cli.disable_ipv6;
        f.latency_first = cli.latency_first;
        f.dev_name = cli.dev_name.unwrap_or(Default::default());
        if let Some(mtu) = cli.mtu {
            f.mtu = mtu;
        }
        f.enable_exit_node = cli.enable_exit_node;
        f.no_tun = cli.no_tun || cfg!(not(feature = "tun"));
        f.use_smoltcp = cli.use_smoltcp;
        if let Some(wl) = cli.relay_network_whitelist {
            f.foreign_network_whitelist = wl.join(" ");
        }
        f.disable_p2p = cli.disable_p2p;
        f.relay_all_peer_rpc = cli.relay_all_peer_rpc;
        if let Some(ipv6_listener) = cli.ipv6_listener {
            f.ipv6_listener = ipv6_listener
                .parse()
                .with_context(|| format!("failed to parse ipv6 listener: {}", ipv6_listener))
                .unwrap();
        }
        f.multi_thread = cli.multi_thread;
        cfg.set_flags(f);

        cfg.set_exit_nodes(cli.exit_nodes.clone());

        cfg
    }
}

fn print_event(msg: String) {
    println!(
        "{}: {}",
        chrono::Local::now().format("%Y-%m-%d %H:%M:%S"),
        msg
    );
}

fn peer_conn_info_to_string(p: crate::proto::cli::PeerConnInfo) -> String {
    format!(
        "my_peer_id: {}, dst_peer_id: {}, tunnel_info: {:?}",
        p.my_peer_id, p.peer_id, p.tunnel
    )
}

#[tracing::instrument]
pub fn handle_event(mut events: EventBusSubscriber) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        while let Ok(e) = events.recv().await {
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
            }
        }
    })
}

#[tokio::main]
async fn main() {
    setup_panic_handler();

    let locale = sys_locale::get_locale().unwrap_or_else(|| String::from("en-US"));
    rust_i18n::set_locale(&locale);

    let cli = Cli::parse();
    let cfg = TomlConfigLoader::from(cli);
    init_logger(&cfg, false).unwrap();

    println!("Starting easytier with config:");
    println!("############### TOML ###############\n");
    println!("{}", cfg.dump());
    println!("-----------------------------------");

    let mut l = launcher::NetworkInstance::new(cfg).set_fetch_node_info(false);
    let _t = ScopedTask::from(handle_event(l.start().unwrap()));
    if let Some(e) = l.wait().await {
        panic!("launcher error: {:?}", e);
    }
}
