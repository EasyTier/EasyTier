#![allow(dead_code)]

#[cfg(test)]
mod tests;

use std::{
    backtrace,
    io::Write as _,
    net::{Ipv4Addr, SocketAddr},
    path::PathBuf,
};

use anyhow::Context;
use clap::Parser;

mod arch;
mod common;
mod connector;
mod gateway;
mod instance;
mod peer_center;
mod peers;
mod rpc;
mod tunnel;
mod utils;
mod vpn_portal;

use common::config::{
    ConsoleLoggerConfig, FileLoggerConfig, NetworkIdentity, PeerConfig, VpnPortalConfig,
};
use instance::instance::Instance;
use tokio::net::TcpSocket;

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
#[command(name = "easytier-core", author, version, about, long_about = None)]
struct Cli {
    #[arg(
        short,
        long,
        help = "path to the config file, NOTE: if this is set, all other options will be ignored"
    )]
    config_file: Option<PathBuf>,

    #[arg(
        long,
        help = "network name to identify this vpn network",
        default_value = "default"
    )]
    network_name: String,
    #[arg(
        long,
        help = "network secret to verify this node belongs to the vpn network",
        default_value = ""
    )]
    network_secret: String,

    #[arg(
        short,
        long,
        help = "ipv4 address of this vpn node, if empty, this node will only forward packets and no TUN device will be created"
    )]
    ipv4: Option<String>,

    #[arg(
        short,
        long,
        help = "automatically determine and set IP address by Easytier, and the IP address starts from 10.0.0.1 by default. Warning, if there is an IP conflict in the network when using DHCP, the IP will be automatically changed."
    )]
    dhcp: bool,

    #[arg(short, long, help = "peers to connect initially", num_args = 0..)]
    peers: Vec<String>,

    #[arg(short, long, help = "use a public shared node to discover peers")]
    external_node: Option<String>,

    #[arg(
        short = 'n',
        long,
        help = "export local networks to other peers in the vpn"
    )]
    proxy_networks: Vec<String>,

    #[arg(
        short,
        long,
        default_value = "0",
        help = "rpc portal address to listen for management. 0 means random
port, 12345 means listen on 12345 of localhost, 0.0.0.0:12345 means
listen on 12345 of all interfaces. default is 0 and will try 15888 first"
    )]
    rpc_portal: String,

    #[arg(short, long, help = "listeners to accept connections, allow format:
a port number: 11010, means tcp/udp will listen on 11010, ws/wss will listen on 11010 and 11011, wg will listen on 11011
url: tcp://0.0.0.0:11010, tcp can be tcp, udp, ring, wg, ws, wss,
proto:port: wg:11011, means listen on 11011 with wireguard protocol
url and proto:port can occur multiple times.
            ", default_values_t = ["11010".to_string()],
        num_args = 0..)]
    listeners: Vec<String>,

    #[arg(
        long,
        help = "do not listen on any port, only connect to peers",
        default_value = "false"
    )]
    no_listener: bool,

    #[arg(long, help = "console log level", 
        value_parser = clap::builder::PossibleValuesParser::new(["trace", "debug", "info", "warn", "error", "off"]))]
    console_log_level: Option<String>,

    #[arg(long, help = "file log level", 
        value_parser = clap::builder::PossibleValuesParser::new(["trace", "debug", "info", "warn", "error", "off"]))]
    file_log_level: Option<String>,
    #[arg(long, help = "directory to store log files")]
    file_log_dir: Option<String>,

    #[arg(long, help = "host name to identify this device")]
    hostname: Option<String>,

    #[arg(
        short = 'm',
        long,
        default_value = "default",
        help = "instance name to identify this vpn node in same machine"
    )]
    instance_name: String,

    #[arg(
        long,
        help = "url that defines the vpn portal, allow other vpn clients to connect.
example: wg://0.0.0.0:11010/10.14.14.0/24, means the vpn portal is a wireguard server listening on vpn.example.com:11010,
and the vpn client is in network of 10.14.14.0/24"
    )]
    vpn_portal: Option<String>,

    #[arg(long, help = "default protocol to use when connecting to peers")]
    default_protocol: Option<String>,

    #[arg(
        short = 'u',
        long,
        help = "disable encryption for peers communication, default is false, must be same with peers",
        default_value = "false"
    )]
    disable_encryption: bool,

    #[arg(
        long,
        help = "use multi-thread runtime, default is single-thread",
        default_value = "false"
    )]
    multi_thread: bool,

    #[arg(long, help = "do not use ipv6", default_value = "false")]
    disable_ipv6: bool,

    #[arg(
        long,
        help = "mtu of the TUN device, default is 1420 for non-encryption, 1400 for encryption"
    )]
    mtu: Option<u16>,

    #[arg(
        long,
        help = "path to the log file, if not set, will print to stdout",
        default_value = "false"
    )]
    latency_first: bool,

    #[arg(
        long,
        help = "exit nodes to forward all traffic to, a virtual ipv4 address, priority is determined by the order of the list",
        num_args = 0..
    )]
    exit_nodes: Vec<Ipv4Addr>,

    #[arg(
        long,
        help = "allow this node to be an exit node, default is false",
        default_value = "false"
    )]
    enable_exit_node: bool,

    #[arg(
        long,
        help = "do not create TUN device, can use subnet proxy to access node",
        default_value = "false"
    )]
    no_tun: bool,

    #[arg(
        long,
        help = "enable smoltcp stack for subnet proxy",
        default_value = "true"
    )]
    use_smoltcp: bool,
}

impl Cli {
    fn parse_listeners(&self) -> Vec<String> {
        println!("parsing listeners: {:?}", self.listeners);
        let proto_port_offset = vec![("tcp", 0), ("udp", 0), ("wg", 1), ("ws", 1), ("wss", 2)];

        if self.no_listener || self.listeners.is_empty() {
            return vec![];
        }

        let origin_listners = self.listeners.clone();
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

        println!("parsed listeners: {:?}", listeners);

        listeners
    }

    fn check_tcp_available(port: u16) -> Option<SocketAddr> {
        let s = format!("127.0.0.1:{}", port).parse::<SocketAddr>().unwrap();
        TcpSocket::new_v4().unwrap().bind(s).map(|_| s).ok()
    }

    fn parse_rpc_portal(&self) -> SocketAddr {
        if let Ok(port) = self.rpc_portal.parse::<u16>() {
            if port == 0 {
                // check tcp 15888 first
                for i in 15888..15900 {
                    if let Some(s) = Cli::check_tcp_available(i) {
                        return s;
                    }
                }
                return "127.0.0.1:0".parse().unwrap();
            }
            return format!("127.0.0.1:{}", port).parse().unwrap();
        }

        self.rpc_portal.parse().unwrap()
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

        cfg.set_inst_name(cli.instance_name.clone());

        cfg.set_hostname(cli.hostname.clone());

        cfg.set_network_identity(NetworkIdentity::new(
            cli.network_name.clone(),
            cli.network_secret.clone(),
        ));

        cfg.set_dhcp(cli.dhcp);

        if !cli.dhcp {
            if let Some(ipv4) = &cli.ipv4 {
                cfg.set_ipv4(Some(
                    ipv4.parse()
                        .with_context(|| format!("failed to parse ipv4 address: {}", ipv4))
                        .unwrap(),
                ))
            }
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
            cli.parse_listeners()
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

        cfg.set_rpc_portal(cli.parse_rpc_portal());

        if cli.external_node.is_some() {
            let mut old_peers = cfg.get_peers();
            old_peers.push(PeerConfig {
                uri: cli
                    .external_node
                    .clone()
                    .unwrap()
                    .parse()
                    .with_context(|| {
                        format!(
                            "failed to parse external node uri: {}",
                            cli.external_node.unwrap()
                        )
                    })
                    .unwrap(),
            });
            cfg.set_peers(old_peers);
        }

        if cli.console_log_level.is_some() {
            cfg.set_console_logger_config(ConsoleLoggerConfig {
                level: cli.console_log_level.clone(),
            });
        }

        if cli.file_log_dir.is_some() || cli.file_log_level.is_some() {
            cfg.set_file_logger_config(FileLoggerConfig {
                level: cli.file_log_level.clone(),
                dir: cli.file_log_dir.clone(),
                file: Some(format!("easytier-{}", cli.instance_name)),
            });
        }

        if cli.vpn_portal.is_some() {
            let url: url::Url = cli
                .vpn_portal
                .clone()
                .unwrap()
                .parse()
                .with_context(|| {
                    format!(
                        "failed to parse vpn portal url: {}",
                        cli.vpn_portal.unwrap()
                    )
                })
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

        let mut f = cfg.get_flags();
        if cli.default_protocol.is_some() {
            f.default_protocol = cli.default_protocol.as_ref().unwrap().clone();
        }
        f.enable_encryption = !cli.disable_encryption;
        f.enable_ipv6 = !cli.disable_ipv6;
        f.latency_first = cli.latency_first;
        if let Some(mtu) = cli.mtu {
            f.mtu = mtu;
        }
        f.enable_exit_node = cli.enable_exit_node;
        f.no_tun = cli.no_tun;
        f.use_smoltcp = cli.use_smoltcp;
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

fn peer_conn_info_to_string(p: crate::rpc::PeerConnInfo) -> String {
    format!(
        "my_peer_id: {}, dst_peer_id: {}, tunnel_info: {:?}",
        p.my_peer_id, p.peer_id, p.tunnel
    )
}

fn setup_panic_handler() {
    std::panic::set_hook(Box::new(|info| {
        let backtrace = backtrace::Backtrace::force_capture();
        println!("panic occurred: {:?}", info);
        let _ = std::fs::File::create("easytier-panic.log")
            .and_then(|mut f| f.write_all(format!("{:?}\n{:#?}", info, backtrace).as_bytes()));
        std::process::exit(1);
    }));
}

#[tracing::instrument]
pub async fn async_main(cli: Cli) {
    let cfg: TomlConfigLoader = cli.into();

    init_logger(&cfg, false).unwrap();
    let mut inst = Instance::new(cfg.clone());

    let mut events = inst.get_global_ctx().subscribe();
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
    });

    println!("Starting easytier with config:");
    println!("############### TOML ###############\n");
    println!("{}", cfg.dump());
    println!("-----------------------------------");

    inst.run().await.unwrap();

    inst.wait().await;
}

fn main() {
    setup_panic_handler();

    let cli = Cli::parse();
    tracing::info!(cli = ?cli, "cli args parsed");

    if cli.multi_thread {
        tokio::runtime::Builder::new_multi_thread()
            .worker_threads(2)
            .enable_all()
            .build()
            .unwrap()
            .block_on(async move { async_main(cli).await })
    } else {
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap()
            .block_on(async move { async_main(cli).await })
    }
}
