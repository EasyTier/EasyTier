#![allow(dead_code)]

#[cfg(test)]
mod tests;

use std::{backtrace, io::Write as _, net::SocketAddr, path::PathBuf};

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
#[command(author, version, about, long_about = None)]
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

    #[arg(short, long, help = "peers to connect initially")]
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
        default_value = "127.0.0.1:15888",
        help = "rpc portal address to listen for management"
    )]
    rpc_portal: SocketAddr,

    #[arg(short, long, help = "listeners to accept connections, pass '' to avoid listening.",
            default_values_t = ["tcp://0.0.0.0:11010".to_string(),
                                "udp://0.0.0.0:11010".to_string(),
                                "wg://0.0.0.0:11011".to_string()])]
    listeners: Vec<String>,

    /// specify the linux network namespace, default is the root namespace
    #[arg(long)]
    net_ns: Option<String>,

    #[arg(long, help = "console log level", 
        value_parser = clap::builder::PossibleValuesParser::new(["trace", "debug", "info", "warn", "error", "off"]))]
    console_log_level: Option<String>,

    #[arg(long, help = "file log level", 
        value_parser = clap::builder::PossibleValuesParser::new(["trace", "debug", "info", "warn", "error", "off"]))]
    file_log_level: Option<String>,
    #[arg(long, help = "directory to store log files")]
    file_log_dir: Option<String>,

    #[arg(
        short = 'm',
        long,
        default_value = "default",
        help = "instance name to identify this vpn node in same machine"
    )]
    instance_name: String,

    #[arg(
        short = 'd',
        long,
        help = "instance uuid to identify this vpn node in whole vpn network example: 123e4567-e89b-12d3-a456-426614174000"
    )]
    instance_id: Option<String>,

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
        cfg.set_network_identity(NetworkIdentity::new(
            cli.network_name.clone(),
            cli.network_secret.clone(),
        ));

        cfg.set_netns(cli.net_ns.clone());
        if let Some(ipv4) = &cli.ipv4 {
            cfg.set_ipv4(
                ipv4.parse()
                    .with_context(|| format!("failed to parse ipv4 address: {}", ipv4))
                    .unwrap(),
            )
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
            cli.listeners
                .iter()
                .filter_map(|s| {
                    if s.is_empty() {
                        return None;
                    }

                    Some(
                        s.parse()
                            .with_context(|| format!("failed to parse listener uri: {}", s))
                            .unwrap(),
                    )
                })
                .collect(),
        );

        for n in cli.proxy_networks.iter() {
            cfg.add_proxy_cidr(
                n.parse()
                    .with_context(|| format!("failed to parse proxy network: {}", n))
                    .unwrap(),
            );
        }

        cfg.set_rpc_portal(cli.rpc_portal);

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
        if let Some(mtu) = cli.mtu {
            f.mtu = mtu;
        }
        cfg.set_flags(f);

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
            }
        }
    });

    println!("Starting easytier with config:");
    println!("############### TOML ##############\n");
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
