#![allow(dead_code)]

#[macro_use]
extern crate rust_i18n;

use std::{
    net::{Ipv4Addr, SocketAddr},
    path::PathBuf,
    sync::Arc,
};

use anyhow::Context;
use clap::Parser;
use tokio::net::TcpSocket;

use easytier::{
    common::{
        config::{
            ConfigLoader, ConsoleLoggerConfig, FileLoggerConfig, NetworkIdentity, PeerConfig,
            TomlConfigLoader, VpnPortalConfig,
        },
        constants::EASYTIER_VERSION,
        global_ctx::{EventBusSubscriber, GlobalCtx, GlobalCtxEvent},
        scoped_task::ScopedTask,
        stun::MockStunInfoCollector,
    },
    connector::{create_connector_by_url, dns_connector::DNSTunnelConnector},
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

#[cfg(feature = "mimalloc")]
use mimalloc_rust::GlobalMiMalloc;

#[cfg(feature = "mimalloc")]
#[global_allocator]
static GLOBAL_MIMALLOC: GlobalMiMalloc = GlobalMiMalloc;

#[derive(Parser, Debug)]
#[command(name = "easytier-core", author, version = EASYTIER_VERSION , about, long_about = None)]
struct Cli {
    #[arg(
        short = 'w',
        long,
        help = t!("core_clap.config_server").to_string()
    )]
    config_server: Option<String>,

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
        help = t!("core_clap.mapped_listeners").to_string(),
        num_args = 0..
    )]
    mapped_listeners: Vec<String>,

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
        default_value = "true"
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
        help = t!("core_clap.proxy_forward_by_system").to_string(),
        default_value = "false"
    )]
    proxy_forward_by_system: bool,

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

    // if not in relay_network_whitelist:
    // for foreign virtual network, will refuse the incoming connection
    // for local virtual network, will refuse relaying tun packet
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
        help = t!("core_clap.compression").to_string(),
        default_value = "none",
    )]
    compression: String,

    #[arg(
        long,
        help = t!("core_clap.bind_device").to_string()
    )]
    bind_device: Option<bool>,

    #[arg(
        long,
        help = t!("core_clap.enable_kcp_proxy").to_string(),
        default_value = "false"
    )]
    enable_kcp_proxy: bool,

    #[arg(
        long,
        help = t!("core_clap.disable_kcp_input").to_string(),
        default_value = "false"
    )]
    disable_kcp_input: bool,
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

    fn check_tcp_available(port: u16) -> Option<SocketAddr> {
        let s = format!("0.0.0.0:{}", port).parse::<SocketAddr>().unwrap();
        TcpSocket::new_v4().unwrap().bind(s).map(|_| s).ok()
    }

    fn parse_rpc_portal(rpc_portal: String) -> anyhow::Result<SocketAddr> {
        if let Ok(port) = rpc_portal.parse::<u16>() {
            if port == 0 {
                // check tcp 15888 first
                for i in 15888..15900 {
                    if let Some(s) = Cli::check_tcp_available(i) {
                        return Ok(s);
                    }
                }
                return Ok("0.0.0.0:0".parse().unwrap());
            }
            return Ok(format!("0.0.0.0:{}", port).parse().unwrap());
        }

        Ok(rpc_portal.parse()?)
    }
}

impl TryFrom<&Cli> for TomlConfigLoader {
    type Error = anyhow::Error;

    fn try_from(cli: &Cli) -> Result<Self, Self::Error> {
        if let Some(config_file) = &cli.config_file {
            println!(
                "NOTICE: loading config file: {:?}, will ignore all command line flags\n",
                config_file
            );
            return Ok(TomlConfigLoader::new(config_file)
                .with_context(|| format!("failed to load config file: {:?}", cli.config_file))?);
        }

        let cfg = TomlConfigLoader::default();

        cfg.set_hostname(cli.hostname.clone());

        cfg.set_network_identity(NetworkIdentity::new(
            cli.network_name.clone(),
            cli.network_secret.clone(),
        ));

        cfg.set_dhcp(cli.dhcp);

        if let Some(ipv4) = &cli.ipv4 {
            cfg.set_ipv4(Some(ipv4.parse().with_context(|| {
                format!("failed to parse ipv4 address: {}", ipv4)
            })?))
        }

        let mut peers = Vec::<PeerConfig>::with_capacity(cli.peers.len());
        for p in &cli.peers {
            peers.push(PeerConfig {
                uri: p
                    .parse()
                    .with_context(|| format!("failed to parse peer uri: {}", p))?,
            });
        }
        cfg.set_peers(peers);

        cfg.set_listeners(
            Cli::parse_listeners(cli.no_listener, cli.listeners.clone())?
                .into_iter()
                .map(|s| s.parse().unwrap())
                .collect(),
        );

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

        for n in cli.proxy_networks.iter() {
            cfg.add_proxy_cidr(
                n.parse()
                    .with_context(|| format!("failed to parse proxy network: {}", n))?,
            );
        }

        cfg.set_rpc_portal(
            Cli::parse_rpc_portal(cli.rpc_portal.clone())
                .with_context(|| format!("failed to parse rpc portal: {}", cli.rpc_portal))?,
        );

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

        if cli.file_log_dir.is_some() || cli.file_log_level.is_some() {
            cfg.set_file_logger_config(FileLoggerConfig {
                level: cli.file_log_level.clone(),
                dir: cli.file_log_dir.clone(),
                file: Some(format!("easytier-{}", cli.instance_name)),
            });
        }

        cfg.set_inst_name(cli.instance_name.clone());

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

        let mut f = cfg.get_flags();
        if cli.default_protocol.is_some() {
            f.default_protocol = cli.default_protocol.as_ref().unwrap().clone();
        }
        f.enable_encryption = !cli.disable_encryption;
        f.enable_ipv6 = !cli.disable_ipv6;
        f.latency_first = cli.latency_first;
        f.dev_name = cli.dev_name.clone().unwrap_or_default();
        if let Some(mtu) = cli.mtu {
            f.mtu = mtu as u32;
        }
        f.enable_exit_node = cli.enable_exit_node;
        f.proxy_forward_by_system = cli.proxy_forward_by_system;
        f.no_tun = cli.no_tun || cfg!(not(feature = "tun"));
        f.use_smoltcp = cli.use_smoltcp;
        if let Some(wl) = cli.relay_network_whitelist.as_ref() {
            f.relay_network_whitelist = wl.join(" ");
        }
        f.disable_p2p = cli.disable_p2p;
        f.disable_udp_hole_punching = cli.disable_udp_hole_punching;
        f.relay_all_peer_rpc = cli.relay_all_peer_rpc;
        f.multi_thread = cli.multi_thread;
        f.data_compress_algo = match cli.compression.as_str() {
            "none" => CompressionAlgoPb::None,
            "zstd" => CompressionAlgoPb::Zstd,
            _ => panic!(
                "unknown compression algorithm: {}, supported: none, zstd",
                cli.compression
            ),
        }
        .into();
        if let Some(bind_device) = cli.bind_device {
            f.bind_device = bind_device;
        }
        f.enable_kcp_proxy = cli.enable_kcp_proxy;
        f.disable_kcp_input = cli.disable_kcp_input;
        cfg.set_flags(f);

        cfg.set_exit_nodes(cli.exit_nodes.clone());

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
        let _wc = web_client::WebClient::new(
            create_connector_by_url(c_url.as_str(), &global_ctx, IpVersion::Both).await?,
            token.to_string(),
        );
        tokio::signal::ctrl_c().await.unwrap();
        DNSTunnelConnector::new("".parse().unwrap(), global_ctx);
        return Ok(());
    }

    println!("Starting easytier with config:");
    println!("############### TOML ###############\n");
    println!("{}", cfg.dump());
    println!("-----------------------------------");

    let mut l = launcher::NetworkInstance::new(cfg).set_fetch_node_info(false);
    let _t = ScopedTask::from(handle_event(l.start().unwrap()));
    if let Some(e) = l.wait().await {
        anyhow::bail!("launcher error: {}", e);
    }
    Ok(())
}

#[tokio::main(flavor = "current_thread")]
async fn main() {
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

    let cli = Cli::parse();

    if let Err(e) = run_main(cli).await {
        eprintln!("error: {:?}", e);
        std::process::exit(1);
    }
}
