#![allow(dead_code)]

#[macro_use]
extern crate rust_i18n;

use std::{
    net::{Ipv4Addr, SocketAddr}, 
    path::PathBuf,
    ffi::OsString
};

use anyhow::Context;
use clap::{
    command,
    Parser,
    Subcommand,
    Args
};
use tokio::net::TcpSocket;

use easytier::{
    common::{
        config::{
            ConfigLoader, ConsoleLoggerConfig, FileLoggerConfig, NetworkIdentity, PeerConfig,
            TomlConfigLoader, VpnPortalConfig,
        },
        constants::EASYTIER_VERSION,
        global_ctx::{EventBusSubscriber, GlobalCtxEvent},
        scoped_task::ScopedTask,
    },
    launcher, proto,
    tunnel::udp::UdpTunnelConnector,
    utils::{init_logger, setup_panic_handler, Service},
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
struct RunArgs {  
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

    #[arg(
        long,
        help = t!("core_clap.work_dir").to_string()
    )]
    work_dir: Option<PathBuf>
}

#[derive(Parser, Debug)]
#[command(name = "easytier-core", author, version = EASYTIER_VERSION , about, long_about = None)]
struct Cli{
    #[command(subcommand)]
    sub_command: SubCmd
}
#[derive(Subcommand, Debug)]
enum SubCmd {
    #[command(
        about = t!("core_clap.run").to_string()
    )]
    Run(RunArgs),
    #[command(
        about = t!("core_clap.service").to_string()
    )]
    Service(ServiceArgs)
}

#[derive(Args, Debug)]
struct ServiceArgs{
    #[command(subcommand)]
    sub_command: SrvSubCmd
}
#[derive(Subcommand, Debug)]
enum SrvSubCmd {
    Install(RunArgs),
    Uninstall,
    Status
}

rust_i18n::i18n!("locales", fallback = "en");

impl RunArgs {
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
                    if let Some(s) = RunArgs::check_tcp_available(i) {
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

impl From<RunArgs> for TomlConfigLoader {
    fn from(args: RunArgs) -> Self {
        if let Some(config_file) = &args.config_file {
            println!(
                "NOTICE: loading config file: {:?}, will ignore all command line flags\n",
                config_file
            );
            return TomlConfigLoader::new(config_file)
                .with_context(|| format!("failed to load config file: {:?}", args.config_file))
                .unwrap();
        }

        let cfg = TomlConfigLoader::default();

        cfg.set_hostname(args.hostname);

        cfg.set_network_identity(NetworkIdentity::new(args.network_name, args.network_secret));

        cfg.set_dhcp(args.dhcp);

        if let Some(ipv4) = &args.ipv4 {
            cfg.set_ipv4(Some(
                ipv4.parse()
                    .with_context(|| format!("failed to parse ipv4 address: {}", ipv4))
                    .unwrap(),
            ))
        }

        cfg.set_peers(
            args.peers
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
            RunArgs::parse_listeners(args.no_listener, args.listeners)
                .into_iter()
                .map(|s| s.parse().unwrap())
                .collect(),
        );

        for n in args.proxy_networks.iter() {
            cfg.add_proxy_cidr(
                n.parse()
                    .with_context(|| format!("failed to parse proxy network: {}", n))
                    .unwrap(),
            );
        }

        cfg.set_rpc_portal(RunArgs::parse_rpc_portal(args.rpc_portal));

        if let Some(external_nodes) = args.external_node {
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

        if args.console_log_level.is_some() {
            cfg.set_console_logger_config(ConsoleLoggerConfig {
                level: args.console_log_level,
            });
        }

        if args.file_log_dir.is_some() || args.file_log_level.is_some() {
            cfg.set_file_logger_config(FileLoggerConfig {
                level: args.file_log_level.clone(),
                dir: args.file_log_dir.clone(),
                file: Some(format!("easytier-{}", args.instance_name)),
            });
        }

        cfg.set_inst_name(args.instance_name);

        if let Some(vpn_portal) = args.vpn_portal {
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

        if let Some(manual_routes) = args.manual_routes {
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
        if let Some(socks5_proxy) = args.socks5 {
            cfg.set_socks5_portal(Some(
                format!("socks5://0.0.0.0:{}", socks5_proxy)
                    .parse()
                    .unwrap(),
            ));
        }

        let mut f = cfg.get_flags();
        if args.default_protocol.is_some() {
            f.default_protocol = args.default_protocol.as_ref().unwrap().clone();
        }
        f.enable_encryption = !args.disable_encryption;
        f.enable_ipv6 = !args.disable_ipv6;
        f.latency_first = args.latency_first;
        f.dev_name = args.dev_name.unwrap_or_default();
        if let Some(mtu) = args.mtu {
            f.mtu = mtu;
        }
        f.enable_exit_node = args.enable_exit_node;
        f.no_tun = args.no_tun || cfg!(not(feature = "tun"));
        f.use_smoltcp = args.use_smoltcp;
        if let Some(wl) = args.relay_network_whitelist {
            f.foreign_network_whitelist = wl.join(" ");
        }
        f.disable_p2p = args.disable_p2p;
        f.relay_all_peer_rpc = args.relay_all_peer_rpc;
        if let Some(ipv6_listener) = args.ipv6_listener {
            f.ipv6_listener = ipv6_listener
                .parse()
                .with_context(|| format!("failed to parse ipv6 listener: {}", ipv6_listener))
                .unwrap();
        }
        f.multi_thread = args.multi_thread;
        cfg.set_flags(f);

        cfg.set_exit_nodes(args.exit_nodes.clone());

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
fn win_service_event_loop(  
    args: RunArgs,
    stop_notify: std::sync::Arc<tokio::sync::Notify>,
    status_handle: windows_service::service_control_handler::ServiceStatusHandle,
) {  
    use tokio::runtime::Runtime;
    use std::time::Duration;
    use windows_service::service::*;

    let err_stop = ServiceStatus {
        service_type: ServiceType::OWN_PROCESS,
        current_state: ServiceState::Stopped,
        controls_accepted: ServiceControlAccept::empty(),
        checkpoint: 0,
        wait_hint: Duration::default(),
        exit_code: ServiceExitCode::Win32(1),
        process_id: None,
    };
    let normal_stop = ServiceStatus {
        service_type: ServiceType::OWN_PROCESS,
        current_state: ServiceState::Stopped,
        controls_accepted: ServiceControlAccept::STOP,
        checkpoint: 0,
        wait_hint: Duration::default(),
        exit_code: ServiceExitCode::Win32(0),
        process_id: None,
    };

    std::thread::spawn(move || {
        let rt = Runtime::new().unwrap();
        rt.block_on(async move {
            tokio::select! {
                res = main_run(args) => {
                    if let Err(e) = res {
                        status_handle.set_service_status(err_stop).unwrap();
                        panic!("{:?}", e);                      
                    } else {
                        status_handle.set_service_status(normal_stop).unwrap();
                        std::process::exit(0);
                    }
                },
                _ = stop_notify.notified() => {
                    status_handle.set_service_status(normal_stop).unwrap();
                    std::process::exit(0);
                }
            }
        });
    });
}

#[cfg(target_os = "windows")]
fn win_service_main(_: Vec<OsString>) {
    use std::time::Duration;
    use windows_service::service_control_handler::*;
    use windows_service::service::*;
    use std::sync::Arc;
    use tokio::sync::Notify;
    
    let args = RunArgs::try_parse().unwrap_or_else(|_| {
            if let SubCmd::Run(args_) = Cli::parse().sub_command {
                args_
            } else {
                panic!("invalid args")
            }
        });

    let stop_notify_send = Arc::new(Notify::new());
    let stop_notify_recv = Arc::clone(&stop_notify_send);
    let event_handler = move |control_event| -> ServiceControlHandlerResult {
        match control_event {
            ServiceControl::Interrogate => {
                ServiceControlHandlerResult::NoError
            }
            ServiceControl::Stop =>
            {
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

    status_handle.set_service_status(next_status).expect("set service status fail");
    win_service_event_loop(args, stop_notify_recv, status_handle);    
}

fn service_manager_handle(srv_arg: ServiceArgs) -> Result<(), String> {
    use service_manager::ServiceStatus;
    let service = Service::new().map_err(|e| {
        format!("Service manager init failed: {:?}", e)
    })?;
    let status = service.status().map_err(|e|{
        format!("Failed to get service info: {:?}", e)
    })?;

    match srv_arg.sub_command {
        SrvSubCmd::Install(_) => {
            if status == ServiceStatus::NotInstalled {
                let mut args = std::env::args_os().skip(3).collect::<Vec<OsString>>();
                args.insert(0, OsString::from("run"));
                
                if let Some(work_dir) = args.iter().position(|x| x == "--work-dir") {
                    let d = std::fs::canonicalize(&args[work_dir + 1]).map_err(|e| {
                        format!("failed to get work dir: {:?}", e)
                    })?;
                    args[work_dir + 1] = OsString::from(d);
                } else {
                    let d = std::env::current_exe().unwrap().parent().unwrap().to_path_buf();
                    args.push(OsString::from("--work-dir"));                    
                    args.push(OsString::from(d));
                }
                service.install(args).map_err(|e| {
                    format!("Service install failed: {:?}", e)
                })?;
                println!("Service installed successfully.");
            } 
            else {
                return Err("Service already installed, please uninstall it first.".to_string());
            }
        }
        SrvSubCmd::Uninstall => {
            if status != ServiceStatus::NotInstalled {
                if status == ServiceStatus::Running{
                    service.stop().map_err(|e| {
                        format!("Service stop failed: {:?}", e)
                    })?;
                }
                service.uninstall().map_err(|e| {
                    format!("Service uninstall failed: {:?}", e)
                })?;
                println!("Service uninstalled successfully.");                
            } 
            else {
                eprint!("Service not installed.");
            }
        }
        SrvSubCmd::Status => {
            println!("Service status: {}", match status {
                ServiceStatus::NotInstalled => "Not Installed",
                ServiceStatus::Stopped(_) => "Stopped",
                ServiceStatus::Running => "Running",                       
            });
        }
    }
    Ok(())
}

async fn main_run(args: RunArgs) -> Result<(), String> {
    if let Some(work_dir) = &args.work_dir {
        std::env::set_current_dir(work_dir).map_err(|e| {
            format!("failed to set work dir: {:?}", e)
        })?;
    }
    
    if args.config_server.is_some() {
        let config_server_url_s = args.config_server.clone().unwrap();
        let config_server_url = match url::Url::parse(&config_server_url_s) {
            Ok(u) => u,
            Err(_) => format!(
                "udp://config-server.easytier.top:22020/{}",
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

        if token.is_empty() {
            panic!("empty token");
        }

        let _wc = web_client::WebClient::new(UdpTunnelConnector::new(c_url), token.to_string());
        tokio::signal::ctrl_c().await.unwrap();
        return Ok(());
    }

    let cfg = TomlConfigLoader::from(args);

    init_logger(&cfg, false).unwrap();

    println!("Starting easytier with config:");
    println!("############### TOML ###############\n");
    println!("{}", cfg.dump());
    println!("-----------------------------------");

    let mut l = launcher::NetworkInstance::new(cfg).set_fetch_node_info(false);
    let _t = ScopedTask::from(handle_event(l.start().unwrap()));
    if let Some(e) = l.wait().await{
        Err(format!("launcher error: {}", e))
    } else {
        Ok(())
    }
        
}

#[tokio::main]
async fn main() {
    setup_panic_handler();

    let locale = sys_locale::get_locale().unwrap_or_else(|| String::from("en-US"));
    rust_i18n::set_locale(&locale);

    #[cfg(target_os = "windows")]
    match windows_service::service_dispatcher::start(String::new(), ffi_service_main) {
        Ok(_) => std::thread::park(),
        Err(e) =>
        {    
             let should_panic = if let windows_service::Error::Winapi(ref io_error) = e { 
                 io_error.raw_os_error() != Some(0x427) // ERROR_FAILED_SERVICE_CONTROLLER_CONNECT
             } else { true };
             
             if should_panic {
                 panic!("SCM start an error: {}", e);
             }
         }
     };
     
    let run_result = if let Ok(args) = RunArgs::try_parse() {
        main_run(args).await
    } else {
        match Cli::parse().sub_command {
            SubCmd::Run(args) => main_run(args).await,
            SubCmd::Service(serv_args) => {
                if let Err(e) = service_manager_handle(serv_args) {
                    eprint!("{}", e);
                    std::process::exit(1);
                }
                return;
            }
        }
    };

    if let Err(e) = run_result {
        panic!("{:?}", e);
    }
}

