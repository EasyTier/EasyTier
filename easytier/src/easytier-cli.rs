use std::{
    ffi::OsString,
    fmt::Write,
    net::{IpAddr, SocketAddr},
    path::PathBuf,
    sync::Mutex,
    time::Duration,
    vec,
};

use anyhow::Context;
use clap::{command, Args, Parser, Subcommand};
use humansize::format_size;
use service_manager::*;
use tabled::settings::Style;
use tokio::time::timeout;

use easytier::{
    common::{
        constants::EASYTIER_VERSION,
        stun::{StunInfoCollector, StunInfoCollectorTrait},
    },
    proto::{
        cli::{
            list_peer_route_pair, ConnectorManageRpc, ConnectorManageRpcClientFactory,
            DumpRouteRequest, GetVpnPortalInfoRequest, ListConnectorRequest,
            ListForeignNetworkRequest, ListGlobalForeignNetworkRequest, ListPeerRequest,
            ListPeerResponse, ListRouteRequest, ListRouteResponse, NodeInfo, PeerManageRpc,
            PeerManageRpcClientFactory, ShowNodeInfoRequest, TcpProxyEntryState,
            TcpProxyEntryTransportType, TcpProxyRpc, TcpProxyRpcClientFactory, VpnPortalRpc,
            VpnPortalRpcClientFactory,
        },
        common::NatType,
        peer_rpc::{GetGlobalPeerMapRequest, PeerCenterRpc, PeerCenterRpcClientFactory},
        rpc_impl::standalone::StandAloneClient,
        rpc_types::controller::BaseController,
    },
    tunnel::tcp::TcpTunnelConnector,
    utils::{cost_to_str, float_to_str, PeerRoutePair},
};

rust_i18n::i18n!("locales", fallback = "en");

#[derive(Parser, Debug)]
#[command(name = "easytier-cli", author, version = EASYTIER_VERSION, about, long_about = None)]
struct Cli {
    /// the instance name
    #[arg(short = 'p', long, default_value = "127.0.0.1:15888")]
    rpc_portal: SocketAddr,

    #[arg(short, long, default_value = "false", help = "verbose output")]
    verbose: bool,

    #[command(subcommand)]
    sub_command: SubCommand,
}

#[derive(Subcommand, Debug)]
enum SubCommand {
    #[command(about = "show peers info")]
    Peer(PeerArgs),
    #[command(about = "manage connectors")]
    Connector(ConnectorArgs),
    #[command(about = "do stun test")]
    Stun,
    #[command(about = "show route info")]
    Route(RouteArgs),
    #[command(about = "show global peers info")]
    PeerCenter,
    #[command(about = "show vpn portal (wireguard) info")]
    VpnPortal,
    #[command(about = "inspect self easytier-core status")]
    Node(NodeArgs),
    #[command(about = "manage easytier-core as a system service")]
    Service(ServiceArgs),
    #[command(about = "show tcp/kcp proxy status")]
    Proxy,
}

#[derive(Args, Debug)]
struct PeerArgs {
    #[command(subcommand)]
    sub_command: Option<PeerSubCommand>,
}

#[derive(Args, Debug)]
struct PeerListArgs {
    #[arg(short, long)]
    verbose: bool,
}

#[derive(Subcommand, Debug)]
enum PeerSubCommand {
    Add,
    Remove,
    List(PeerListArgs),
    ListForeign,
    ListGlobalForeign,
}

#[derive(Args, Debug)]
struct RouteArgs {
    #[command(subcommand)]
    sub_command: Option<RouteSubCommand>,
}

#[derive(Subcommand, Debug)]
enum RouteSubCommand {
    List,
    Dump,
}

#[derive(Args, Debug)]
struct ConnectorArgs {
    #[arg(short, long)]
    ipv4: Option<String>,

    #[arg(short, long)]
    peers: Vec<String>,

    #[command(subcommand)]
    sub_command: Option<ConnectorSubCommand>,
}

#[derive(Subcommand, Debug)]
enum ConnectorSubCommand {
    Add,
    Remove,
    List,
}

#[derive(Subcommand, Debug)]
enum NodeSubCommand {
    #[command(about = "show node info")]
    Info,
    #[command(about = "show node config")]
    Config,
}

#[derive(Args, Debug)]
struct NodeArgs {
    #[command(subcommand)]
    sub_command: Option<NodeSubCommand>,
}

#[derive(Args, Debug)]
struct ServiceArgs {
    #[arg(short, long, default_value = env!("CARGO_PKG_NAME"), help = "service name")]
    name: String,

    #[command(subcommand)]
    sub_command: ServiceSubCommand,
}

#[derive(Subcommand, Debug)]
enum ServiceSubCommand {
    #[command(about = "register easytier-core as a system service")]
    Install(InstallArgs),
    #[command(about = "unregister easytier-core system service")]
    Uninstall,
    #[command(about = "check easytier-core system service status")]
    Status,
    #[command(about = "start easytier-core system service")]
    Start,
    #[command(about = "stop easytier-core system service")]
    Stop,
}

#[derive(Args, Debug)]
struct InstallArgs {
    #[arg(long, default_value = env!("CARGO_PKG_DESCRIPTION"), help = "service description")]
    description: String,

    #[arg(long)]
    display_name: Option<String>,

    #[arg(long, default_value = "false")]
    disable_autostart: bool,

    #[arg(long, help = "path to easytier-core binary")]
    core_path: Option<PathBuf>,

    #[arg(long)]
    service_work_dir: Option<PathBuf>,

    #[arg(
        trailing_var_arg = true,
        allow_hyphen_values = true,
        help = "args to pass to easytier-core"
    )]
    core_args: Option<Vec<OsString>>,
}

type Error = anyhow::Error;

struct CommandHandler {
    client: Mutex<RpcClient>,
    verbose: bool,
}

type RpcClient = StandAloneClient<TcpTunnelConnector>;

impl CommandHandler {
    async fn get_peer_manager_client(
        &self,
    ) -> Result<Box<dyn PeerManageRpc<Controller = BaseController>>, Error> {
        Ok(self
            .client
            .lock()
            .unwrap()
            .scoped_client::<PeerManageRpcClientFactory<BaseController>>("".to_string())
            .await
            .with_context(|| "failed to get peer manager client")?)
    }

    async fn get_connector_manager_client(
        &self,
    ) -> Result<Box<dyn ConnectorManageRpc<Controller = BaseController>>, Error> {
        Ok(self
            .client
            .lock()
            .unwrap()
            .scoped_client::<ConnectorManageRpcClientFactory<BaseController>>("".to_string())
            .await
            .with_context(|| "failed to get connector manager client")?)
    }

    async fn get_peer_center_client(
        &self,
    ) -> Result<Box<dyn PeerCenterRpc<Controller = BaseController>>, Error> {
        Ok(self
            .client
            .lock()
            .unwrap()
            .scoped_client::<PeerCenterRpcClientFactory<BaseController>>("".to_string())
            .await
            .with_context(|| "failed to get peer center client")?)
    }

    async fn get_vpn_portal_client(
        &self,
    ) -> Result<Box<dyn VpnPortalRpc<Controller = BaseController>>, Error> {
        Ok(self
            .client
            .lock()
            .unwrap()
            .scoped_client::<VpnPortalRpcClientFactory<BaseController>>("".to_string())
            .await
            .with_context(|| "failed to get vpn portal client")?)
    }

    async fn get_tcp_proxy_client(
        &self,
        transport_type: &str,
    ) -> Result<Box<dyn TcpProxyRpc<Controller = BaseController>>, Error> {
        Ok(self
            .client
            .lock()
            .unwrap()
            .scoped_client::<TcpProxyRpcClientFactory<BaseController>>(transport_type.to_string())
            .await
            .with_context(|| "failed to get vpn portal client")?)
    }

    async fn list_peers(&self) -> Result<ListPeerResponse, Error> {
        let client = self.get_peer_manager_client().await?;
        let request = ListPeerRequest::default();
        let response = client.list_peer(BaseController::default(), request).await?;
        Ok(response)
    }

    async fn list_routes(&self) -> Result<ListRouteResponse, Error> {
        let client = self.get_peer_manager_client().await?;
        let request = ListRouteRequest::default();
        let response = client
            .list_route(BaseController::default(), request)
            .await?;
        Ok(response)
    }

    async fn list_peer_route_pair(&self) -> Result<Vec<PeerRoutePair>, Error> {
        let peers = self.list_peers().await?.peer_infos;
        let routes = self.list_routes().await?.routes;
        Ok(list_peer_route_pair(peers, routes))
    }

    #[allow(dead_code)]
    fn handle_peer_add(&self, _args: PeerArgs) {
        println!("add peer");
    }

    #[allow(dead_code)]
    fn handle_peer_remove(&self, _args: PeerArgs) {
        println!("remove peer");
    }

    async fn handle_peer_list(&self, _args: &PeerArgs) -> Result<(), Error> {
        #[derive(tabled::Tabled)]
        struct PeerTableItem {
            ipv4: String,
            hostname: String,
            cost: String,
            lat_ms: String,
            loss_rate: String,
            rx_bytes: String,
            tx_bytes: String,
            tunnel_proto: String,
            nat_type: String,
            id: String,
            version: String,
        }

        impl From<PeerRoutePair> for PeerTableItem {
            fn from(p: PeerRoutePair) -> Self {
                let route = p.route.clone().unwrap_or_default();
                PeerTableItem {
                    ipv4: route.ipv4_addr.map(|ip| ip.to_string()).unwrap_or_default(),
                    hostname: route.hostname.clone(),
                    cost: cost_to_str(route.cost),
                    lat_ms: if route.cost == 1 {
                        float_to_str(p.get_latency_ms().unwrap_or(0.0), 3)
                    } else {
                        route.path_latency_latency_first().to_string()
                    },
                    loss_rate: float_to_str(p.get_loss_rate().unwrap_or(0.0), 3),
                    rx_bytes: format_size(p.get_rx_bytes().unwrap_or(0), humansize::DECIMAL),
                    tx_bytes: format_size(p.get_tx_bytes().unwrap_or(0), humansize::DECIMAL),
                    tunnel_proto: p
                        .get_conn_protos()
                        .unwrap_or_default()
                        .join(",")
                        .to_string(),
                    nat_type: p.get_udp_nat_type(),
                    id: route.peer_id.to_string(),
                    version: if route.version.is_empty() {
                        "unknown".to_string()
                    } else {
                        route.version.to_string()
                    },
                }
            }
        }

        impl From<NodeInfo> for PeerTableItem {
            fn from(p: NodeInfo) -> Self {
                PeerTableItem {
                    ipv4: p.ipv4_addr.clone(),
                    hostname: p.hostname.clone(),
                    cost: "Local".to_string(),
                    lat_ms: "-".to_string(),
                    loss_rate: "-".to_string(),
                    rx_bytes: "-".to_string(),
                    tx_bytes: "-".to_string(),
                    tunnel_proto: "-".to_string(),
                    nat_type: if let Some(info) = p.stun_info {
                        info.udp_nat_type().as_str_name().to_string()
                    } else {
                        "Unknown".to_string()
                    },
                    id: p.peer_id.to_string(),
                    version: p.version,
                }
            }
        }

        let mut items: Vec<PeerTableItem> = vec![];
        let peer_routes = self.list_peer_route_pair().await?;
        if self.verbose {
            println!("{:#?}", peer_routes);
            return Ok(());
        }

        let client = self.get_peer_manager_client().await?;
        let node_info = client
            .show_node_info(BaseController::default(), ShowNodeInfoRequest::default())
            .await?
            .node_info
            .ok_or(anyhow::anyhow!("node info not found"))?;
        items.push(node_info.into());

        for p in peer_routes {
            items.push(p.into());
        }

        println!("{}", tabled::Table::new(items).with(Style::modern()));

        Ok(())
    }

    async fn handle_route_dump(&self) -> Result<(), Error> {
        let client = self.get_peer_manager_client().await?;
        let request = DumpRouteRequest::default();
        let response = client
            .dump_route(BaseController::default(), request)
            .await?;
        println!("response: {}", response.result);
        Ok(())
    }

    async fn handle_foreign_network_list(&self) -> Result<(), Error> {
        let client = self.get_peer_manager_client().await?;
        let request = ListForeignNetworkRequest::default();
        let response = client
            .list_foreign_network(BaseController::default(), request)
            .await?;
        let network_map = response;
        if self.verbose {
            println!("{:#?}", network_map);
            return Ok(());
        }

        for (idx, (k, v)) in network_map.foreign_networks.iter().enumerate() {
            println!("{} Network Name: {}", idx + 1, k);
            for peer in v.peers.iter() {
                println!(
                    "  peer_id: {}, peer_conn_count: {}, conns: [ {} ]",
                    peer.peer_id,
                    peer.conns.len(),
                    peer.conns
                        .iter()
                        .map(|conn| format!(
                            "remote_addr: {}, rx_bytes: {}, tx_bytes: {}, latency_us: {}",
                            conn.tunnel
                                .as_ref()
                                .map(|t| t.remote_addr.clone().unwrap_or_default())
                                .unwrap_or_default(),
                            conn.stats.as_ref().map(|s| s.rx_bytes).unwrap_or_default(),
                            conn.stats.as_ref().map(|s| s.tx_bytes).unwrap_or_default(),
                            conn.stats
                                .as_ref()
                                .map(|s| s.latency_us)
                                .unwrap_or_default(),
                        ))
                        .collect::<Vec<_>>()
                        .join("; ")
                );
            }
        }
        Ok(())
    }

    async fn handle_global_foreign_network_list(&self) -> Result<(), Error> {
        let client = self.get_peer_manager_client().await?;
        let request = ListGlobalForeignNetworkRequest::default();
        let response = client
            .list_global_foreign_network(BaseController::default(), request)
            .await?;
        if self.verbose {
            println!("{:#?}", response);
            return Ok(());
        }

        for (k, v) in response.foreign_networks.iter() {
            println!("Peer ID: {}", k);
            for n in v.foreign_networks.iter() {
                println!(
                    "  Network Name: {}, Last Updated: {}, Version: {}, PeerIds: {:?}",
                    n.network_name, n.last_updated, n.version, n.peer_ids
                );
            }
        }

        Ok(())
    }

    async fn handle_route_list(&self) -> Result<(), Error> {
        #[derive(tabled::Tabled)]
        struct RouteTableItem {
            ipv4: String,
            hostname: String,
            proxy_cidrs: String,

            next_hop_ipv4: String,
            next_hop_hostname: String,
            next_hop_lat: f64,
            path_len: i32,
            path_latency: i32,

            next_hop_ipv4_lat_first: String,
            next_hop_hostname_lat_first: String,
            path_len_lat_first: i32,
            path_latency_lat_first: i32,

            version: String,
        }

        let mut items: Vec<RouteTableItem> = vec![];
        let client = self.get_peer_manager_client().await?;
        let node_info = client
            .show_node_info(BaseController::default(), ShowNodeInfoRequest::default())
            .await?
            .node_info
            .ok_or(anyhow::anyhow!("node info not found"))?;

        items.push(RouteTableItem {
            ipv4: node_info.ipv4_addr.clone(),
            hostname: node_info.hostname.clone(),
            proxy_cidrs: node_info.proxy_cidrs.join(", "),

            next_hop_ipv4: "-".to_string(),
            next_hop_hostname: "Local".to_string(),
            next_hop_lat: 0.0,
            path_len: 0,
            path_latency: 0,

            next_hop_ipv4_lat_first: "-".to_string(),
            next_hop_hostname_lat_first: "Local".to_string(),
            path_len_lat_first: 0,
            path_latency_lat_first: 0,

            version: node_info.version.clone(),
        });
        let peer_routes = self.list_peer_route_pair().await?;
        for p in peer_routes.iter() {
            let Some(next_hop_pair) = peer_routes.iter().find(|pair| {
                pair.route.clone().unwrap_or_default().peer_id
                    == p.route.clone().unwrap_or_default().next_hop_peer_id
            }) else {
                continue;
            };

            let next_hop_pair_latency_first = peer_routes.iter().find(|pair| {
                pair.route.clone().unwrap_or_default().peer_id
                    == p.route
                        .clone()
                        .unwrap_or_default()
                        .next_hop_peer_id_latency_first
                        .unwrap_or_default()
            });

            let route = p.route.clone().unwrap_or_default();
            if route.cost == 1 {
                items.push(RouteTableItem {
                    ipv4: route.ipv4_addr.map(|ip| ip.to_string()).unwrap_or_default(),
                    hostname: route.hostname.clone(),
                    proxy_cidrs: route.proxy_cidrs.clone().join(",").to_string(),

                    next_hop_ipv4: "DIRECT".to_string(),
                    next_hop_hostname: "".to_string(),
                    next_hop_lat: next_hop_pair.get_latency_ms().unwrap_or(0.0),
                    path_len: route.cost,
                    path_latency: next_hop_pair.get_latency_ms().unwrap_or_default() as i32,

                    next_hop_ipv4_lat_first: next_hop_pair_latency_first
                        .map(|pair| pair.route.clone().unwrap_or_default().ipv4_addr)
                        .unwrap_or_default()
                        .map(|ip| ip.to_string())
                        .unwrap_or_default(),
                    next_hop_hostname_lat_first: next_hop_pair_latency_first
                        .map(|pair| pair.route.clone().unwrap_or_default().hostname)
                        .unwrap_or_default()
                        .clone(),
                    path_latency_lat_first: next_hop_pair_latency_first
                        .map(|pair| {
                            pair.route
                                .clone()
                                .unwrap_or_default()
                                .path_latency_latency_first
                                .unwrap_or_default()
                        })
                        .unwrap_or_default(),
                    path_len_lat_first: next_hop_pair_latency_first
                        .map(|pair| {
                            pair.route
                                .clone()
                                .unwrap_or_default()
                                .cost_latency_first
                                .unwrap_or_default()
                        })
                        .unwrap_or_default(),

                    version: if route.version.is_empty() {
                        "unknown".to_string()
                    } else {
                        route.version.to_string()
                    },
                });
            } else {
                items.push(RouteTableItem {
                    ipv4: route.ipv4_addr.map(|ip| ip.to_string()).unwrap_or_default(),
                    hostname: route.hostname.clone(),
                    proxy_cidrs: route.proxy_cidrs.clone().join(",").to_string(),
                    next_hop_ipv4: next_hop_pair
                        .route
                        .clone()
                        .unwrap_or_default()
                        .ipv4_addr
                        .map(|ip| ip.to_string())
                        .unwrap_or_default(),
                    next_hop_hostname: next_hop_pair
                        .route
                        .clone()
                        .unwrap_or_default()
                        .hostname
                        .clone(),
                    next_hop_lat: next_hop_pair.get_latency_ms().unwrap_or(0.0),
                    path_len: route.cost,
                    path_latency: p.route.clone().unwrap_or_default().path_latency as i32,

                    next_hop_ipv4_lat_first: next_hop_pair_latency_first
                        .map(|pair| pair.route.clone().unwrap_or_default().ipv4_addr)
                        .unwrap_or_default()
                        .map(|ip| ip.to_string())
                        .unwrap_or_default(),
                    next_hop_hostname_lat_first: next_hop_pair_latency_first
                        .map(|pair| pair.route.clone().unwrap_or_default().hostname)
                        .unwrap_or_default()
                        .clone(),
                    path_latency_lat_first: next_hop_pair_latency_first
                        .map(|pair| {
                            pair.route
                                .clone()
                                .unwrap_or_default()
                                .path_latency_latency_first
                                .unwrap_or_default()
                        })
                        .unwrap_or_default(),
                    path_len_lat_first: next_hop_pair_latency_first
                        .map(|pair| {
                            pair.route
                                .clone()
                                .unwrap_or_default()
                                .cost_latency_first
                                .unwrap_or_default()
                        })
                        .unwrap_or_default(),

                    version: if route.version.is_empty() {
                        "unknown".to_string()
                    } else {
                        route.version.to_string()
                    },
                });
            }
        }

        println!("{}", tabled::Table::new(items).with(Style::modern()));

        Ok(())
    }

    async fn handle_connector_list(&self) -> Result<(), Error> {
        let client = self.get_connector_manager_client().await?;
        let request = ListConnectorRequest::default();
        let response = client
            .list_connector(BaseController::default(), request)
            .await?;
        println!("response: {:#?}", response);
        Ok(())
    }
}

pub struct ServiceInstallOptions {
    pub program: PathBuf,
    pub args: Vec<OsString>,
    pub work_directory: PathBuf,
    pub disable_autostart: bool,
    pub description: Option<String>,
    pub display_name: Option<String>,
}
pub struct Service {
    lable: ServiceLabel,
    kind: ServiceManagerKind,
    service_manager: Box<dyn ServiceManager>,
}

impl Service {
    pub fn new(name: String) -> Result<Self, Error> {
        #[cfg(target_os = "windows")]
        let service_manager = Box::new(crate::win_service_manager::WinServiceManager::new()?);

        #[cfg(not(target_os = "windows"))]
        let service_manager = <dyn ServiceManager>::native()?;
        let kind = ServiceManagerKind::native()?;

        Ok(Self {
            lable: name.parse()?,
            kind,
            service_manager,
        })
    }

    pub fn install(&self, options: &ServiceInstallOptions) -> Result<(), Error> {
        let ctx = ServiceInstallCtx {
            label: self.lable.clone(),
            program: options.program.clone(),
            args: options.args.clone(),
            contents: self.make_install_content_option(options),
            autostart: !options.disable_autostart,
            username: None,
            working_directory: Some(options.work_directory.clone()),
            environment: None,
        };
        if self.status()? != ServiceStatus::NotInstalled {
            return Err(anyhow::anyhow!(
                "Service is already installed! Service Name: {}",
                self.lable
            ));
        }

        self.service_manager
            .install(ctx.clone())
            .map_err(|e| anyhow::anyhow!("failed to install service: {:?}", e))?;

        println!(
            "Service installed successfully! Service Name: {}",
            self.lable
        );

        Ok(())
    }

    pub fn uninstall(&self) -> Result<(), Error> {
        let ctx = ServiceUninstallCtx {
            label: self.lable.clone(),
        };
        let status = self.status()?;

        if status == ServiceStatus::NotInstalled {
            return Err(anyhow::anyhow!("Service is not installed"));
        }

        if status == ServiceStatus::Running {
            self.service_manager.stop(ServiceStopCtx {
                label: self.lable.clone(),
            })?;
        }

        self.service_manager
            .uninstall(ctx)
            .map_err(|e| anyhow::anyhow!("failed to uninstall service: {}", e))
    }

    pub fn status(&self) -> Result<ServiceStatus, Error> {
        let ctx = ServiceStatusCtx {
            label: self.lable.clone(),
        };
        let status = self.service_manager.status(ctx)?;

        Ok(status)
    }

    pub fn start(&self) -> Result<(), Error> {
        let ctx = ServiceStartCtx {
            label: self.lable.clone(),
        };
        let status = self.status()?;

        match status {
            ServiceStatus::Running => Err(anyhow::anyhow!("Service is already running")),
            ServiceStatus::Stopped(_) => {
                self.service_manager
                    .start(ctx)
                    .map_err(|e| anyhow::anyhow!("failed to start service: {}", e))?;
                Ok(())
            }
            ServiceStatus::NotInstalled => Err(anyhow::anyhow!("Service is not installed")),
        }
    }

    pub fn stop(&self) -> Result<(), Error> {
        let ctx = ServiceStopCtx {
            label: self.lable.clone(),
        };
        let status = self.status()?;

        match status {
            ServiceStatus::Running => {
                self.service_manager
                    .stop(ctx)
                    .map_err(|e| anyhow::anyhow!("failed to stop service: {}", e))?;
                Ok(())
            }
            ServiceStatus::Stopped(_) => Err(anyhow::anyhow!("Service is already stopped")),
            ServiceStatus::NotInstalled => Err(anyhow::anyhow!("Service is not installed")),
        }
    }

    fn make_install_content_option(&self, options: &ServiceInstallOptions) -> Option<String> {
        match self.kind {
            ServiceManagerKind::Systemd => Some(self.make_systemd_unit(options).unwrap()),
            ServiceManagerKind::Rcd => Some(self.make_rcd_script(options).unwrap()),
            ServiceManagerKind::OpenRc => Some(self.make_open_rc_script(options).unwrap()),
            _ => {
                #[cfg(target_os = "windows")]
                {
                    let win_options = win_service_manager::WinServiceInstallOptions {
                        description: options.description.clone(),
                        display_name: options.display_name.clone(),
                        dependencies: Some(vec!["rpcss".to_string(), "dnscache".to_string()]),
                    };

                    Some(serde_json::to_string(&win_options).unwrap())
                }

                #[cfg(not(target_os = "windows"))]
                None
            }
        }
    }

    fn make_systemd_unit(
        &self,
        options: &ServiceInstallOptions,
    ) -> Result<String, std::fmt::Error> {
        let args = options
            .args
            .iter()
            .map(|a| a.to_string_lossy())
            .collect::<Vec<_>>()
            .join(" ");
        let target_app = options.program.display().to_string();
        let work_dir = options.work_directory.display().to_string();
        let mut unit_content = String::new();

        writeln!(unit_content, "[Unit]")?;
        writeln!(unit_content, "After=network.target syslog.target")?;
        if let Some(ref d) = options.description {
            writeln!(unit_content, "Description={d}")?;
        }
        writeln!(unit_content, "StartLimitIntervalSec=0")?;
        writeln!(unit_content)?;
        writeln!(unit_content, "[Service]")?;
        writeln!(unit_content, "Type=simple")?;
        writeln!(unit_content, "WorkingDirectory={work_dir}")?;
        writeln!(unit_content, "ExecStart={target_app} {args}")?;
        writeln!(unit_content, "Restart=always")?;
        writeln!(unit_content, "RestartSec=1")?;
        writeln!(unit_content, "LimitNOFILE=infinity")?;
        writeln!(unit_content)?;
        writeln!(unit_content, "[Install]")?;
        writeln!(unit_content, "WantedBy=multi-user.target")?;

        std::result::Result::Ok(unit_content)
    }

    fn make_rcd_script(&self, options: &ServiceInstallOptions) -> Result<String, std::fmt::Error> {
        let name = self.lable.to_qualified_name();
        let args = options
            .args
            .iter()
            .map(|a| a.to_string_lossy())
            .collect::<Vec<_>>()
            .join(" ");
        let target_app = options.program.display().to_string();
        let work_dir = options.work_directory.display().to_string();
        let mut script = String::new();

        writeln!(script, "#!/bin/sh")?;
        writeln!(script, "#")?;
        writeln!(script, "# PROVIDE: {name}")?;
        writeln!(script, "# REQUIRE: LOGIN FILESYSTEMS NETWORKING ")?;
        writeln!(script, "# KEYWORD: shutdown")?;
        writeln!(script)?;
        writeln!(script, ". /etc/rc.subr")?;
        writeln!(script)?;
        writeln!(script, "name=\"{name}\"")?;
        if let Some(ref d) = options.description {
            writeln!(script, "desc=\"{d}\"")?;
        }
        writeln!(script, "rcvar=\"{name}_enable\"")?;
        writeln!(script)?;
        writeln!(script, "load_rc_config ${{name}}")?;
        writeln!(script)?;
        writeln!(script, ": ${{{name}_options=\"{args}\"}}")?;
        writeln!(script)?;
        writeln!(script, "{name}_chdir=\"{work_dir}\"")?;
        writeln!(script, "pidfile=\"/var/run/${{name}}.pid\"")?;
        writeln!(script, "procname=\"{target_app}\"")?;
        writeln!(script, "command=\"/usr/sbin/daemon\"")?;
        writeln!(
            script,
            "command_args=\"-c -S -T ${{name}} -p ${{pidfile}} ${{procname}} ${{{name}_options}}\""
        )?;
        writeln!(script)?;
        writeln!(script, "run_rc_command \"$1\"")?;

        std::result::Result::Ok(script)
    }

    fn make_open_rc_script(
        &self,
        options: &ServiceInstallOptions,
    ) -> Result<String, std::fmt::Error> {
        let args = options
            .args
            .iter()
            .map(|a| a.to_string_lossy())
            .collect::<Vec<_>>()
            .join(" ");
        let target_app = options.program.display().to_string();
        let work_dir = options.work_directory.display().to_string();
        let mut script = String::new();

        writeln!(script, "#!/sbin/openrc-run")?;
        writeln!(script)?;
        if let Some(ref d) = options.description {
            writeln!(script, "description=\"{d}\"")?;
        }
        writeln!(script, "command=\"{target_app}\"")?;
        writeln!(script, "command_args=\"{args}\"")?;
        writeln!(script, "pidfile=\"/run/${{RC_SVCNAME}}.pid\"")?;
        writeln!(script, "command_background=\"yes\"")?;
        writeln!(script, "directory=\"{work_dir}\"")?;
        writeln!(script)?;
        writeln!(script, "depend() {{")?;
        writeln!(script, "    need net")?;
        writeln!(script, "    use looger")?;
        writeln!(script, "}}")?;

        std::result::Result::Ok(script)
    }
}

#[tokio::main]
#[tracing::instrument]
async fn main() -> Result<(), Error> {
    let cli = Cli::parse();
    let client = RpcClient::new(TcpTunnelConnector::new(
        format!("tcp://{}:{}", cli.rpc_portal.ip(), cli.rpc_portal.port())
            .parse()
            .unwrap(),
    ));
    let handler = CommandHandler {
        client: Mutex::new(client),
        verbose: cli.verbose,
    };

    match cli.sub_command {
        SubCommand::Peer(peer_args) => match &peer_args.sub_command {
            Some(PeerSubCommand::Add) => {
                println!("add peer");
            }
            Some(PeerSubCommand::Remove) => {
                println!("remove peer");
            }
            Some(PeerSubCommand::List(arg)) => {
                if arg.verbose {
                    println!("{:#?}", handler.list_peer_route_pair().await?);
                } else {
                    handler.handle_peer_list(&peer_args).await?;
                }
            }
            Some(PeerSubCommand::ListForeign) => {
                handler.handle_foreign_network_list().await?;
            }
            Some(PeerSubCommand::ListGlobalForeign) => {
                handler.handle_global_foreign_network_list().await?;
            }
            None => {
                handler.handle_peer_list(&peer_args).await?;
            }
        },
        SubCommand::Connector(conn_args) => match conn_args.sub_command {
            Some(ConnectorSubCommand::Add) => {
                println!("add connector");
            }
            Some(ConnectorSubCommand::Remove) => {
                println!("remove connector");
            }
            Some(ConnectorSubCommand::List) => {
                handler.handle_connector_list().await?;
            }
            None => {
                handler.handle_connector_list().await?;
            }
        },
        SubCommand::Route(route_args) => match route_args.sub_command {
            Some(RouteSubCommand::List) | None => handler.handle_route_list().await?,
            Some(RouteSubCommand::Dump) => handler.handle_route_dump().await?,
        },
        SubCommand::Stun => {
            timeout(Duration::from_secs(25), async move {
                let collector = StunInfoCollector::new_with_default_servers();
                loop {
                    let ret = collector.get_stun_info();
                    if ret.udp_nat_type != NatType::Unknown as i32 {
                        println!("stun info: {:#?}", ret);
                        break;
                    }
                    tokio::time::sleep(Duration::from_millis(200)).await;
                }
            })
            .await
            .unwrap();
        }
        SubCommand::PeerCenter => {
            let peer_center_client = handler.get_peer_center_client().await?;
            let resp = peer_center_client
                .get_global_peer_map(
                    BaseController::default(),
                    GetGlobalPeerMapRequest::default(),
                )
                .await?;

            #[derive(tabled::Tabled)]
            struct PeerCenterTableItem {
                node_id: String,
                direct_peers: String,
            }

            let mut table_rows = vec![];
            for (k, v) in resp.global_peer_map.iter() {
                let node_id = k;
                let direct_peers = v
                    .direct_peers
                    .iter()
                    .map(|(k, v)| format!("{}: {:?}ms", k, v.latency_ms,))
                    .collect::<Vec<_>>();
                table_rows.push(PeerCenterTableItem {
                    node_id: node_id.to_string(),
                    direct_peers: direct_peers.join("\n"),
                });
            }

            println!("{}", tabled::Table::new(table_rows).with(Style::modern()));
        }
        SubCommand::VpnPortal => {
            let vpn_portal_client = handler.get_vpn_portal_client().await?;
            let resp = vpn_portal_client
                .get_vpn_portal_info(
                    BaseController::default(),
                    GetVpnPortalInfoRequest::default(),
                )
                .await?
                .vpn_portal_info
                .unwrap_or_default();
            println!("portal_name: {}", resp.vpn_type);
            println!(
                r#"
############### client_config_start ###############
{}
############### client_config_end ###############
"#,
                resp.client_config
            );
            println!("connected_clients:\n{:#?}", resp.connected_clients);
        }
        SubCommand::Node(sub_cmd) => {
            let client = handler.get_peer_manager_client().await?;
            let node_info = client
                .show_node_info(BaseController::default(), ShowNodeInfoRequest::default())
                .await?
                .node_info
                .ok_or(anyhow::anyhow!("node info not found"))?;
            match sub_cmd.sub_command {
                Some(NodeSubCommand::Info) | None => {
                    let stun_info = node_info.stun_info.clone().unwrap_or_default();
                    let ip_list = node_info.ip_list.clone().unwrap_or_default();

                    let mut builder = tabled::builder::Builder::default();
                    builder.push_record(vec!["Virtual IP", node_info.ipv4_addr.as_str()]);
                    builder.push_record(vec!["Hostname", node_info.hostname.as_str()]);
                    builder.push_record(vec![
                        "Proxy CIDRs",
                        node_info.proxy_cidrs.join(", ").as_str(),
                    ]);
                    builder.push_record(vec!["Peer ID", node_info.peer_id.to_string().as_str()]);
                    stun_info.public_ip.iter().for_each(|ip| {
                        let Ok(ip) = ip.parse::<IpAddr>() else {
                            return;
                        };
                        if ip.is_ipv4() {
                            builder.push_record(vec!["Public IPv4", ip.to_string().as_str()]);
                        } else {
                            builder.push_record(vec!["Public IPv6", ip.to_string().as_str()]);
                        }
                    });
                    builder.push_record(vec![
                        "UDP Stun Type",
                        format!("{:?}", stun_info.udp_nat_type()).as_str(),
                    ]);
                    ip_list.interface_ipv4s.iter().for_each(|ip| {
                        builder.push_record(vec![
                            "Interface IPv4",
                            format!("{}", ip.to_string()).as_str(),
                        ]);
                    });
                    ip_list.interface_ipv6s.iter().for_each(|ip| {
                        builder.push_record(vec![
                            "Interface IPv6",
                            format!("{}", ip.to_string()).as_str(),
                        ]);
                    });
                    for (idx, l) in node_info.listeners.iter().enumerate() {
                        if l.starts_with("ring") {
                            continue;
                        }
                        builder.push_record(vec![format!("Listener {}", idx).as_str(), l]);
                    }

                    println!("{}", builder.build().with(Style::modern()));
                }
                Some(NodeSubCommand::Config) => {
                    println!("{}", node_info.config);
                }
            }
        }
        SubCommand::Service(service_args) => {
            let service = Service::new(service_args.name)?;
            match service_args.sub_command {
                ServiceSubCommand::Install(install_args) => {
                    let bin_path = install_args.core_path.unwrap_or_else(|| {
                        let mut ret = std::env::current_exe()
                            .unwrap()
                            .parent()
                            .unwrap()
                            .join("easytier-core");

                        if cfg!(target_os = "windows") {
                            ret.set_extension("exe");
                        }

                        ret
                    });
                    let bin_path = std::fs::canonicalize(bin_path).map_err(|e| {
                        anyhow::anyhow!("failed to get easytier core application: {}", e)
                    })?;
                    let bin_args = install_args.core_args.unwrap_or_default();
                    let work_dir = install_args.service_work_dir.unwrap_or_else(|| {
                        if cfg!(target_os = "windows") {
                            bin_path.parent().unwrap().to_path_buf()
                        } else {
                            std::env::temp_dir()
                        }
                    });

                    let work_dir = std::fs::canonicalize(&work_dir).map_err(|e| {
                        anyhow::anyhow!(
                            "failed to get service work directory[{}]: {}",
                            work_dir.display(),
                            e
                        )
                    })?;

                    if !work_dir.is_dir() {
                        return Err(anyhow::anyhow!("work directory is not a directory"));
                    }

                    let install_options = ServiceInstallOptions {
                        program: bin_path,
                        args: bin_args,
                        work_directory: work_dir,
                        disable_autostart: install_args.disable_autostart,
                        description: Some(install_args.description),
                        display_name: install_args.display_name,
                    };
                    service.install(&install_options)?;
                }
                ServiceSubCommand::Uninstall => {
                    service.uninstall()?;
                }
                ServiceSubCommand::Status => {
                    let status = service.status()?;
                    match status {
                        ServiceStatus::Running => println!("Service is running"),
                        ServiceStatus::Stopped(_) => println!("Service is stopped"),
                        ServiceStatus::NotInstalled => println!("Service is not installed"),
                    }
                }
                ServiceSubCommand::Start => {
                    service.start()?;
                }
                ServiceSubCommand::Stop => {
                    service.stop()?;
                }
            }
        }
        SubCommand::Proxy => {
            let mut entries = vec![];
            let client = handler.get_tcp_proxy_client("tcp").await?;
            let ret = client
                .list_tcp_proxy_entry(BaseController::default(), Default::default())
                .await;
            entries.extend(ret.unwrap_or_default().entries);

            let client = handler.get_tcp_proxy_client("kcp_src").await?;
            let ret = client
                .list_tcp_proxy_entry(BaseController::default(), Default::default())
                .await;
            entries.extend(ret.unwrap_or_default().entries);

            let client = handler.get_tcp_proxy_client("kcp_dst").await?;
            let ret = client
                .list_tcp_proxy_entry(BaseController::default(), Default::default())
                .await;
            entries.extend(ret.unwrap_or_default().entries);

            #[derive(tabled::Tabled)]
            struct TableItem {
                src: String,
                dst: String,
                start_time: String,
                state: String,
                transport_type: String,
            }

            let table_rows = entries
                .iter()
                .map(|e| TableItem {
                    src: SocketAddr::from(e.src.unwrap_or_default()).to_string(),
                    dst: SocketAddr::from(e.dst.unwrap_or_default()).to_string(),
                    start_time: chrono::DateTime::<chrono::Utc>::from_timestamp_millis(
                        (e.start_time * 1000) as i64,
                    )
                    .unwrap()
                    .with_timezone(&chrono::Local)
                    .format("%Y-%m-%d %H:%M:%S")
                    .to_string(),
                    state: format!("{:?}", TcpProxyEntryState::try_from(e.state).unwrap()),
                    transport_type: format!(
                        "{:?}",
                        TcpProxyEntryTransportType::try_from(e.transport_type).unwrap()
                    ),
                })
                .collect::<Vec<_>>();

            println!("{}", tabled::Table::new(table_rows).with(Style::modern()));
        }
    }

    Ok(())
}

#[cfg(target_os = "windows")]
mod win_service_manager {
    use std::{ffi::OsStr, ffi::OsString, io, path::PathBuf};
    use windows_service::{
        service::{
            ServiceAccess, ServiceDependency, ServiceErrorControl, ServiceInfo, ServiceStartType,
            ServiceType,
        },
        service_manager::{ServiceManager, ServiceManagerAccess},
    };

    use service_manager::{
        ServiceInstallCtx, ServiceLevel, ServiceStartCtx, ServiceStatus, ServiceStatusCtx,
        ServiceStopCtx, ServiceUninstallCtx,
    };

    use winreg::{enums::*, RegKey};

    use easytier::common::constants::WIN_SERVICE_WORK_DIR_REG_KEY;

    use serde::{Deserialize, Serialize};

    #[derive(Serialize, Deserialize)]
    pub struct WinServiceInstallOptions {
        pub dependencies: Option<Vec<String>>,
        pub description: Option<String>,
        pub display_name: Option<String>,
    }

    pub struct WinServiceManager {
        service_manager: ServiceManager,
    }

    impl WinServiceManager {
        pub fn new() -> Result<Self, crate::Error> {
            let service_manager =
                ServiceManager::local_computer(None::<&str>, ServiceManagerAccess::ALL_ACCESS)?;
            Ok(Self { service_manager })
        }
    }
    impl service_manager::ServiceManager for WinServiceManager {
        fn available(&self) -> io::Result<bool> {
            Ok(true)
        }

        fn install(&self, ctx: ServiceInstallCtx) -> io::Result<()> {
            let start_type_ = if ctx.autostart {
                ServiceStartType::AutoStart
            } else {
                ServiceStartType::OnDemand
            };
            let srv_name = OsString::from(ctx.label.to_qualified_name());
            let mut dis_name = srv_name.clone();
            let mut description: Option<OsString> = None;
            let mut dependencies = Vec::<ServiceDependency>::new();

            if let Some(s) = ctx.contents.as_ref() {
                let options: WinServiceInstallOptions = serde_json::from_str(s.as_str()).unwrap();
                if let Some(d) = options.dependencies {
                    dependencies = d
                        .iter()
                        .map(|dep| ServiceDependency::Service(OsString::from(dep.clone())))
                        .collect::<Vec<_>>();
                }
                if let Some(d) = options.description {
                    description = Some(OsString::from(d));
                }
                if let Some(d) = options.display_name {
                    dis_name = OsString::from(d);
                }
            }

            let service_info = ServiceInfo {
                name: srv_name,
                display_name: dis_name,
                service_type: ServiceType::OWN_PROCESS,
                start_type: start_type_,
                error_control: ServiceErrorControl::Normal,
                executable_path: ctx.program,
                launch_arguments: ctx.args,
                dependencies: dependencies.clone(),
                account_name: None,
                account_password: None,
            };

            let service = self
                .service_manager
                .create_service(&service_info, ServiceAccess::ALL_ACCESS)
                .map_err(|e| io::Error::new(io::ErrorKind::Other, e))?;

            if let Some(s) = description {
                service
                    .set_description(s.clone())
                    .map_err(|e| io::Error::new(io::ErrorKind::Other, e))?;
            }

            if let Some(work_dir) = ctx.working_directory {
                set_service_work_directory(&ctx.label.to_qualified_name(), work_dir)?;
            }

            Ok(())
        }

        fn uninstall(&self, ctx: ServiceUninstallCtx) -> io::Result<()> {
            let service = self
                .service_manager
                .open_service(ctx.label.to_qualified_name(), ServiceAccess::ALL_ACCESS)
                .map_err(|e| io::Error::new(io::ErrorKind::Other, e))?;

            service
                .delete()
                .map_err(|e| io::Error::new(io::ErrorKind::Other, e))
        }

        fn start(&self, ctx: ServiceStartCtx) -> io::Result<()> {
            let service = self
                .service_manager
                .open_service(ctx.label.to_qualified_name(), ServiceAccess::ALL_ACCESS)
                .map_err(|e| io::Error::new(io::ErrorKind::Other, e))?;

            service
                .start(&[] as &[&OsStr])
                .map_err(|e| io::Error::new(io::ErrorKind::Other, e))
        }

        fn stop(&self, ctx: ServiceStopCtx) -> io::Result<()> {
            let service = self
                .service_manager
                .open_service(ctx.label.to_qualified_name(), ServiceAccess::ALL_ACCESS)
                .map_err(|e| io::Error::new(io::ErrorKind::Other, e))?;

            _ = service
                .stop()
                .map_err(|e| io::Error::new(io::ErrorKind::Other, e))?;

            Ok(())
        }

        fn level(&self) -> ServiceLevel {
            ServiceLevel::System
        }

        fn set_level(&mut self, level: ServiceLevel) -> io::Result<()> {
            match level {
                ServiceLevel::System => Ok(()),
                _ => Err(io::Error::new(
                    io::ErrorKind::Other,
                    "Unsupported service level",
                )),
            }
        }

        fn status(&self, ctx: ServiceStatusCtx) -> io::Result<ServiceStatus> {
            let service = match self
                .service_manager
                .open_service(ctx.label.to_qualified_name(), ServiceAccess::QUERY_STATUS)
            {
                Ok(s) => s,
                Err(e) => {
                    if let windows_service::Error::Winapi(ref win_err) = e {
                        if win_err.raw_os_error() == Some(0x424) {
                            return Ok(ServiceStatus::NotInstalled);
                        }
                    }
                    return Err(io::Error::new(io::ErrorKind::Other, e));
                }
            };

            let status = service
                .query_status()
                .map_err(|e| io::Error::new(io::ErrorKind::Other, e))?;

            match status.current_state {
                windows_service::service::ServiceState::Stopped => Ok(ServiceStatus::Stopped(None)),
                _ => Ok(ServiceStatus::Running),
            }
        }
    }

    fn set_service_work_directory(service_name: &str, work_directory: PathBuf) -> io::Result<()> {
        let (reg_key, _) =
            RegKey::predef(HKEY_LOCAL_MACHINE).create_subkey(WIN_SERVICE_WORK_DIR_REG_KEY)?;
        reg_key
            .set_value::<OsString, _>(service_name, &work_directory.as_os_str().to_os_string())?;
        Ok(())
    }
}
