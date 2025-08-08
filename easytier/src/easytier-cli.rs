use std::{
    ffi::OsString,
    fmt::Write,
    net::{IpAddr, SocketAddr},
    path::PathBuf,
    str::FromStr,
    sync::Mutex,
    time::Duration,
    vec,
};

use anyhow::Context;
use cidr::Ipv4Inet;
use clap::{command, Args, CommandFactory, Parser, Subcommand};
use clap_complete::Shell;
use dashmap::DashMap;
use humansize::format_size;
use rust_i18n::t;
use service_manager::*;
use tabled::settings::Style;
use tokio::time::timeout;

use easytier::{
    common::{
        config::PortForwardConfig,
        constants::EASYTIER_VERSION,
        stun::{StunInfoCollector, StunInfoCollectorTrait},
    },
    proto::{
        cli::{
            list_peer_route_pair, AclManageRpc, AclManageRpcClientFactory, AddPortForwardRequest,
            ConnectorManageRpc, ConnectorManageRpcClientFactory, DumpRouteRequest,
            GetAclStatsRequest, GetPrometheusStatsRequest, GetStatsRequest, GetVpnPortalInfoRequest, GetWhitelistRequest, ListConnectorRequest,
            ListForeignNetworkRequest, ListGlobalForeignNetworkRequest, ListMappedListenerRequest,
            ListPeerRequest, ListPeerResponse, ListPortForwardRequest, ListRouteRequest,
            ListRouteResponse, ManageMappedListenerRequest, MappedListenerManageAction,
            MappedListenerManageRpc, MappedListenerManageRpcClientFactory, NodeInfo, PeerManageRpc,
            PeerManageRpcClientFactory, PortForwardManageRpc, PortForwardManageRpcClientFactory,
            RemovePortForwardRequest, SetWhitelistRequest, ShowNodeInfoRequest, StatsRpc, StatsRpcClientFactory, TcpProxyEntryState,
            TcpProxyEntryTransportType, TcpProxyRpc, TcpProxyRpcClientFactory, VpnPortalRpc,
            VpnPortalRpcClientFactory,
        },
        common::{NatType, SocketType},
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

    #[arg(
        short = 'o',
        long = "output",
        value_enum,
        default_value = "table",
        help = "output format"
    )]
    output_format: OutputFormat,

    #[command(subcommand)]
    sub_command: SubCommand,
}

#[derive(Subcommand, Debug)]
enum SubCommand {
    #[command(about = "show peers info")]
    Peer(PeerArgs),
    #[command(about = "manage connectors")]
    Connector(ConnectorArgs),
    #[command(about = "manage mapped listeners")]
    MappedListener(MappedListenerArgs),
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
    #[command(about = "show ACL rules statistics")]
    Acl(AclArgs),
    #[command(about = "manage port forwarding")]
    PortForward(PortForwardArgs),
    #[command(about = "manage TCP/UDP whitelist")]
    Whitelist(WhitelistArgs),
    #[command(about = "show statistics information")]
    Stats(StatsArgs),
    #[command(about = t!("core_clap.generate_completions").to_string())]
    GenAutocomplete { shell: Shell },
}

#[derive(clap::ValueEnum, Debug, Clone, PartialEq)]
enum OutputFormat {
    Table,
    Json,
}

#[derive(Args, Debug)]
struct PeerArgs {
    #[command(subcommand)]
    sub_command: Option<PeerSubCommand>,
}

#[derive(Subcommand, Debug)]
enum PeerSubCommand {
    Add,
    Remove,
    List,
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

#[derive(Args, Debug)]
struct MappedListenerArgs {
    #[command(subcommand)]
    sub_command: Option<MappedListenerSubCommand>,
}

#[derive(Subcommand, Debug)]
enum MappedListenerSubCommand {
    /// Add Mapped Listerner
    Add { url: String },
    /// Remove Mapped Listener
    Remove { url: String },
    /// List Existing Mapped Listener
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
struct AclArgs {
    #[command(subcommand)]
    sub_command: Option<AclSubCommand>,
}

#[derive(Subcommand, Debug)]
enum AclSubCommand {
    Stats,
}

#[derive(Args, Debug)]
struct PortForwardArgs {
    #[command(subcommand)]
    sub_command: Option<PortForwardSubCommand>,
}

#[derive(Subcommand, Debug)]
enum PortForwardSubCommand {
    /// Add port forward rule
    Add {
        #[arg(help = "Protocol (tcp/udp)")]
        protocol: String,
        #[arg(help = "Local bind address (e.g., 0.0.0.0:8080)")]
        bind_addr: String,
        #[arg(help = "Destination address (e.g., 10.1.1.1:80)")]
        dst_addr: String,
    },
    /// Remove port forward rule
    Remove {
        #[arg(help = "Protocol (tcp/udp)")]
        protocol: String,
        #[arg(help = "Local bind address (e.g., 0.0.0.0:8080)")]
        bind_addr: String,
        #[arg(help = "Optional Destination address (e.g., 10.1.1.1:80)")]
        dst_addr: Option<String>,
    },
    /// List port forward rules
    List,
}

#[derive(Args, Debug)]
struct WhitelistArgs {
    #[command(subcommand)]
    sub_command: Option<WhitelistSubCommand>,
}

#[derive(Subcommand, Debug)]
enum WhitelistSubCommand {
    /// Set TCP port whitelist
    SetTcp {
        #[arg(help = "TCP ports (e.g., 80,443,8000-9000)")]
        ports: String,
    },
    /// Set UDP port whitelist
    SetUdp {
        #[arg(help = "UDP ports (e.g., 53,5000-6000)")]
        ports: String,
    },
    /// Clear TCP whitelist
    ClearTcp,
    /// Clear UDP whitelist
    ClearUdp,
    /// Show current whitelist configuration
    Show,
}

#[derive(Args, Debug)]
struct StatsArgs {
    #[command(subcommand)]
    sub_command: Option<StatsSubCommand>,
}

#[derive(Subcommand, Debug)]
enum StatsSubCommand {
    /// Show general statistics
    Show,
    /// Show statistics in Prometheus format
    Prometheus,
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

    #[arg(long)]
    disable_autostart: Option<bool>,

    #[arg(long)]
    disable_restart_on_failure: Option<bool>,

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

struct CommandHandler<'a> {
    client: Mutex<RpcClient>,
    verbose: bool,
    output_format: &'a OutputFormat,
}

type RpcClient = StandAloneClient<TcpTunnelConnector>;

impl CommandHandler<'_> {
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

    async fn get_mapped_listener_manager_client(
        &self,
    ) -> Result<Box<dyn MappedListenerManageRpc<Controller = BaseController>>, Error> {
        Ok(self
            .client
            .lock()
            .unwrap()
            .scoped_client::<MappedListenerManageRpcClientFactory<BaseController>>("".to_string())
            .await
            .with_context(|| "failed to get mapped listener manager client")?)
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

    async fn get_acl_manager_client(
        &self,
    ) -> Result<Box<dyn AclManageRpc<Controller = BaseController>>, Error> {
        Ok(self
            .client
            .lock()
            .unwrap()
            .scoped_client::<AclManageRpcClientFactory<BaseController>>("".to_string())
            .await
            .with_context(|| "failed to get acl manager client")?)
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

    async fn get_port_forward_manager_client(
        &self,
    ) -> Result<Box<dyn PortForwardManageRpc<Controller = BaseController>>, Error> {
        Ok(self
            .client
            .lock()
            .unwrap()
            .scoped_client::<PortForwardManageRpcClientFactory<BaseController>>("".to_string())
            .await
            .with_context(|| "failed to get port forward manager client")?)
    }

    async fn get_stats_client(
        &self,
    ) -> Result<Box<dyn StatsRpc<Controller = BaseController>>, Error> {
        Ok(self
            .client
            .lock()
            .unwrap()
            .scoped_client::<StatsRpcClientFactory<BaseController>>("".to_string())
            .await
            .with_context(|| "failed to get stats client")?)
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

    async fn handle_peer_list(&self) -> Result<(), Error> {
        #[derive(tabled::Tabled, serde::Serialize)]
        struct PeerTableItem {
            #[tabled(rename = "ipv4")]
            cidr: String,
            #[tabled(skip)]
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
                    cidr: route.ipv4_addr.map(|ip| ip.to_string()).unwrap_or_default(),
                    ipv4: route
                        .ipv4_addr
                        .map(|ip: easytier::proto::common::Ipv4Inet| ip.address.unwrap_or_default())
                        .map(|ip| ip.to_string())
                        .unwrap_or_default(),
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
                    cidr: p.ipv4_addr.clone(),
                    ipv4: Ipv4Inet::from_str(&p.ipv4_addr)
                        .map(|ip| ip.address().to_string())
                        .unwrap_or_default(),
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
            println!("{}", serde_json::to_string_pretty(&peer_routes)?);
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

        // Sort items by ipv4 (using IpAddr for proper numeric comparison) first, then by hostname
        items.sort_by(|a, b| {
            use std::net::{IpAddr, Ipv4Addr};
            use std::str::FromStr;
            let a_ip = IpAddr::from_str(&a.ipv4).unwrap_or(IpAddr::V4(Ipv4Addr::UNSPECIFIED));
            let b_ip = IpAddr::from_str(&b.ipv4).unwrap_or(IpAddr::V4(Ipv4Addr::UNSPECIFIED));
            match a_ip.cmp(&b_ip) {
                std::cmp::Ordering::Equal => a.hostname.cmp(&b.hostname),
                other => other,
            }
        });

        print_output(&items, self.output_format)?;

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
        if self.verbose || *self.output_format == OutputFormat::Json {
            let json = serde_json::to_string_pretty(&network_map.foreign_networks)?;
            println!("{}", json);
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
        if self.verbose || *self.output_format == OutputFormat::Json {
            println!(
                "{}",
                serde_json::to_string_pretty(&response.foreign_networks)?
            );
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
        #[derive(tabled::Tabled, serde::Serialize)]
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
        let peer_routes = self.list_peer_route_pair().await?;

        if self.verbose {
            #[derive(serde::Serialize)]
            struct VerboseItem {
                node_info: NodeInfo,
                peer_routes: Vec<PeerRoutePair>,
            }
            println!(
                "{}",
                serde_json::to_string_pretty(&VerboseItem {
                    node_info,
                    peer_routes
                })?
            );
            return Ok(());
        }

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
            items.push(RouteTableItem {
                ipv4: route.ipv4_addr.map(|ip| ip.to_string()).unwrap_or_default(),
                hostname: route.hostname.clone(),
                proxy_cidrs: route.proxy_cidrs.clone().join(",").to_string(),
                next_hop_ipv4: if route.cost == 1 {
                    "DIRECT".to_string()
                } else {
                    next_hop_pair
                        .route
                        .clone()
                        .unwrap_or_default()
                        .ipv4_addr
                        .map(|ip| ip.to_string())
                        .unwrap_or_default()
                },
                next_hop_hostname: if route.cost == 1 {
                    "DIRECT".to_string()
                } else {
                    next_hop_pair
                        .route
                        .clone()
                        .unwrap_or_default()
                        .hostname
                        .clone()
                },
                next_hop_lat: next_hop_pair.get_latency_ms().unwrap_or(0.0),
                path_len: route.cost,
                path_latency: route.path_latency,

                next_hop_ipv4_lat_first: if route.cost_latency_first.unwrap_or_default() == 1 {
                    "DIRECT".to_string()
                } else {
                    next_hop_pair_latency_first
                        .map(|pair| pair.route.clone().unwrap_or_default().ipv4_addr)
                        .unwrap_or_default()
                        .map(|ip| ip.to_string())
                        .unwrap_or_default()
                },
                next_hop_hostname_lat_first: if route.cost_latency_first.unwrap_or_default() == 1 {
                    "DIRECT".to_string()
                } else {
                    next_hop_pair_latency_first
                        .map(|pair| pair.route.clone().unwrap_or_default().hostname)
                        .unwrap_or_default()
                        .clone()
                },
                path_latency_lat_first: route.path_latency_latency_first.unwrap_or_default(),
                path_len_lat_first: route.cost_latency_first.unwrap_or_default(),

                version: if route.version.is_empty() {
                    "unknown".to_string()
                } else {
                    route.version.to_string()
                },
            });
        }

        print_output(&items, self.output_format)?;

        Ok(())
    }

    async fn handle_connector_list(&self) -> Result<(), Error> {
        let client = self.get_connector_manager_client().await?;
        let request = ListConnectorRequest::default();
        let response = client
            .list_connector(BaseController::default(), request)
            .await?;
        if self.verbose || *self.output_format == OutputFormat::Json {
            println!("{}", serde_json::to_string_pretty(&response.connectors)?);
            return Ok(());
        }
        println!("response: {:#?}", response);
        Ok(())
    }

    async fn handle_acl_stats(&self) -> Result<(), Error> {
        let client = self.get_acl_manager_client().await?;
        let request = GetAclStatsRequest::default();
        let response = client
            .get_acl_stats(BaseController::default(), request)
            .await?;

        if let Some(acl_stats) = response.acl_stats {
            if self.output_format == &OutputFormat::Json {
                println!("{}", serde_json::to_string_pretty(&acl_stats)?);
            } else {
                println!("{}", acl_stats);
            }
        } else {
            println!("No ACL statistics available");
        }

        Ok(())
    }

    async fn handle_mapped_listener_list(&self) -> Result<(), Error> {
        let client = self.get_mapped_listener_manager_client().await?;
        let request = ListMappedListenerRequest::default();
        let response = client
            .list_mapped_listener(BaseController::default(), request)
            .await?;
        if self.verbose || *self.output_format == OutputFormat::Json {
            println!(
                "{}",
                serde_json::to_string_pretty(&response.mappedlisteners)?
            );
            return Ok(());
        }
        println!("response: {:#?}", response);
        Ok(())
    }

    async fn handle_mapped_listener_add(&self, url: &String) -> Result<(), Error> {
        let url = Self::mapped_listener_validate_url(url)?;
        let client = self.get_mapped_listener_manager_client().await?;
        let request = ManageMappedListenerRequest {
            action: MappedListenerManageAction::MappedListenerAdd as i32,
            url: Some(url.into()),
        };
        let _response = client
            .manage_mapped_listener(BaseController::default(), request)
            .await?;
        Ok(())
    }

    async fn handle_mapped_listener_remove(&self, url: &String) -> Result<(), Error> {
        let url = Self::mapped_listener_validate_url(url)?;
        let client = self.get_mapped_listener_manager_client().await?;
        let request = ManageMappedListenerRequest {
            action: MappedListenerManageAction::MappedListenerRemove as i32,
            url: Some(url.into()),
        };
        let _response = client
            .manage_mapped_listener(BaseController::default(), request)
            .await?;
        Ok(())
    }

    fn mapped_listener_validate_url(url: &String) -> Result<url::Url, Error> {
        let url = url::Url::parse(url)?;
        if url.scheme() != "tcp" && url.scheme() != "udp" {
            return Err(anyhow::anyhow!(
                "Url ({url}) must start with tcp:// or udp://"
            ));
        } else if url.port().is_none() {
            return Err(anyhow::anyhow!("Url ({url}) is missing port num"));
        }
        Ok(url)
    }

    async fn handle_port_forward_add(
        &self,
        protocol: &str,
        bind_addr: &str,
        dst_addr: &str,
    ) -> Result<(), Error> {
        let bind_addr: std::net::SocketAddr = bind_addr
            .parse()
            .with_context(|| format!("Invalid bind address: {}", bind_addr))?;
        let dst_addr: std::net::SocketAddr = dst_addr
            .parse()
            .with_context(|| format!("Invalid destination address: {}", dst_addr))?;

        if protocol != "tcp" && protocol != "udp" {
            return Err(anyhow::anyhow!("Protocol must be 'tcp' or 'udp'"));
        }

        let client = self.get_port_forward_manager_client().await?;
        let request = AddPortForwardRequest {
            cfg: Some(
                PortForwardConfig {
                    proto: protocol.to_string(),
                    bind_addr: bind_addr.into(),
                    dst_addr: dst_addr.into(),
                }
                .into(),
            ),
        };

        client
            .add_port_forward(BaseController::default(), request)
            .await?;
        println!(
            "Port forward rule added: {} {} -> {}",
            protocol, bind_addr, dst_addr
        );
        Ok(())
    }

    async fn handle_port_forward_remove(
        &self,
        protocol: &str,
        bind_addr: &str,
        dst_addr: Option<&str>,
    ) -> Result<(), Error> {
        let bind_addr: std::net::SocketAddr = bind_addr
            .parse()
            .with_context(|| format!("Invalid bind address: {}", bind_addr))?;

        if protocol != "tcp" && protocol != "udp" {
            return Err(anyhow::anyhow!("Protocol must be 'tcp' or 'udp'"));
        }

        let client = self.get_port_forward_manager_client().await?;
        let request = RemovePortForwardRequest {
            cfg: Some(
                PortForwardConfig {
                    proto: protocol.to_string(),
                    bind_addr: bind_addr.into(),
                    dst_addr: dst_addr
                        .map(|s| s.parse::<SocketAddr>().unwrap())
                        .map(Into::into)
                        .unwrap_or("0.0.0.0:0".parse::<SocketAddr>().unwrap().into()),
                }
                .into(),
            ),
        };

        client
            .remove_port_forward(BaseController::default(), request)
            .await?;
        println!("Port forward rule removed: {} {}", protocol, bind_addr);
        Ok(())
    }

    async fn handle_port_forward_list(&self) -> Result<(), Error> {
        let client = self.get_port_forward_manager_client().await?;
        let request = ListPortForwardRequest::default();
        let response = client
            .list_port_forward(BaseController::default(), request)
            .await?;

        if self.verbose || *self.output_format == OutputFormat::Json {
            println!("{}", serde_json::to_string_pretty(&response)?);
            return Ok(());
        }

        #[derive(tabled::Tabled, serde::Serialize)]
        struct PortForwardTableItem {
            protocol: String,
            bind_addr: String,
            dst_addr: String,
        }

        let items: Vec<PortForwardTableItem> = response
            .cfgs
            .into_iter()
            .map(|rule| PortForwardTableItem {
                protocol: format!(
                    "{:?}",
                    SocketType::try_from(rule.socket_type).unwrap_or(SocketType::Tcp)
                ),
                bind_addr: rule
                    .bind_addr
                    .map(|addr| addr.to_string())
                    .unwrap_or_default(),
                dst_addr: rule
                    .dst_addr
                    .map(|addr| addr.to_string())
                    .unwrap_or_default(),
            })
            .collect();

        print_output(&items, self.output_format)?;
        Ok(())
    }

    async fn handle_whitelist_set_tcp(&self, ports: &str) -> Result<(), Error> {
        let tcp_ports = Self::parse_port_list(ports)?;
        let client = self.get_acl_manager_client().await?;

        // Get current UDP ports to preserve them
        let current = client
            .get_whitelist(BaseController::default(), GetWhitelistRequest::default())
            .await?;
        let request = SetWhitelistRequest {
            tcp_ports,
            udp_ports: current.udp_ports,
        };

        client
            .set_whitelist(BaseController::default(), request)
            .await?;
        println!("TCP whitelist updated: {}", ports);
        Ok(())
    }

    async fn handle_whitelist_set_udp(&self, ports: &str) -> Result<(), Error> {
        let udp_ports = Self::parse_port_list(ports)?;
        let client = self.get_acl_manager_client().await?;

        // Get current TCP ports to preserve them
        let current = client
            .get_whitelist(BaseController::default(), GetWhitelistRequest::default())
            .await?;
        let request = SetWhitelistRequest {
            tcp_ports: current.tcp_ports,
            udp_ports,
        };

        client
            .set_whitelist(BaseController::default(), request)
            .await?;
        println!("UDP whitelist updated: {}", ports);
        Ok(())
    }

    async fn handle_whitelist_clear_tcp(&self) -> Result<(), Error> {
        let client = self.get_acl_manager_client().await?;

        // Get current UDP ports to preserve them
        let current = client
            .get_whitelist(BaseController::default(), GetWhitelistRequest::default())
            .await?;
        let request = SetWhitelistRequest {
            tcp_ports: vec![],
            udp_ports: current.udp_ports,
        };

        client
            .set_whitelist(BaseController::default(), request)
            .await?;
        println!("TCP whitelist cleared");
        Ok(())
    }

    async fn handle_whitelist_clear_udp(&self) -> Result<(), Error> {
        let client = self.get_acl_manager_client().await?;

        // Get current TCP ports to preserve them
        let current = client
            .get_whitelist(BaseController::default(), GetWhitelistRequest::default())
            .await?;
        let request = SetWhitelistRequest {
            tcp_ports: current.tcp_ports,
            udp_ports: vec![],
        };

        client
            .set_whitelist(BaseController::default(), request)
            .await?;
        println!("UDP whitelist cleared");
        Ok(())
    }

    async fn handle_whitelist_show(&self) -> Result<(), Error> {
        let client = self.get_acl_manager_client().await?;
        let request = GetWhitelistRequest::default();
        let response = client
            .get_whitelist(BaseController::default(), request)
            .await?;

        if self.verbose || *self.output_format == OutputFormat::Json {
            println!("{}", serde_json::to_string_pretty(&response)?);
            return Ok(());
        }

        println!(
            "TCP Whitelist: {}",
            if response.tcp_ports.is_empty() {
                "None".to_string()
            } else {
                response.tcp_ports.join(", ")
            }
        );

        println!(
            "UDP Whitelist: {}",
            if response.udp_ports.is_empty() {
                "None".to_string()
            } else {
                response.udp_ports.join(", ")
            }
        );

        Ok(())
    }

    fn parse_port_list(ports_str: &str) -> Result<Vec<String>, Error> {
        let mut ports = Vec::new();
        for port_spec in ports_str.split(',') {
            let port_spec = port_spec.trim();
            if port_spec.contains('-') {
                // Handle port range
                let parts: Vec<&str> = port_spec.split('-').collect();
                if parts.len() != 2 {
                    return Err(anyhow::anyhow!("Invalid port range: {}", port_spec));
                }
                let start: u16 = parts[0]
                    .parse()
                    .with_context(|| format!("Invalid start port: {}", parts[0]))?;
                let end: u16 = parts[1]
                    .parse()
                    .with_context(|| format!("Invalid end port: {}", parts[1]))?;
                if start > end {
                    return Err(anyhow::anyhow!("Invalid port range: start > end"));
                }
                ports.push(format!("{}-{}", start, end));
            } else {
                // Handle single port
                let port: u16 = port_spec
                    .parse()
                    .with_context(|| format!("Invalid port number: {}", port_spec))?;
                ports.push(port.to_string());
            }
        }
        Ok(ports)
    }
}

#[derive(Debug)]
pub struct ServiceInstallOptions {
    pub program: PathBuf,
    pub args: Vec<OsString>,
    pub work_directory: PathBuf,
    pub disable_autostart: bool,
    pub description: Option<String>,
    pub display_name: Option<String>,
    pub disable_restart_on_failure: bool,
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

        println!("service manager kind: {:?}", kind);

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
            disable_restart_on_failure: options.disable_restart_on_failure,
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

fn print_output<T>(items: &[T], format: &OutputFormat) -> Result<(), Error>
where
    T: tabled::Tabled + serde::Serialize,
{
    match format {
        OutputFormat::Table => {
            println!("{}", tabled::Table::new(items).with(Style::modern()));
        }
        OutputFormat::Json => {
            println!("{}", serde_json::to_string_pretty(items)?);
        }
    }
    Ok(())
}

#[tokio::main]
#[tracing::instrument]
async fn main() -> Result<(), Error> {
    let locale = sys_locale::get_locale().unwrap_or_else(|| String::from("en-US"));
    rust_i18n::set_locale(&locale);
    let cli = Cli::parse();

    let client = RpcClient::new(TcpTunnelConnector::new(
        format!("tcp://{}:{}", cli.rpc_portal.ip(), cli.rpc_portal.port())
            .parse()
            .unwrap(),
    ));
    let handler = CommandHandler {
        client: Mutex::new(client),
        verbose: cli.verbose,
        output_format: &cli.output_format,
    };

    match cli.sub_command {
        SubCommand::Peer(peer_args) => match &peer_args.sub_command {
            Some(PeerSubCommand::Add) => {
                println!("add peer");
            }
            Some(PeerSubCommand::Remove) => {
                println!("remove peer");
            }
            Some(PeerSubCommand::List) => {
                handler.handle_peer_list().await?;
            }
            Some(PeerSubCommand::ListForeign) => {
                handler.handle_foreign_network_list().await?;
            }
            Some(PeerSubCommand::ListGlobalForeign) => {
                handler.handle_global_foreign_network_list().await?;
            }
            None => {
                handler.handle_peer_list().await?;
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
        SubCommand::MappedListener(mapped_listener_args) => {
            match mapped_listener_args.sub_command {
                Some(MappedListenerSubCommand::Add { url }) => {
                    handler.handle_mapped_listener_add(&url).await?;
                    println!("add mapped listener: {url}");
                }
                Some(MappedListenerSubCommand::Remove { url }) => {
                    handler.handle_mapped_listener_remove(&url).await?;
                    println!("remove mapped listener: {url}");
                }
                Some(MappedListenerSubCommand::List) | None => {
                    handler.handle_mapped_listener_list().await?;
                }
            }
        }
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
                        if cli.output_format == OutputFormat::Json {
                            match serde_json::to_string_pretty(&ret) {
                                Ok(json) => println!("{}", json),
                                Err(e) => eprintln!("Error serializing to JSON: {}", e),
                            }
                        } else {
                            println!("stun info: {:#?}", ret);
                        }
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
            let route_infos = handler.list_peer_route_pair().await?;
            struct PeerCenterNodeInfo {
                hostname: String,
                ipv4: String,
            }
            let node_id_to_node_info = DashMap::new();
            let node_info = handler
                .get_peer_manager_client()
                .await?
                .show_node_info(BaseController::default(), ShowNodeInfoRequest::default())
                .await?
                .node_info
                .ok_or(anyhow::anyhow!("node info not found"))?;
            node_id_to_node_info.insert(
                node_info.peer_id,
                PeerCenterNodeInfo {
                    hostname: node_info.hostname.clone(),
                    ipv4: node_info.ipv4_addr.clone(),
                },
            );
            for route_info in route_infos {
                let Some(peer_id) = route_info.route.as_ref().map(|x| x.peer_id) else {
                    continue;
                };
                node_id_to_node_info.insert(
                    peer_id,
                    PeerCenterNodeInfo {
                        hostname: route_info
                            .route
                            .as_ref()
                            .map(|x| x.hostname.clone())
                            .unwrap_or_default(),
                        ipv4: route_info
                            .route
                            .as_ref()
                            .and_then(|x| x.ipv4_addr)
                            .map(|x| x.to_string())
                            .unwrap_or_default(),
                    },
                );
            }

            #[derive(tabled::Tabled, serde::Serialize)]
            struct PeerCenterTableItem {
                node_id: String,
                hostname: String,
                ipv4: String,
                #[tabled(rename = "direct_peers")]
                #[serde(skip_serializing)]
                direct_peers_str: String,
                #[tabled(skip)]
                direct_peers: Vec<DirectPeerItem>,
            }

            #[derive(serde::Serialize)]
            struct DirectPeerItem {
                node_id: String,
                hostname: String,
                ipv4: String,
                latency_ms: i32,
            }

            let mut table_rows = vec![];
            for (k, v) in resp.global_peer_map.iter() {
                let node_id = k;
                let direct_peers: Vec<_> = v
                    .direct_peers
                    .iter()
                    .map(|(k, v)| DirectPeerItem {
                        node_id: k.to_string(),
                        hostname: node_id_to_node_info
                            .get(k)
                            .map(|x| x.hostname.clone())
                            .unwrap_or_default(),
                        ipv4: node_id_to_node_info
                            .get(k)
                            .map(|x| x.ipv4.clone())
                            .unwrap_or_default(),
                        latency_ms: v.latency_ms,
                    })
                    .collect();
                let direct_peers_strs = direct_peers
                    .iter()
                    .map(|x| {
                        format!(
                            "{}({}[{}]): {}ms",
                            x.node_id, x.hostname, x.ipv4, x.latency_ms,
                        )
                    })
                    .collect::<Vec<_>>();

                table_rows.push(PeerCenterTableItem {
                    node_id: node_id.to_string(),
                    hostname: node_id_to_node_info
                        .get(node_id)
                        .map(|x| x.hostname.clone())
                        .unwrap_or_default(),
                    ipv4: node_id_to_node_info
                        .get(node_id)
                        .map(|x| x.ipv4.clone())
                        .unwrap_or_default(),
                    direct_peers_str: direct_peers_strs.join("\n"),
                    direct_peers,
                });
            }

            print_output(&table_rows, &cli.output_format)?;
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
                    if cli.verbose || cli.output_format == OutputFormat::Json {
                        println!("{}", serde_json::to_string_pretty(&node_info)?);
                        return Ok(());
                    }

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
                        disable_autostart: install_args.disable_autostart.unwrap_or(false),
                        description: Some(install_args.description),
                        display_name: install_args.display_name,
                        disable_restart_on_failure: install_args
                            .disable_restart_on_failure
                            .unwrap_or(false),
                    };
                    println!("install_options: {:#?}", install_options);
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

            for client_type in &["tcp", "kcp_src", "kcp_dst", "quic_src", "quic_dst"] {
                let client = handler.get_tcp_proxy_client(client_type).await?;
                let ret = client
                    .list_tcp_proxy_entry(BaseController::default(), Default::default())
                    .await;
                entries.extend(ret.unwrap_or_default().entries);
            }

            if cli.verbose {
                println!("{}", serde_json::to_string_pretty(&entries)?);
                return Ok(());
            }

            #[derive(tabled::Tabled, serde::Serialize)]
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

            print_output(&table_rows, &cli.output_format)?;
        }
        SubCommand::Acl(acl_args) => match &acl_args.sub_command {
            Some(AclSubCommand::Stats) | None => {
                handler.handle_acl_stats().await?;
            }
        },
        SubCommand::PortForward(port_forward_args) => match &port_forward_args.sub_command {
            Some(PortForwardSubCommand::Add {
                protocol,
                bind_addr,
                dst_addr,
            }) => {
                handler
                    .handle_port_forward_add(protocol, bind_addr, dst_addr)
                    .await?;
            }
            Some(PortForwardSubCommand::Remove {
                protocol,
                bind_addr,
                dst_addr,
            }) => {
                handler
                    .handle_port_forward_remove(protocol, bind_addr, dst_addr.as_deref())
                    .await?;
            }
            Some(PortForwardSubCommand::List) | None => {
                handler.handle_port_forward_list().await?;
            }
        },
        SubCommand::Whitelist(whitelist_args) => match &whitelist_args.sub_command {
            Some(WhitelistSubCommand::SetTcp { ports }) => {
                handler.handle_whitelist_set_tcp(ports).await?;
            }
            Some(WhitelistSubCommand::SetUdp { ports }) => {
                handler.handle_whitelist_set_udp(ports).await?;
            }
            Some(WhitelistSubCommand::ClearTcp) => {
                handler.handle_whitelist_clear_tcp().await?;
            }
            Some(WhitelistSubCommand::ClearUdp) => {
                handler.handle_whitelist_clear_udp().await?;
            }
            Some(WhitelistSubCommand::Show) | None => {
                handler.handle_whitelist_show().await?;
            }
        },
        SubCommand::Stats(stats_args) => match &stats_args.sub_command {
            Some(StatsSubCommand::Show) | None => {
                let client = handler.get_stats_client().await?;
                let request = GetStatsRequest {};
                let response = client
                    .get_stats(BaseController::default(), request)
                    .await?;

                if cli.output_format == OutputFormat::Json {
                    println!("{}", serde_json::to_string_pretty(&response.metrics)?);
                } else {
                    #[derive(tabled::Tabled, serde::Serialize)]
                    struct StatsTableRow {
                        #[tabled(rename = "Metric Name")]
                        name: String,
                        #[tabled(rename = "Value")]
                        value: String,
                        #[tabled(rename = "Labels")]
                        labels: String,
                    }

                    let table_rows: Vec<StatsTableRow> = response
                        .metrics
                        .iter()
                        .map(|metric| {
                            let labels_str = if metric.labels.is_empty() {
                                "-".to_string()
                            } else {
                                metric
                                    .labels
                                    .iter()
                                    .map(|(k, v)| format!("{}={}", k, v))
                                    .collect::<Vec<_>>()
                                    .join(", ")
                            };
                            
                            let formatted_value = if metric.name.contains("bytes") {
                                format_size(metric.value, humansize::BINARY)
                            } else if metric.name.contains("duration") {
                                format!("{} ms", metric.value)
                            } else {
                                metric.value.to_string()
                            };

                            StatsTableRow {
                                name: metric.name.clone(),
                                value: formatted_value,
                                labels: labels_str,
                            }
                        })
                        .collect();

                    print_output(&table_rows, &cli.output_format)?
                }
            }
            Some(StatsSubCommand::Prometheus) => {
                let client = handler.get_stats_client().await?;
                let request = GetPrometheusStatsRequest {};
                let response = client
                    .get_prometheus_stats(BaseController::default(), request)
                    .await?;

                println!("{}", response.prometheus_text);
            }
        },
        SubCommand::GenAutocomplete { shell } => {
            let mut cmd = Cli::command();
            easytier::print_completions(shell, &mut cmd, "easytier-cli");
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
