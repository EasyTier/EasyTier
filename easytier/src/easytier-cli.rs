use std::{net::SocketAddr, sync::Mutex, time::Duration, vec};

use anyhow::{Context, Ok};
use clap::{command, Args, Parser, Subcommand};
use humansize::format_size;
use tabled::settings::Style;
use tokio::time::timeout;

use easytier::{
    common::{constants::EASYTIER_VERSION, stun::StunInfoCollector, stun::StunInfoCollectorTrait},
    proto::{
        cli::{
            ConnectorManageRpc, ConnectorManageRpcClientFactory, DumpRouteRequest,
            GetVpnPortalInfoRequest, ListConnectorRequest, ListForeignNetworkRequest,
            ListGlobalForeignNetworkRequest, ListPeerRequest, ListPeerResponse, ListRouteRequest,
            ListRouteResponse, NodeInfo, PeerManageRpc, PeerManageRpcClientFactory,
            ShowNodeInfoRequest, VpnPortalRpc, VpnPortalRpcClientFactory,
        },
        common::NatType,
        peer_rpc::{GetGlobalPeerMapRequest, PeerCenterRpc, PeerCenterRpcClientFactory},
        rpc_impl::standalone::StandAloneClient,
        rpc_types::controller::BaseController,
    },
    tunnel::tcp::TcpTunnelConnector,
    utils::{cost_to_str, float_to_str, list_peer_route_pair, PeerRoutePair},
};

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
    Peer(PeerArgs),
    Connector(ConnectorArgs),
    Stun,
    Route(RouteArgs),
    PeerCenter,
    VpnPortal,
    Node(NodeArgs),
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
    Info,
    Config,
}

#[derive(Args, Debug)]
struct NodeArgs {
    #[command(subcommand)]
    sub_command: Option<NodeSubCommand>,
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
                PeerTableItem {
                    ipv4: p
                        .route
                        .ipv4_addr
                        .clone()
                        .map(|ip| ip.to_string())
                        .unwrap_or_default(),
                    hostname: p.route.hostname.clone(),
                    cost: cost_to_str(p.route.cost),
                    lat_ms: float_to_str(p.get_latency_ms().unwrap_or(0.0), 3),
                    loss_rate: float_to_str(p.get_loss_rate().unwrap_or(0.0), 3),
                    rx_bytes: format_size(p.get_rx_bytes().unwrap_or(0), humansize::DECIMAL),
                    tx_bytes: format_size(p.get_tx_bytes().unwrap_or(0), humansize::DECIMAL),
                    tunnel_proto: p.get_conn_protos().unwrap_or(vec![]).join(",").to_string(),
                    nat_type: p.get_udp_nat_type(),
                    id: p.route.peer_id.to_string(),
                    version: if p.route.version.is_empty() {
                        "unknown".to_string()
                    } else {
                        p.route.version.to_string()
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

        println!(
            "{}",
            tabled::Table::new(items).with(Style::modern()).to_string()
        );

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
            cost: i32,
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
            cost: 0,
            version: node_info.version.clone(),
        });
        let peer_routes = self.list_peer_route_pair().await?;
        for p in peer_routes.iter() {
            let Some(next_hop_pair) = peer_routes
                .iter()
                .find(|pair| pair.route.peer_id == p.route.next_hop_peer_id)
            else {
                continue;
            };

            if p.route.cost == 1 {
                items.push(RouteTableItem {
                    ipv4: p
                        .route
                        .ipv4_addr
                        .clone()
                        .map(|ip| ip.to_string())
                        .unwrap_or_default(),
                    hostname: p.route.hostname.clone(),
                    proxy_cidrs: p.route.proxy_cidrs.clone().join(",").to_string(),
                    next_hop_ipv4: "DIRECT".to_string(),
                    next_hop_hostname: "".to_string(),
                    next_hop_lat: next_hop_pair.get_latency_ms().unwrap_or(0.0),
                    cost: p.route.cost,
                    version: if p.route.version.is_empty() {
                        "unknown".to_string()
                    } else {
                        p.route.version.to_string()
                    },
                });
            } else {
                items.push(RouteTableItem {
                    ipv4: p
                        .route
                        .ipv4_addr
                        .clone()
                        .map(|ip| ip.to_string())
                        .unwrap_or_default(),
                    hostname: p.route.hostname.clone(),
                    proxy_cidrs: p.route.proxy_cidrs.clone().join(",").to_string(),
                    next_hop_ipv4: next_hop_pair
                        .route
                        .ipv4_addr
                        .clone()
                        .map(|ip| ip.to_string())
                        .unwrap_or_default(),
                    next_hop_hostname: next_hop_pair.route.hostname.clone(),
                    next_hop_lat: next_hop_pair.get_latency_ms().unwrap_or(0.0),
                    cost: p.route.cost,
                    version: if p.route.version.is_empty() {
                        "unknown".to_string()
                    } else {
                        p.route.version.to_string()
                    },
                });
            }
        }

        println!(
            "{}",
            tabled::Table::new(items).with(Style::modern()).to_string()
        );

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

            println!(
                "{}",
                tabled::Table::new(table_rows)
                    .with(Style::modern())
                    .to_string()
            );
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

                    let mut builder = tabled::builder::Builder::default();
                    builder.push_record(vec!["Virtual IP", node_info.ipv4_addr.as_str()]);
                    builder.push_record(vec!["Hostname", node_info.hostname.as_str()]);
                    builder.push_record(vec![
                        "Proxy CIDRs",
                        node_info.proxy_cidrs.join(", ").as_str(),
                    ]);
                    builder.push_record(vec!["Peer ID", node_info.peer_id.to_string().as_str()]);
                    builder.push_record(vec!["Public IP", stun_info.public_ip.join(", ").as_str()]);
                    builder.push_record(vec![
                        "UDP Stun Type",
                        format!("{:?}", stun_info.udp_nat_type()).as_str(),
                    ]);
                    for (idx, l) in node_info.listeners.iter().enumerate() {
                        if l.starts_with("ring") {
                            continue;
                        }
                        builder.push_record(vec![format!("Listener {}", idx).as_str(), l]);
                    }

                    println!("{}", builder.build().with(Style::modern()).to_string());
                }
                Some(NodeSubCommand::Config) => {
                    println!("{}", node_info.config);
                }
            }
        }
    }

    Ok(())
}
