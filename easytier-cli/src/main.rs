use std::vec;

use clap::{command, Args, Parser, Subcommand};
use easytier_core::rpc::{
    connector_manage_rpc_client::ConnectorManageRpcClient,
    peer_manage_rpc_client::PeerManageRpcClient, *,
};
use humansize::format_size;
use tabled::settings::Style;

#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Cli {
    /// the instance name
    #[arg(short = 'n', long, default_value = "default")]
    instance_name: String,

    #[command(subcommand)]
    sub_command: Option<SubCommand>,
}

#[derive(Subcommand, Debug)]
enum SubCommand {
    Peer(PeerArgs),
    Connector(ConnectorArgs),
    Route,
}

#[derive(Args, Debug)]
struct PeerArgs {
    #[arg(short, long)]
    ipv4: Option<String>,

    #[arg(short, long)]
    peers: Vec<String>,

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

#[derive(thiserror::Error, Debug)]
enum Error {
    #[error("tonic transport error")]
    TonicTransportError(#[from] tonic::transport::Error),
    #[error("tonic rpc error")]
    TonicRpcError(#[from] tonic::Status),
}

#[derive(Debug)]
struct PeerRoutePair {
    route: Route,
    peer: Option<PeerInfo>,
}

impl PeerRoutePair {
    fn get_latency_ms(&self) -> Option<f64> {
        let mut ret = u64::MAX;
        let p = self.peer.as_ref()?;
        for conn in p.conns.iter() {
            let Some(stats) = &conn.stats else {
                continue;
            };
            ret = ret.min(stats.latency_us);
        }

        if ret == u64::MAX {
            None
        } else {
            Some(f64::from(ret as u32) / 1000.0)
        }
    }

    fn get_rx_bytes(&self) -> Option<u64> {
        let mut ret = 0;
        let p = self.peer.as_ref()?;
        for conn in p.conns.iter() {
            let Some(stats) = &conn.stats else {
                continue;
            };
            ret += stats.rx_bytes;
        }

        if ret == 0 {
            None
        } else {
            Some(ret)
        }
    }

    fn get_tx_bytes(&self) -> Option<u64> {
        let mut ret = 0;
        let p = self.peer.as_ref()?;
        for conn in p.conns.iter() {
            let Some(stats) = &conn.stats else {
                continue;
            };
            ret += stats.tx_bytes;
        }

        if ret == 0 {
            None
        } else {
            Some(ret)
        }
    }

    fn get_loss_rate(&self) -> Option<f64> {
        let mut ret = 0.0;
        let p = self.peer.as_ref()?;
        for conn in p.conns.iter() {
            ret += conn.loss_rate;
        }

        if ret == 0.0 {
            None
        } else {
            Some(ret as f64)
        }
    }

    fn get_conn_protos(&self) -> Option<Vec<String>> {
        let mut ret = vec![];
        let p = self.peer.as_ref()?;
        for conn in p.conns.iter() {
            let Some(tunnel_info) = &conn.tunnel else {
                continue;
            };
            // insert if not exists
            if !ret.contains(&tunnel_info.tunnel_type) {
                ret.push(tunnel_info.tunnel_type.clone());
            }
        }

        if ret.is_empty() {
            None
        } else {
            Some(ret)
        }
    }

    fn get_udp_nat_type(self: &Self) -> String {
        let mut ret = NatType::Unknown;
        if let Some(r) = &self.route.stun_info {
            ret = NatType::try_from(r.udp_nat_type).unwrap();
        }
        format!("{:?}", ret)
    }
}

struct CommandHandler {
    addr: String,
}

impl CommandHandler {
    async fn get_peer_manager_client(
        &self,
    ) -> Result<PeerManageRpcClient<tonic::transport::Channel>, Error> {
        Ok(PeerManageRpcClient::connect(self.addr.clone()).await?)
    }

    async fn get_connector_manager_client(
        &self,
    ) -> Result<ConnectorManageRpcClient<tonic::transport::Channel>, Error> {
        Ok(ConnectorManageRpcClient::connect(self.addr.clone()).await?)
    }

    async fn list_peers(&self) -> Result<ListPeerResponse, Error> {
        let mut client = self.get_peer_manager_client().await?;
        let request = tonic::Request::new(ListPeerRequest::default());
        let response = client.list_peer(request).await?;
        Ok(response.into_inner())
    }

    async fn list_routes(&self) -> Result<ListRouteResponse, Error> {
        let mut client = self.get_peer_manager_client().await?;
        let request = tonic::Request::new(ListRouteRequest::default());
        let response = client.list_route(request).await?;
        Ok(response.into_inner())
    }

    async fn list_peer_route_pair(&self) -> Result<Vec<PeerRoutePair>, Error> {
        let mut peers = self.list_peers().await?.peer_infos;
        let mut routes = self.list_routes().await?.routes;
        let mut pairs: Vec<PeerRoutePair> = vec![];

        for route in routes.iter_mut() {
            let peer = peers.iter_mut().find(|peer| peer.peer_id == route.peer_id);
            pairs.push(PeerRoutePair {
                route: route.clone(),
                peer: peer.cloned(),
            });
        }

        Ok(pairs)
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
            cost: i32,
            lat_ms: f64,
            loss_rate: f64,
            rx_bytes: String,
            tx_bytes: String,
            tunnel_proto: String,
            nat_type: String,
            id: String,
        }

        impl From<PeerRoutePair> for PeerTableItem {
            fn from(p: PeerRoutePair) -> Self {
                PeerTableItem {
                    ipv4: p.route.ipv4_addr.clone(),
                    hostname: p.route.hostname.clone(),
                    cost: p.route.cost,
                    lat_ms: p.get_latency_ms().unwrap_or(0.0),
                    loss_rate: p.get_loss_rate().unwrap_or(0.0),
                    rx_bytes: format_size(p.get_rx_bytes().unwrap_or(0), humansize::DECIMAL),
                    tx_bytes: format_size(p.get_tx_bytes().unwrap_or(0), humansize::DECIMAL),
                    tunnel_proto: p.get_conn_protos().unwrap_or(vec![]).join(",").to_string(),
                    nat_type: p.get_udp_nat_type(),
                    id: p.route.peer_id.clone(),
                }
            }
        }

        let mut items: Vec<PeerTableItem> = vec![];
        let peer_routes = self.list_peer_route_pair().await?;
        for p in peer_routes {
            items.push(p.into());
        }

        println!(
            "{}",
            tabled::Table::new(items).with(Style::modern()).to_string()
        );

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
        }

        let mut items: Vec<RouteTableItem> = vec![];
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
                    ipv4: p.route.ipv4_addr.clone(),
                    hostname: p.route.hostname.clone(),
                    proxy_cidrs: p.route.proxy_cidrs.clone().join(",").to_string(),
                    next_hop_ipv4: "DIRECT".to_string(),
                    next_hop_hostname: "".to_string(),
                    next_hop_lat: next_hop_pair.get_latency_ms().unwrap_or(0.0),
                    cost: p.route.cost,
                });
            } else {
                items.push(RouteTableItem {
                    ipv4: p.route.ipv4_addr.clone(),
                    hostname: p.route.hostname.clone(),
                    proxy_cidrs: p.route.proxy_cidrs.clone().join(",").to_string(),
                    next_hop_ipv4: next_hop_pair.route.ipv4_addr.clone(),
                    next_hop_hostname: next_hop_pair.route.hostname.clone(),
                    next_hop_lat: next_hop_pair.get_latency_ms().unwrap_or(0.0),
                    cost: p.route.cost,
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
        let mut client = self.get_connector_manager_client().await?;
        let request = tonic::Request::new(ListConnectorRequest::default());
        let response = client.list_connector(request).await?;
        println!("response: {:#?}", response.into_inner());
        Ok(())
    }
}

#[tokio::main]
async fn main() -> Result<(), Error> {
    let cli = Cli::parse();
    let handler = CommandHandler {
        addr: "http://127.0.0.1:15888".to_string(),
    };

    match cli.sub_command {
        Some(SubCommand::Peer(peer_args)) => match &peer_args.sub_command {
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
            None => {
                handler.handle_peer_list(&peer_args).await?;
            }
        },
        Some(SubCommand::Connector(conn_args)) => match conn_args.sub_command {
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
        Some(SubCommand::Route) => {
            handler.handle_route_list().await?;
        }
        None => {
            println!("list peer");
        }
    }

    Ok(())
}
