use clap::{command, Args, Parser, Subcommand};
use easytier_rpc::{
    connector_manage_rpc_client::ConnectorManageRpcClient,
    peer_manage_rpc_client::PeerManageRpcClient, ListConnectorRequest, ListPeerRequest,
    ListRouteRequest,
};

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

#[derive(Subcommand, Debug)]
enum PeerSubCommand {
    Add,
    Remove,
    List,
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

    #[allow(dead_code)]
    fn handle_peer_add(&self, _args: PeerArgs) {
        println!("add peer");
    }

    #[allow(dead_code)]
    fn handle_peer_remove(&self, _args: PeerArgs) {
        println!("remove peer");
    }

    async fn handle_peer_list(&self, _args: PeerArgs) -> Result<(), Error> {
        let mut client = self.get_peer_manager_client().await?;
        let request = tonic::Request::new(ListPeerRequest::default());
        let response = client.list_peer(request).await?;
        println!("response: {:#?}", response.into_inner());
        Ok(())
    }

    async fn handle_route_list(&self) -> Result<(), Error> {
        let mut client = self.get_peer_manager_client().await?;
        let request = tonic::Request::new(ListRouteRequest::default());
        let response = client.list_route(request).await?;
        println!("response: {:#?}", response.into_inner());
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
    println!("cli: {:?}", cli);

    let handler = CommandHandler {
        addr: "http://127.0.0.1:15888".to_string(),
    };

    match cli.sub_command {
        Some(SubCommand::Peer(peer_args)) => match peer_args.sub_command {
            Some(PeerSubCommand::Add) => {
                println!("add peer");
            }
            Some(PeerSubCommand::Remove) => {
                println!("remove peer");
            }
            Some(PeerSubCommand::List) => {
                handler.handle_peer_list(peer_args).await?;
            }
            None => {
                handler.handle_peer_list(peer_args).await?;
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
