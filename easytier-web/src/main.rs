use std::net::SocketAddr;

use easytier::tunnel::udp::UdpTunnelListener;
use tokio::net::TcpListener;

mod client_manager;
mod restful;

#[tokio::main]
async fn main() {
    let listener = UdpTunnelListener::new("udp://0.0.0.0:11210".parse().unwrap());
    let mut mgr = client_manager::ClientManager::new(Box::new(listener));
    mgr.serve().await.unwrap();

    let mut restful_server = restful::RestfulServer::new("0.0.0.0:11211".parse().unwrap());
    restful_server.start().await.unwrap();

    tokio::signal::ctrl_c().await.unwrap();
}
