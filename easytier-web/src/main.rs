#![allow(dead_code)]

use std::sync::Arc;

use easytier::tunnel::udp::UdpTunnelListener;

mod client_manager;
mod restful;

#[tokio::main]
async fn main() {
    let listener = UdpTunnelListener::new("udp://0.0.0.0:22020".parse().unwrap());
    let mut mgr = client_manager::ClientManager::new();
    mgr.serve(listener).await.unwrap();
    let mgr = Arc::new(mgr);

    let mut restful_server =
        restful::RestfulServer::new("0.0.0.0:11211".parse().unwrap(), mgr.clone())
            .await
            .unwrap();
    restful_server.start().await.unwrap();

    tokio::signal::ctrl_c().await.unwrap();
}
