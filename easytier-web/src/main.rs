use easytier::tunnel::udp::UdpTunnelListener;

mod client_manager;

#[tokio::main]
async fn main() {
    let listener = UdpTunnelListener::new("udp://0.0.0.0:11210".parse().unwrap());
    let mut mgr = client_manager::ClientManager::new(Box::new(listener));
    mgr.serve().await.unwrap();
}
