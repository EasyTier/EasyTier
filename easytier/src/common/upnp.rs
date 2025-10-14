use igd_next::{PortMappingProtocol, SearchOptions, aio::tokio::search_gateway};
use tokio::net::UdpSocket;

use super::error::Error;

/// Try a best-effort UPnP mapping for given local UDP port (IPv4 only).
pub async fn try_upnp_map_udp(port: u16) -> Result<(), Error>{
    // Search for a gateway
    let options = SearchOptions {
        timeout: Some(std::time::Duration::from_millis(500)),
        ..Default::default()
    };

    let gateway = search_gateway(options).await?;
    // Create a UDP socket and connect to Gateway to determine the local address
    let udp = UdpSocket::bind(format!("0.0.0.0:0")).await?;
    udp.connect(gateway.addr).await?;
    let mut local_addr = udp.local_addr()?;

    // Set local address to be mapped
    local_addr.set_port(port);
    let _ = gateway.add_port(
        PortMappingProtocol::UDP,
        port,
        local_addr,
        60,
        "EasyTier").await?;
    
    Ok(())
}
