pub mod peer_manager;
pub mod route_trait;

#[cfg(test)]
pub mod tests;

pub use easytier_core::peers::create_packet_recv_chan;
pub use route_trait::Route;
