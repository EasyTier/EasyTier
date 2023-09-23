use std::{net::Ipv4Addr, sync::Arc};

use async_trait::async_trait;
use tokio_util::bytes::Bytes;

use crate::common::error::Error;

use super::PeerId;

#[async_trait]
pub trait RouteInterface {
    async fn list_peers(&self) -> Vec<PeerId>;
    async fn send_route_packet(
        &self,
        msg: Bytes,
        route_id: u8,
        dst_peer_id: &PeerId,
    ) -> Result<(), Error>;
}

pub type RouteInterfaceBox = Box<dyn RouteInterface + Send + Sync>;

#[async_trait]
pub trait Route {
    async fn open(&self, interface: RouteInterfaceBox) -> Result<u8, ()>;
    async fn close(&self);

    async fn get_peer_id_by_ipv4(&self, ipv4: &Ipv4Addr) -> Option<PeerId>;
    async fn get_next_hop(&self, peer_id: &PeerId) -> Option<PeerId>;

    async fn handle_route_packet(&self, src_peer_id: PeerId, packet: Bytes);

    async fn list_routes(&self) -> Vec<easytier_rpc::Route>;
}

pub type ArcRoute = Arc<Box<dyn Route + Send + Sync>>;
