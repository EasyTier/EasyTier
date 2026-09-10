use async_trait::async_trait;

use crate::proto::rpc_types::{controller::BaseController, handler::Handler};
use crate::tunnel::Tunnel;

mod peer_adapters;
pub(crate) mod policy;
pub mod port_mapping;
pub(crate) mod tcp;
pub(crate) mod udp;

/// Registration seam for hole-punch RPC services.
///
/// The engines build the proto-generated server wrapper around their RPC
/// endpoint; the implementation owns the peer RPC registry and the network
/// domain the service is registered under. Implemented only by the sealed
/// peer adapter in `peer_adapters.rs`.
pub(crate) trait HolePunchRpcRegistry: Send + Sync + 'static {
    fn register_rpc_service<H>(&self, service: H)
    where
        H: Handler<Controller = BaseController>;

    fn unregister_rpc_service<H>(&self, service: H)
    where
        H: Handler<Controller = BaseController>;
}

#[async_trait]
pub(crate) trait HolePunchTunnelSink: Send + Sync + 'static {
    async fn add_client_tunnel(&self, tunnel: Box<dyn Tunnel>) -> anyhow::Result<()>;

    async fn add_server_tunnel(&self, tunnel: Box<dyn Tunnel>) -> anyhow::Result<()>;
}
