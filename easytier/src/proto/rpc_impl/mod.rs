use crate::tunnel::{Tunnel, mpsc::MpscTunnel};

pub type RpcController = super::rpc_types::controller::BaseController;

pub mod bidirect;
pub mod client;
pub mod packet;
pub mod server;
pub mod service_registry;
pub mod standalone;

pub type Transport = MpscTunnel<Box<dyn Tunnel>>;
pub type RpcTransactId = i64;
