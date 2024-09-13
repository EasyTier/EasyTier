use crate::tunnel::{mpsc::MpscTunnel, Tunnel};

pub type RpcController = super::rpc_types::controller::BaseController;

pub mod client;
pub mod packet;
pub mod server;
pub mod service_registry;

pub type Transport = MpscTunnel<Box<dyn Tunnel>>;
pub type RpcTransactId = i64;
