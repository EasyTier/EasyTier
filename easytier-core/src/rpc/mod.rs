use crate::tunnel::{Tunnel, mpsc::MpscTunnel};

pub type RpcController = crate::proto::rpc_types::controller::BaseController;

pub mod bidirect;
pub mod client;
pub(crate) mod dispatch;
#[cfg(all(feature = "management-rpc", any(test, target_os = "wasi")))]
pub(crate) mod operation;
pub mod packet;
pub mod server;
pub mod service_registry;
pub mod standalone;

pub type Transport = MpscTunnel<Box<dyn Tunnel>>;
pub type RpcTransactId = i64;
