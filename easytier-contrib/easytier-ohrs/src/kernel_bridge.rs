mod socket_server;

pub(crate) use easytier_ohos_kernel::routing::aggregate_requested_tun_routes;
pub use socket_server::{start_local_socket_server, stop_local_socket_server};
