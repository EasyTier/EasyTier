use std::sync::LazyLock;
use std::time::Duration;
use url::Url;

#[allow(unused_imports)]
pub use easytier_core::config::dns::*;

mod policy;
#[allow(unused_imports)]
pub use policy::*;
pub mod zone;
#[allow(clippy::module_inception)]
mod dns;
pub use dns::*;

pub static DNS_SERVER_RPC_ADDR: LazyLock<Url> =
    LazyLock::new(|| Url::parse("tcp://127.0.0.1:49813").unwrap());

pub const DNS_NODE_TTI: Duration = Duration::from_secs(5);

pub const DNS_NODE_HEARTBEAT_INTERVAL: Duration = Duration::from_secs(2);
pub const DNS_NODE_RECONCILE_INTERVAL: Duration = Duration::from_secs(10);
pub const DNS_SERVER_ELECTION_INTERVAL: Duration = Duration::from_secs(5);
pub const DNS_PEER_TTI: Duration = Duration::from_secs(3);
pub const DNS_PEER_REFRESH_ATTEMPTS: usize = 3;
pub const DNS_PEER_REFRESH_BACKOFF: Duration = Duration::from_secs(1);
