// This module is copy and modified from https://github.com/fanyang89/libdns
#[cfg(feature = "magic-dns")]
pub(crate) mod config;
#[cfg(feature = "magic-dns")]
pub(crate) mod server;

#[cfg(feature = "magic-dns")]
pub mod client_instance;
#[cfg(feature = "magic-dns")]
pub mod runner;
#[cfg(feature = "magic-dns")]
pub mod server_instance;
#[cfg(feature = "magic-dns")]
pub mod system_config;

#[cfg(all(test, feature = "tun", feature = "magic-dns"))]
mod tests;

pub static MAGIC_DNS_INSTANCE_ADDR: &str = "tcp://127.0.0.1:49813";
pub static MAGIC_DNS_FAKE_IP: &str = "100.100.100.101";
pub static DEFAULT_ET_DNS_ZONE: &str = "et.net.";
