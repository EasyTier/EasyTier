// This module is copy and modified from https://github.com/fanyang89/libdns
#[cfg(all(feature = "magic-dns", feature = "tun"))]
pub(crate) mod config;
#[cfg(all(feature = "magic-dns", feature = "tun"))]
pub(crate) mod server;

#[cfg(all(feature = "magic-dns", feature = "tun"))]
pub mod client_instance;
#[cfg(all(feature = "magic-dns", feature = "tun"))]
pub mod runner;
#[cfg(all(feature = "magic-dns", feature = "tun"))]
pub mod server_instance;
#[cfg(all(feature = "magic-dns", feature = "tun"))]
pub mod system_config;

#[cfg(all(test, feature = "tun", feature = "magic-dns"))]
mod tests;

pub static MAGIC_DNS_INSTANCE_ADDR: &str = "tcp://127.0.0.1:49813";
pub static MAGIC_DNS_INSTANCE_SOCKET_ADDR: &str = "127.0.0.1:49813";
pub static MAGIC_DNS_FAKE_IP: &str = "100.100.100.101";
pub use easytier_core::config::toml::DEFAULT_ET_DNS_ZONE;
