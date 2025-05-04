// This module is copy and modified from https://github.com/fanyang89/libdns
pub(crate) mod config;
pub(crate) mod server;

pub mod client_instance;
pub mod runner;
pub mod server_instance;
pub mod system_config;

#[cfg(test)]
mod tests;

pub static MAGIC_DNS_INSTANCE_ADDR: &str = "tcp://127.0.0.1:49813";
pub static MAGIC_DNS_FAKE_IP: &str = "100.100.100.101";
pub static DEFAULT_ET_DNS_ZONE: &str = "et.net.";
