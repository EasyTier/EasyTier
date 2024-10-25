#![allow(dead_code)]

mod arch;
mod connector;
mod gateway;
mod instance;
mod peer_center;
mod vpn_portal;

pub mod common;
pub mod launcher;
pub mod peers;
pub mod proto;
pub mod tunnel;
pub mod utils;

#[cfg(test)]
mod tests;

pub const VERSION: &str = common::constants::EASYTIER_VERSION;
