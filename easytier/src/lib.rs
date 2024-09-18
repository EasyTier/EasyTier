#![allow(dead_code)]

mod arch;
mod connector;
mod gateway;
mod instance;
mod peer_center;
mod peers;
mod proto;
mod vpn_portal;

pub mod common;
pub mod launcher;
pub mod tunnel;
pub mod utils;

pub const VERSION: &str = common::constants::EASYTIER_VERSION;
