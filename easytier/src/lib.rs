#![allow(dead_code)]

mod arch;
mod gateway;
mod instance;
mod peer_center;
mod vpn_portal;

pub mod common;
pub mod connector;
pub mod launcher;
pub mod peers;
pub mod proto;
pub mod tunnel;
pub mod utils;
pub mod web_client;

#[cfg(test)]
mod tests;

pub const VERSION: &str = common::constants::EASYTIER_VERSION;
rust_i18n::i18n!("locales", fallback = "en");
