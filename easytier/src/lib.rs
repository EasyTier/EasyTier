#![allow(dead_code)]

use std::io;

use clap::Command;
use clap_complete::Generator;

mod arch;
mod gateway;
mod instance;
mod peer_center;
mod vpn_portal;

pub mod common;
pub mod connector;
pub mod launcher;
pub mod instance_manager;
pub mod peers;
pub mod proto;
pub mod tunnel;
pub mod utils;
pub mod web_client;

#[cfg(test)]
mod tests;

pub const VERSION: &str = common::constants::EASYTIER_VERSION;
rust_i18n::i18n!("locales", fallback = "en");

pub fn print_completions<G: Generator>(generator: G, cmd: &mut Command, bin_name:&str) {
    clap_complete::generate(generator, cmd, bin_name, &mut io::stdout());
}