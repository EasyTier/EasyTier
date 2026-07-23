use std::io;

use clap::Command;
use clap_complete::{Generator, Shell};

mod arch;
mod gateway;
mod host_runtime;
pub mod instance;
mod vpn_portal;

pub mod common;
#[cfg(feature = "management")]
pub mod core;
pub mod proto;
#[cfg(feature = "management-rpc")]
pub mod rpc_service;
#[cfg(feature = "management")]
pub mod service_manager;
pub(crate) mod socket;
pub mod tunnel;
pub mod utils;
#[cfg(feature = "management")]
pub mod web_client;

#[cfg(test)]
mod tests;

pub const VERSION: &str = common::constants::EASYTIER_VERSION;
rust_i18n::i18n!("locales", fallback = "en");

#[derive(clap::ValueEnum, Debug, Clone, PartialEq)]
pub enum ShellType {
    Bash,
    Elvish,
    Fish,
    Powershell,
    Zsh,
    Nu,
}

impl ShellType {
    pub fn to_shell(&self) -> Option<Shell> {
        match self {
            ShellType::Bash => Some(Shell::Bash),
            ShellType::Elvish => Some(Shell::Elvish),
            ShellType::Fish => Some(Shell::Fish),
            ShellType::Powershell => Some(Shell::PowerShell),
            ShellType::Zsh => Some(Shell::Zsh),
            ShellType::Nu => None,
        }
    }
}

pub fn print_completions<G: Generator>(generator: G, cmd: &mut Command, bin_name: &str) {
    clap_complete::generate(generator, cmd, bin_name, &mut io::stdout());
}

pub fn print_nushell_completions(cmd: &mut Command, bin_name: &str) {
    clap_complete::generate(
        clap_complete_nushell::Nushell,
        cmd,
        bin_name,
        &mut io::stdout(),
    );
}
