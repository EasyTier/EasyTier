#![allow(dead_code)]

use std::io;

use clap::Command;
use clap_complete::{Generator, Shell};

// When the `hotpath` feature is off, alias the current crate as `hotpath` so
// call sites keep using `hotpath::...` paths, and provide a local no-op shim
// for the profiling macros. This keeps `hotpath` an optional dependency: the
// profiler is absent from the dependency graph entirely in default builds.
#[cfg(not(feature = "hotpath"))]
extern crate self as hotpath;
#[cfg(not(feature = "hotpath"))]
mod hotpath_off;
#[cfg(not(feature = "hotpath"))]
pub(crate) use hotpath_off::wrap;

// `hotpath-alloc` registers a global profiling allocator, which is mutually
// exclusive with the `jemalloc`/`mimalloc` global allocators.
#[cfg(all(feature = "hotpath-alloc", any(feature = "jemalloc", feature = "mimalloc")))]
compile_error!("feature `hotpath-alloc` cannot be enabled together with `jemalloc` or `mimalloc`");

// Re-export `Instant` at the crate root so public APIs that expose it
// (e.g. `Route::get_peer_info_last_update_time`) reference a deliberate
// public type rather than leaking an inaccessible one.
pub use quanta::Instant;

mod arch;
mod gateway;
pub mod instance;
mod peer_center;
mod vpn_portal;

pub mod common;
pub mod connector;
pub mod core;
pub mod instance_manager;
pub mod launcher;
pub mod peers;
pub mod proto;
pub mod rpc_service;
pub mod service_manager;
pub mod tunnel;
pub mod utils;
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
