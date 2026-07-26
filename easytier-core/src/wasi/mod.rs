//! WASI runtime integration for EasyTier core.
//!
//! Portable Host capability seams live in [`crate::host`]. This module owns
//! the concrete WASI adapters, the `easytier_host` import contract, and the
//! guest lifecycle ABI used by an externally driven WASI runtime.

pub mod abi;

/// Concrete adapters a WASI guest uses to connect portable Host seams to the
/// [`abi::HOST_IMPORT_MODULE`] runtime contract.
#[cfg(target_os = "wasi")]
pub mod adapter;
#[cfg(target_os = "wasi")]
pub(crate) mod imports;
#[cfg(target_os = "wasi")]
pub(crate) mod runtime;
#[cfg(any(test, target_os = "wasi"))]
pub(crate) mod runtime_driver;
#[cfg(any(test, target_os = "wasi"))]
pub(crate) mod schema;
#[cfg(any(test, target_os = "wasi"))]
pub(crate) mod time;
#[cfg(any(test, target_os = "wasi"))]
pub(crate) mod wire;
