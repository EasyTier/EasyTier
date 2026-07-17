//! Portable connection orchestration.

pub mod composite;
pub mod direct;
// Kept public: the host-driven adapter chain is WASI-only production code
// (cfg(target_os = "wasi")), so crate-private visibility would surface
// dead-code warnings on host builds for code that is live on WASI.
pub mod host;
pub mod manual;
pub mod protocol;
pub mod transport;
