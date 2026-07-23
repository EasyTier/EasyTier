//! Host capability seams.
//!
//! This module is the single home of every Host capability seam (see
//! CONTEXT.md, "Host capability"): DNS resolution, connector environment
//! facts, packet egress, and host-backed sockets. The socket-flavoured seams
//! — the host operation runtime and identifiers, the TCP stream and UDP
//! socket bridges, socket factories, and TCP listeners — live in [`socket`].
//! Concrete WASI adapters for these seams live in [`crate::wasi`].

pub mod dns;
pub mod environment;
pub mod packet;
pub mod socket;
#[cfg(test)]
pub(crate) mod testkit;
