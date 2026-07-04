//! Core-visible socket primitives.
//!
//! This Module is below [`crate::tunnel`]. Sockets represent established or
//! bindable communication endpoints; tunnels are produced later by runtime
//! upgraders and can be handed to peers.

pub mod ring;
pub mod tcp;
pub mod udp;
