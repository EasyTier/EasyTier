//! Core-visible socket primitives.
//!
//! This Module is below [`crate::tunnel`]. Sockets represent established or
//! bindable communication endpoints; tunnels are produced later by runtime
//! upgraders and can be handed to peers.

pub mod dial;
pub mod dns;
pub mod listen;
pub mod ring;
pub mod tcp;
pub mod udp;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum IpVersion {
    V4,
    V6,
    Both,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NetNamespace(String);

impl NetNamespace {
    pub fn new(token: impl Into<String>) -> Self {
        Self(token.into())
    }

    pub fn token(&self) -> &str {
        &self.0
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SocketContext {
    pub ip_version: IpVersion,
    pub socket_mark: Option<u32>,
    pub netns: Option<NetNamespace>,
}

impl Default for SocketContext {
    fn default() -> Self {
        Self {
            ip_version: IpVersion::Both,
            socket_mark: None,
            netns: None,
        }
    }
}
