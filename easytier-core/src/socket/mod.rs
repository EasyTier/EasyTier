//! Core-visible socket primitives.
//!
//! This Module is below [`crate::tunnel`]. Sockets represent established or
//! bindable communication endpoints; tunnels are produced later by runtime
//! upgraders and can be handed to peers. Host capability seams (DNS, packet
//! egress, environment facts, and the WASI mechanism backend) live in
//! [`crate::host`].

pub mod ring;
pub mod tcp;
pub mod udp;

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum IpVersion {
    V4,
    V6,
    Both,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NetNamespace(String);

impl NetNamespace {
    pub fn new(token: impl Into<String>) -> Self {
        Self(token.into())
    }

    pub fn token(&self) -> &str {
        &self.0
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SocketContext {
    pub ip_version: IpVersion,
    pub socket_mark: Option<u32>,
    pub netns: Option<NetNamespace>,
}

impl SocketContext {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn with_ip_version(mut self, ip_version: IpVersion) -> Self {
        self.ip_version = ip_version;
        self
    }

    pub fn with_socket_mark(mut self, socket_mark: Option<u32>) -> Self {
        self.socket_mark = socket_mark;
        self
    }

    pub fn with_netns(mut self, netns: Option<NetNamespace>) -> Self {
        self.netns = netns;
        self
    }
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
