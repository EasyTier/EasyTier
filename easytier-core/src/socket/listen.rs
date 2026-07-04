use std::path::PathBuf;

use async_trait::async_trait;

use crate::socket::{
    SocketContext,
    dial::{BindEndpoint, SocketKind},
};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ListenEndpoint {
    Ip,
    Ring(uuid::Uuid),
    UnixPath(PathBuf),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SocketListenRequest {
    pub socket_kind: SocketKind,
    pub endpoint: ListenEndpoint,
    pub binds: Vec<BindEndpoint>,
    pub context: SocketContext,
}

impl SocketListenRequest {
    pub fn new(socket_kind: SocketKind) -> Self {
        Self {
            socket_kind,
            endpoint: ListenEndpoint::Ip,
            binds: Vec::new(),
            context: SocketContext::default(),
        }
    }

    pub fn ring(id: uuid::Uuid) -> Self {
        Self {
            socket_kind: SocketKind::Ring,
            endpoint: ListenEndpoint::Ring(id),
            binds: Vec::new(),
            context: SocketContext::default(),
        }
    }

    pub fn unix(path: impl Into<PathBuf>) -> Self {
        Self {
            socket_kind: SocketKind::Unix,
            endpoint: ListenEndpoint::UnixPath(path.into()),
            binds: Vec::new(),
            context: SocketContext::default(),
        }
    }

    pub fn with_binds(mut self, binds: Vec<BindEndpoint>) -> Self {
        self.binds = binds;
        self
    }

    pub fn with_context(mut self, context: SocketContext) -> Self {
        self.context = context;
        self
    }

    pub fn effective_binds(&self) -> Vec<BindEndpoint> {
        if self.binds.is_empty() {
            vec![BindEndpoint::Default]
        } else {
            self.binds.clone()
        }
    }
}

#[async_trait]
pub trait SocketListener: Send {
    type ConnectedSocket: Send + 'static;

    async fn listen(&mut self, request: SocketListenRequest) -> anyhow::Result<()>;

    async fn accept(&mut self) -> anyhow::Result<Self::ConnectedSocket>;
}

#[cfg(test)]
mod tests {
    use std::net::SocketAddr;

    use super::*;

    #[test]
    fn empty_listen_binds_expand_to_default_bind() {
        let request = SocketListenRequest::new(SocketKind::Tcp);

        assert_eq!(request.effective_binds(), vec![BindEndpoint::Default]);
    }

    #[test]
    fn listen_request_preserves_bind_candidates() {
        let bind_addr = SocketAddr::from(([0, 0, 0, 0], 11010));
        let request = SocketListenRequest::new(SocketKind::Udp).with_binds(vec![
            BindEndpoint::Addr(bind_addr),
            BindEndpoint::Device("eth0".to_owned()),
        ]);

        assert_eq!(
            request.effective_binds(),
            vec![
                BindEndpoint::Addr(bind_addr),
                BindEndpoint::Device("eth0".to_owned()),
            ]
        );
    }

    #[test]
    fn listen_request_preserves_non_ip_endpoint() {
        let id = uuid::Uuid::new_v4();

        assert_eq!(
            SocketListenRequest::ring(id).endpoint,
            ListenEndpoint::Ring(id)
        );
        assert_eq!(
            SocketListenRequest::unix("/tmp/easytier.sock").endpoint,
            ListenEndpoint::UnixPath("/tmp/easytier.sock".into())
        );
    }
}
