//! UDP socket resources exposed by the data plane.

use std::{net::SocketAddr, sync::Arc};

use super::{DataPlaneIoGuard, DataPlaneLease, DataPlaneUdpIo, FlowData, FlowLease};

pub struct DataPlaneUdpSocket {
    pub(super) socket: Arc<DataPlaneUdpIo>,
    pub(super) _bind_flow: FlowLease<FlowData>,
    pub(super) local_addr: SocketAddr,
    pub(super) _data_plane_lease: DataPlaneLease,
    pub(super) generation: DataPlaneIoGuard,
}

impl DataPlaneUdpSocket {
    pub fn local_addr(&self) -> SocketAddr {
        self.local_addr
    }

    pub async fn send_to(&self, buf: &[u8], addr: SocketAddr) -> Result<usize, std::io::Error> {
        self.generation
            .ensure_open()
            .map_err(|error| error.into_io_error())?;
        tokio::select! {
            biased;
            _ = self.generation.closed() => Err(self.generation.closed_io_error()),
            result = self.socket.send_to(buf, addr) => result,
        }
    }

    pub async fn recv_from(&self, buf: &mut [u8]) -> Result<(usize, SocketAddr), std::io::Error> {
        self.generation
            .ensure_open()
            .map_err(|error| error.into_io_error())?;
        tokio::select! {
            biased;
            _ = self.generation.closed() => Err(self.generation.closed_io_error()),
            result = self.socket.recv_from(buf) => result,
        }
    }

    pub(super) async fn recv_from_limited(
        &self,
        max_len: usize,
    ) -> Result<(Vec<u8>, SocketAddr, bool), std::io::Error> {
        self.generation
            .ensure_open()
            .map_err(|error| error.into_io_error())?;
        tokio::select! {
            biased;
            _ = self.generation.closed() => Err(self.generation.closed_io_error()),
            result = self.socket.recv_from_limited(max_len) => result,
        }
    }
}
