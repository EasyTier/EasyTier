//! UDP socket resources exposed by the data plane.

use std::{
    any::Any,
    collections::{HashMap, hash_map::Entry},
    net::SocketAddr,
    sync::{Arc, Mutex},
};

use super::{
    DataPlaneIoGuard, DataPlaneLease, DataPlaneUdpIo, FlowData, FlowKey, FlowLease, FlowSet,
    UDP_ENTRY,
};

pub struct DataPlaneUdpSocket {
    pub(super) socket: Arc<DataPlaneUdpIo>,
    pub(super) flows: FlowSet,
    pub(super) routes: Mutex<HashMap<SocketAddr, FlowLease<FlowData>>>,
    pub(super) local_addr: SocketAddr,
    pub(super) _reservation: Arc<dyn Any + Send + Sync>,
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
        let key = FlowKey {
            src: self.local_addr,
            dst: addr,
            kind: UDP_ENTRY,
        };
        if let Entry::Vacant(route) = self.routes.lock().unwrap().entry(addr) {
            let lease = FlowLease::try_register(self.flows.clone(), key, FlowData::Udp)
                .ok_or_else(|| {
                    std::io::Error::new(
                        std::io::ErrorKind::AddrInUse,
                        "data-plane UDP flow already exists",
                    )
                })?;
            route.insert(lease);
        }
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
