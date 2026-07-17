use std::{collections::HashMap, io, sync::Mutex, task::Poll};

use crate::socket::udp::{UdpSocketRecvMeta, UdpSocketSendMeta};

use super::{HostUdpDatagram, HostUdpIo};
use crate::host::{
    HostOperationId, HostSocketHandle, HostSocketIo,
    wasi_common::{host_error, status},
    wasi_wire::{UDP_METADATA_LEN, decode_udp_metadata, encode_udp_metadata},
};

const HOST_PENDING: i32 = -1;
const HOST_WOULD_BLOCK: i32 = -5;

#[link(wasm_import_module = "easytier_host")]
unsafe extern "C" {
    fn start_udp_recv(handle: u64, operation: u64, capacity: u32) -> i32;
    fn take_udp_recv(
        operation: u64,
        destination: u32,
        capacity: u32,
        metadata: u32,
        metadata_len: u32,
    ) -> i32;
    fn try_udp_send(handle: u64, source: u32, length: u32, metadata: u32, metadata_len: u32)
    -> i32;
    fn start_udp_send_ready(handle: u64, operation: u64) -> i32;
    fn take_udp_send_ready(operation: u64) -> i32;
    fn cancel_operation(operation: u64) -> i32;
    fn close(handle: u64) -> i32;
}

struct WasiUdpRecvBuffer {
    data: Vec<u8>,
    metadata: [u8; UDP_METADATA_LEN],
}

#[derive(Default)]
pub struct WasiHostUdpIo {
    recv_buffers: Mutex<HashMap<HostOperationId, WasiUdpRecvBuffer>>,
}

impl WasiHostUdpIo {
    pub(in crate::host) fn forget_operation(&self, operation: HostOperationId) {
        self.recv_buffers
            .lock()
            .expect("WASI UDP receive buffer registry poisoned")
            .remove(&operation);
    }
}

impl HostSocketIo for WasiHostUdpIo {
    fn cancel_operation(&self, operation: HostOperationId) -> io::Result<()> {
        self.forget_operation(operation);
        status("cancel_operation", unsafe { cancel_operation(operation.0) })
    }

    fn close(&self, handle: HostSocketHandle) -> io::Result<()> {
        status("close", unsafe { close(handle.0) })
    }
}

impl HostUdpIo for WasiHostUdpIo {
    fn submit_recv(
        &self,
        handle: HostSocketHandle,
        operation: HostOperationId,
        capacity: usize,
    ) -> io::Result<()> {
        let capacity_u32 = u32::try_from(capacity).map_err(|_| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                "UDP receive buffer is too large",
            )
        })?;
        status("start_udp_recv", unsafe {
            start_udp_recv(handle.0, operation.0, capacity_u32)
        })?;
        self.recv_buffers
            .lock()
            .expect("WASI UDP receive buffer registry poisoned")
            .insert(
                operation,
                WasiUdpRecvBuffer {
                    data: vec![0; capacity],
                    metadata: [0; UDP_METADATA_LEN],
                },
            );
        Ok(())
    }

    fn take_recv(&self, operation: HostOperationId) -> Poll<io::Result<HostUdpDatagram>> {
        let mut buffers = self
            .recv_buffers
            .lock()
            .expect("WASI UDP receive buffer registry poisoned");
        let Some(buffer) = buffers.get_mut(&operation) else {
            return Poll::Ready(Err(io::Error::new(
                io::ErrorKind::NotFound,
                "WASI UDP receive operation buffer is missing",
            )));
        };
        let result = unsafe {
            take_udp_recv(
                operation.0,
                buffer.data.as_mut_ptr() as u32,
                buffer.data.len() as u32,
                buffer.metadata.as_mut_ptr() as u32,
                UDP_METADATA_LEN as u32,
            )
        };
        match result {
            HOST_PENDING => Poll::Pending,
            value if value >= 0 => {
                let length = value as usize;
                let mut buffer = buffers.remove(&operation).unwrap();
                if length > buffer.data.len() {
                    return Poll::Ready(Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "host UDP receive completion exceeds the submitted capacity",
                    )));
                }
                buffer.data.truncate(length);
                let (peer_addr, dst_ip, _) = match decode_udp_metadata(&buffer.metadata) {
                    Ok(metadata) => metadata,
                    Err(error) => return Poll::Ready(Err(error)),
                };
                Poll::Ready(Ok(HostUdpDatagram {
                    data: buffer.data,
                    peer_addr,
                    meta: UdpSocketRecvMeta { dst_ip },
                }))
            }
            value => {
                buffers.remove(&operation);
                Poll::Ready(Err(host_error("take_udp_recv", value)))
            }
        }
    }

    fn try_send(
        &self,
        handle: HostSocketHandle,
        source: &[u8],
        peer_addr: std::net::SocketAddr,
        meta: UdpSocketSendMeta,
    ) -> io::Result<()> {
        if meta.src_ifindex.is_some() && !matches!(meta.src_ip, Some(std::net::IpAddr::V6(_))) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "UDP source interface index requires an IPv6 source address",
            ));
        }
        let length = u32::try_from(source.len()).map_err(|_| {
            io::Error::new(io::ErrorKind::InvalidInput, "UDP send buffer is too large")
        })?;
        let metadata = encode_udp_metadata(peer_addr, meta.src_ip, meta.src_ifindex);
        match unsafe {
            try_udp_send(
                handle.0,
                source.as_ptr() as u32,
                length,
                metadata.as_ptr() as u32,
                UDP_METADATA_LEN as u32,
            )
        } {
            0 => Ok(()),
            HOST_WOULD_BLOCK => Err(io::ErrorKind::WouldBlock.into()),
            value => Err(host_error("try_udp_send", value)),
        }
    }

    fn submit_send_ready(
        &self,
        handle: HostSocketHandle,
        operation: HostOperationId,
    ) -> io::Result<()> {
        status("start_udp_send_ready", unsafe {
            start_udp_send_ready(handle.0, operation.0)
        })
    }

    fn take_send_ready(&self, operation: HostOperationId) -> Poll<io::Result<()>> {
        match unsafe { take_udp_send_ready(operation.0) } {
            HOST_PENDING => Poll::Pending,
            0 => Poll::Ready(Ok(())),
            value => Poll::Ready(Err(host_error("take_udp_send_ready", value))),
        }
    }
}
