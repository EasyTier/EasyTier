use std::{io, task::Poll};

use crate::host::socket::{
    HostOperationId, HostSocketHandle, HostSocketIo, HostTcpIo,
    factory::{HostSocketFactoryIo, HostTcpConnectResult, HostUdpBindResult},
    listener::{HostTcpBindResult, HostTcpListenerIo},
    udp::{HostUdpDatagram, HostUdpIo},
};
use crate::socket::{
    tcp::{TcpConnectOptions, TcpListenOptions},
    udp::{UdpBindOptions, UdpSocketSendMeta},
};

use crate::wasi::{
    imports::{
        HOST_PENDING, cancel_operation, close, start_tcp_accept, start_tcp_bind, start_tcp_connect,
        start_udp_bind, take_tcp_accept, take_tcp_bind, take_tcp_connect, take_udp_bind,
    },
    wire::{
        common::{host_error, status, tcp_connect_error},
        options::{
            BOUND_SOCKET_RESULT_LEN, TCP_SOCKET_RESULT_LEN, decode_tcp_bind_result,
            decode_tcp_socket_result, decode_udp_bind_result, encode_tcp_connect_options,
            encode_tcp_listen_options, encode_udp_bind_options,
        },
    },
};

use super::{WasiHostTcpIo, udp::WasiHostUdpIo};

#[derive(Default)]
pub struct WasiHostSocketBackend {
    tcp: WasiHostTcpIo,
    udp: WasiHostUdpIo,
}

impl WasiHostSocketBackend {
    fn decode_transferred<T>(&self, encoded: &[u8], decoded: io::Result<T>) -> io::Result<T> {
        match decoded {
            Ok(result) => Ok(result),
            Err(decode_error) => {
                let handle = HostSocketHandle(u64::from_be_bytes(encoded[..8].try_into().unwrap()));
                match self.close(handle) {
                    Ok(()) => Err(decode_error),
                    Err(close_error) => Err(io::Error::new(
                        decode_error.kind(),
                        format!(
                            "{decode_error}; additionally failed to close malformed host result: {close_error}"
                        ),
                    )),
                }
            }
        }
    }
}

impl HostSocketIo for WasiHostSocketBackend {
    fn cancel_operation(&self, operation: HostOperationId) -> io::Result<()> {
        self.tcp.forget_operation(operation);
        self.udp.forget_operation(operation);
        status("cancel_operation", unsafe { cancel_operation(operation.0) })
    }

    fn close(&self, handle: HostSocketHandle) -> io::Result<()> {
        status("close", unsafe { close(handle.0) })
    }
}

impl HostTcpIo for WasiHostSocketBackend {
    fn submit_read(
        &self,
        handle: HostSocketHandle,
        operation: HostOperationId,
        capacity: usize,
    ) -> io::Result<()> {
        self.tcp.submit_read(handle, operation, capacity)
    }

    fn take_read(&self, operation: HostOperationId) -> Poll<io::Result<Vec<u8>>> {
        self.tcp.take_read(operation)
    }

    fn submit_write(
        &self,
        handle: HostSocketHandle,
        operation: HostOperationId,
        source: &[u8],
    ) -> io::Result<()> {
        self.tcp.submit_write(handle, operation, source)
    }

    fn take_write(&self, operation: HostOperationId) -> Poll<io::Result<()>> {
        self.tcp.take_write(operation)
    }
}

impl HostUdpIo for WasiHostSocketBackend {
    fn submit_recv(
        &self,
        handle: HostSocketHandle,
        operation: HostOperationId,
        capacity: usize,
    ) -> io::Result<()> {
        self.udp.submit_recv(handle, operation, capacity)
    }

    fn take_recv(&self, operation: HostOperationId) -> Poll<io::Result<HostUdpDatagram>> {
        self.udp.take_recv(operation)
    }

    fn try_send(
        &self,
        handle: HostSocketHandle,
        source: &[u8],
        peer_addr: std::net::SocketAddr,
        meta: UdpSocketSendMeta,
    ) -> io::Result<()> {
        self.udp.try_send(handle, source, peer_addr, meta)
    }

    fn submit_send_ready(
        &self,
        handle: HostSocketHandle,
        operation: HostOperationId,
    ) -> io::Result<()> {
        self.udp.submit_send_ready(handle, operation)
    }

    fn take_send_ready(&self, operation: HostOperationId) -> Poll<io::Result<()>> {
        self.udp.take_send_ready(operation)
    }
}

impl HostSocketFactoryIo for WasiHostSocketBackend {
    fn submit_tcp_connect(
        &self,
        operation: HostOperationId,
        options: &TcpConnectOptions,
    ) -> io::Result<()> {
        let encoded = encode_tcp_connect_options(options)?;
        status("start_tcp_connect", unsafe {
            start_tcp_connect(
                operation.0,
                encoded.as_ptr() as u32,
                encoded_len("TCP connect options", &encoded)?,
            )
        })
    }

    fn take_tcp_connect(
        &self,
        operation: HostOperationId,
    ) -> Poll<io::Result<HostTcpConnectResult>> {
        let mut encoded = [0_u8; TCP_SOCKET_RESULT_LEN];
        match unsafe {
            take_tcp_connect(
                operation.0,
                encoded.as_mut_ptr() as u32,
                TCP_SOCKET_RESULT_LEN as u32,
            )
        } {
            HOST_PENDING => Poll::Pending,
            0 => Poll::Ready(self.decode_transferred(&encoded, decode_tcp_socket_result(&encoded))),
            value => Poll::Ready(Err(tcp_connect_error(value))),
        }
    }

    fn submit_udp_bind(
        &self,
        operation: HostOperationId,
        options: &UdpBindOptions,
    ) -> io::Result<()> {
        let encoded = encode_udp_bind_options(options)?;
        status("start_udp_bind", unsafe {
            start_udp_bind(
                operation.0,
                encoded.as_ptr() as u32,
                encoded_len("UDP bind options", &encoded)?,
            )
        })
    }

    fn take_udp_bind(&self, operation: HostOperationId) -> Poll<io::Result<HostUdpBindResult>> {
        let mut encoded = [0_u8; BOUND_SOCKET_RESULT_LEN];
        match unsafe {
            take_udp_bind(
                operation.0,
                encoded.as_mut_ptr() as u32,
                BOUND_SOCKET_RESULT_LEN as u32,
            )
        } {
            HOST_PENDING => Poll::Pending,
            0 => Poll::Ready(self.decode_transferred(&encoded, decode_udp_bind_result(&encoded))),
            value => Poll::Ready(Err(host_error("take_udp_bind", value))),
        }
    }
}

impl HostTcpListenerIo for WasiHostSocketBackend {
    fn submit_tcp_bind(
        &self,
        operation: HostOperationId,
        options: &TcpListenOptions,
    ) -> io::Result<()> {
        let encoded = encode_tcp_listen_options(options)?;
        status("start_tcp_bind", unsafe {
            start_tcp_bind(
                operation.0,
                encoded.as_ptr() as u32,
                encoded_len("TCP listen options", &encoded)?,
            )
        })
    }

    fn take_tcp_bind(&self, operation: HostOperationId) -> Poll<io::Result<HostTcpBindResult>> {
        let mut encoded = [0_u8; BOUND_SOCKET_RESULT_LEN];
        match unsafe {
            take_tcp_bind(
                operation.0,
                encoded.as_mut_ptr() as u32,
                BOUND_SOCKET_RESULT_LEN as u32,
            )
        } {
            HOST_PENDING => Poll::Pending,
            0 => Poll::Ready(self.decode_transferred(&encoded, decode_tcp_bind_result(&encoded))),
            value => Poll::Ready(Err(host_error("take_tcp_bind", value))),
        }
    }

    fn submit_tcp_accept(
        &self,
        handle: HostSocketHandle,
        operation: HostOperationId,
    ) -> io::Result<()> {
        status("start_tcp_accept", unsafe {
            start_tcp_accept(handle.0, operation.0)
        })
    }

    fn take_tcp_accept(
        &self,
        operation: HostOperationId,
    ) -> Poll<io::Result<HostTcpConnectResult>> {
        let mut encoded = [0_u8; TCP_SOCKET_RESULT_LEN];
        match unsafe {
            take_tcp_accept(
                operation.0,
                encoded.as_mut_ptr() as u32,
                TCP_SOCKET_RESULT_LEN as u32,
            )
        } {
            HOST_PENDING => Poll::Pending,
            0 => Poll::Ready(self.decode_transferred(&encoded, decode_tcp_socket_result(&encoded))),
            value => Poll::Ready(Err(host_error("take_tcp_accept", value))),
        }
    }
}

fn encoded_len(description: &str, encoded: &[u8]) -> io::Result<u32> {
    u32::try_from(encoded.len()).map_err(|_| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("{description} exceed WASI guest memory"),
        )
    })
}
