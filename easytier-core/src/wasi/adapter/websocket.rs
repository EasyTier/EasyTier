//! WASI imports for host-accepted WebSocket message tunnels.

use std::{
    collections::HashMap,
    io,
    sync::{Arc, Mutex},
    task::Poll,
};

#[cfg(not(feature = "wasm-host-websocket-outbound"))]
use std::{fmt, marker::PhantomData};

use crate::{
    host::{
        socket::{HostOperationId, HostSocketHandle, HostSocketIo},
        websocket::{HostWebSocketIo, HostWebSocketMessage},
    },
    tunnel::Tunnel,
    wasi::{
        imports::{
            HOST_PENDING, HOST_WEBSOCKET_CLOSED, HOST_WEBSOCKET_TEXT, cancel_operation, close,
            start_websocket_receive, start_websocket_send, take_websocket_receive,
            take_websocket_send,
        },
        wire::common::{host_error, status},
    },
};

#[cfg(not(feature = "wasm-host-websocket-outbound"))]
use crate::{
    listener::{
        ExternalListenerFactory, ExternalListenerRequest, queue::HostListenerQueue,
        transport::AcceptedTransport,
    },
    socket::{SocketListener, tcp::VirtualTcpSocket},
};

#[cfg(feature = "wasm-host-websocket-outbound")]
use crate::connectivity::manual::ExternalTunnelConnector;
#[cfg(feature = "wasm-host-websocket-outbound")]
use crate::wasi::imports::{start_websocket_connect, take_websocket_connect};

#[cfg(not(feature = "wasm-host-websocket-outbound"))]
const MAX_PENDING_HOST_WEBSOCKETS: usize = 256;

#[derive(Default)]
pub struct WasiHostWebSocketIo {
    receive_capacities: Mutex<HashMap<HostOperationId, usize>>,
}

impl WasiHostWebSocketIo {
    fn forget_operation(&self, operation: HostOperationId) {
        self.receive_capacities.lock().unwrap().remove(&operation);
    }
}

impl HostSocketIo for WasiHostWebSocketIo {
    fn cancel_operation(&self, operation: HostOperationId) -> io::Result<()> {
        self.forget_operation(operation);
        status("cancel_operation", unsafe { cancel_operation(operation.0) })
    }

    fn close(&self, handle: HostSocketHandle) -> io::Result<()> {
        status("close", unsafe { close(handle.0) })
    }
}

impl HostWebSocketIo for WasiHostWebSocketIo {
    fn submit_receive(
        &self,
        handle: HostSocketHandle,
        operation: HostOperationId,
        capacity: usize,
    ) -> io::Result<()> {
        let capacity = u32::try_from(capacity).map_err(|_| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                "WebSocket receive buffer is too large",
            )
        })?;
        status("start_websocket_receive", unsafe {
            start_websocket_receive(handle.0, operation.0, capacity)
        })?;
        self.receive_capacities
            .lock()
            .unwrap()
            .insert(operation, capacity as usize);
        Ok(())
    }

    fn take_receive(&self, operation: HostOperationId) -> Poll<io::Result<HostWebSocketMessage>> {
        let mut capacities = self.receive_capacities.lock().unwrap();
        let Some(&capacity) = capacities.get(&operation) else {
            return Poll::Ready(Err(io::Error::new(
                io::ErrorKind::NotFound,
                "WASI WebSocket receive capacity is missing",
            )));
        };
        let result = unsafe { take_websocket_receive(operation.0, 0, 0) };
        match result {
            HOST_PENDING => Poll::Pending,
            HOST_WEBSOCKET_CLOSED => {
                capacities.remove(&operation);
                Poll::Ready(Err(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "host WebSocket closed",
                )))
            }
            HOST_WEBSOCKET_TEXT => {
                capacities.remove(&operation);
                Poll::Ready(Ok(HostWebSocketMessage::Text))
            }
            length if length >= 0 => {
                let length = length as usize;
                if length > capacity {
                    capacities.remove(&operation);
                    let _ = unsafe { cancel_operation(operation.0) };
                    return Poll::Ready(Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "host WebSocket message exceeds submitted capacity",
                    )));
                }
                let mut buffer = vec![0; length];
                let copied = unsafe {
                    take_websocket_receive(
                        operation.0,
                        buffer.as_mut_ptr() as u32,
                        buffer.len() as u32,
                    )
                };
                capacities.remove(&operation);
                if copied == length as i32 {
                    Poll::Ready(Ok(HostWebSocketMessage::Binary(buffer)))
                } else {
                    let _ = unsafe { cancel_operation(operation.0) };
                    Poll::Ready(Err(host_error("take_websocket_receive copy", copied)))
                }
            }
            code => {
                capacities.remove(&operation);
                Poll::Ready(Err(host_error("take_websocket_receive", code)))
            }
        }
    }

    fn submit_send(
        &self,
        handle: HostSocketHandle,
        operation: HostOperationId,
        source: &[u8],
    ) -> io::Result<()> {
        let length = u32::try_from(source.len()).map_err(|_| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                "WebSocket send buffer is too large",
            )
        })?;
        status("start_websocket_send", unsafe {
            start_websocket_send(handle.0, operation.0, source.as_ptr() as u32, length)
        })
    }

    fn take_send(&self, operation: HostOperationId) -> Poll<io::Result<()>> {
        match unsafe { take_websocket_send(operation.0) } {
            HOST_PENDING => Poll::Pending,
            0 => Poll::Ready(Ok(())),
            code => Poll::Ready(Err(host_error("take_websocket_send", code))),
        }
    }
}

#[cfg(feature = "wasm-host-websocket-outbound")]
pub(crate) struct WasiHostWebSocketConnector {
    runtime: crate::host::socket::HostSocketRuntime,
    io: Arc<WasiHostWebSocketIo>,
}

#[cfg(feature = "wasm-host-websocket-outbound")]
impl WasiHostWebSocketConnector {
    pub(crate) fn new(
        runtime: crate::host::socket::HostSocketRuntime,
        io: Arc<WasiHostWebSocketIo>,
    ) -> Self {
        Self { runtime, io }
    }
}

#[cfg(feature = "wasm-host-websocket-outbound")]
#[async_trait::async_trait]
impl ExternalTunnelConnector for WasiHostWebSocketConnector {
    fn supports_scheme(&self, scheme: &str) -> bool {
        matches!(scheme, "ws" | "wss")
    }

    async fn connect(&self, url: &url::Url) -> anyhow::Result<Box<dyn Tunnel>> {
        let encoded = url.as_str().as_bytes();
        let encoded_len = u32::try_from(encoded.len())
            .map_err(|_| anyhow::anyhow!("host WebSocket URL exceeds WASI guest memory"))?;
        let handle = self
            .runtime
            .run_operation(
                self.io.clone(),
                |_, operation| {
                    status("start_websocket_connect", unsafe {
                        start_websocket_connect(operation.0, encoded.as_ptr() as u32, encoded_len)
                    })
                },
                |_, operation| match unsafe { take_websocket_connect(operation.0) } {
                    value if value == i64::from(HOST_PENDING) => Poll::Pending,
                    value if value > 0 => Poll::Ready(Ok(HostSocketHandle(value as u64))),
                    value => Poll::Ready(Err(host_error(
                        "take_websocket_connect",
                        i32::try_from(value).unwrap_or(i32::MIN),
                    ))),
                },
                |io, operation| io.cancel_operation(operation),
            )
            .await?;
        let local_url = url::Url::parse(&format!("{}://0.0.0.0:0", url.scheme()))?;
        Ok(crate::tunnel::host_websocket::new_host_websocket_tunnel(
            self.runtime.clone(),
            self.io.clone(),
            handle,
            local_url,
            url.clone(),
            None,
        ))
    }
}

#[cfg(not(feature = "wasm-host-websocket-outbound"))]
type HostWebSocketTunnelQueue = HostListenerQueue<Box<dyn Tunnel>>;

/// Owns the Host WebSocket I/O Adapter and its listener admission queue.
#[cfg(not(feature = "wasm-host-websocket-outbound"))]
pub(crate) struct WasiHostWebSocketIngress {
    runtime: crate::host::socket::HostSocketRuntime,
    io: Arc<WasiHostWebSocketIo>,
    queue: Arc<HostWebSocketTunnelQueue>,
}

#[cfg(not(feature = "wasm-host-websocket-outbound"))]
impl WasiHostWebSocketIngress {
    pub(crate) fn new(runtime: crate::host::socket::HostSocketRuntime) -> Self {
        Self::with_io(runtime, Arc::new(WasiHostWebSocketIo::default()))
    }

    pub(crate) fn with_io(
        runtime: crate::host::socket::HostSocketRuntime,
        io: Arc<WasiHostWebSocketIo>,
    ) -> Self {
        Self {
            runtime,
            io,
            queue: Arc::new(HostListenerQueue::new(MAX_PENDING_HOST_WEBSOCKETS)),
        }
    }

    pub(crate) fn listener_factory<TcpSocket>(
        &self,
    ) -> Arc<dyn ExternalListenerFactory<AcceptedTransport<TcpSocket>>>
    where
        TcpSocket: VirtualTcpSocket,
    {
        Arc::new(WasiHostWebSocketListenerFactory {
            queue: self.queue.clone(),
        })
    }

    pub(crate) fn accept(
        &self,
        handle: HostSocketHandle,
        metadata: crate::wasi::schema::WasiHostWebSocketMetadata,
    ) -> anyhow::Result<()> {
        let crate::wasi::schema::WasiHostWebSocketMetadata {
            local_url,
            remote_url,
            resolved_remote_url,
            ..
        } = metadata;
        self.queue.enqueue_with(|| {
            crate::tunnel::host_websocket::new_host_websocket_tunnel(
                self.runtime.clone(),
                self.io.clone(),
                handle,
                local_url,
                remote_url,
                resolved_remote_url,
            )
        })
    }
}

#[cfg(not(feature = "wasm-host-websocket-outbound"))]
struct WasiHostWebSocketListenerFactory {
    queue: Arc<HostWebSocketTunnelQueue>,
}

#[cfg(not(feature = "wasm-host-websocket-outbound"))]
impl<TcpSocket> ExternalListenerFactory<AcceptedTransport<TcpSocket>>
    for WasiHostWebSocketListenerFactory
where
    TcpSocket: VirtualTcpSocket,
{
    fn supports_scheme(&self, scheme: &str) -> bool {
        matches!(scheme, "ws" | "wss")
    }

    fn create(
        &self,
        request: ExternalListenerRequest,
    ) -> Box<dyn SocketListener<Accepted = AcceptedTransport<TcpSocket>>> {
        Box::new(WasiHostWebSocketListener {
            registered: self.queue.register_listener(),
            queue: self.queue.clone(),
            local_url: request.url,
            tcp_socket: PhantomData,
        })
    }
}

#[cfg(not(feature = "wasm-host-websocket-outbound"))]
struct WasiHostWebSocketListener<TcpSocket> {
    registered: bool,
    queue: Arc<HostWebSocketTunnelQueue>,
    local_url: url::Url,
    tcp_socket: PhantomData<fn() -> TcpSocket>,
}

#[cfg(not(feature = "wasm-host-websocket-outbound"))]
impl<TcpSocket> fmt::Debug for WasiHostWebSocketListener<TcpSocket> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("WasiHostWebSocketListener")
            .field("local_url", &self.local_url)
            .field("registered", &self.registered)
            .finish()
    }
}

#[async_trait::async_trait]
#[cfg(not(feature = "wasm-host-websocket-outbound"))]
impl<TcpSocket> SocketListener for WasiHostWebSocketListener<TcpSocket>
where
    TcpSocket: VirtualTcpSocket,
{
    type Accepted = AcceptedTransport<TcpSocket>;

    async fn listen(&mut self) -> anyhow::Result<()> {
        if !self.registered {
            anyhow::bail!("Host WebSocket listener queue is closed");
        }
        Ok(())
    }

    async fn accept(&mut self) -> anyhow::Result<Self::Accepted> {
        let tunnel = self
            .queue
            .accept()
            .await
            .ok_or_else(|| anyhow::anyhow!("Host WebSocket listener queue is closed"))?;
        Ok(AcceptedTransport::Tunnel {
            tunnel,
            local_url: self.local_url.clone(),
        })
    }

    fn local_url(&self) -> url::Url {
        self.local_url.clone()
    }
}

#[cfg(not(feature = "wasm-host-websocket-outbound"))]
impl<TcpSocket> Drop for WasiHostWebSocketListener<TcpSocket> {
    fn drop(&mut self) {
        if self.registered {
            self.queue.unregister_listener();
        }
    }
}
