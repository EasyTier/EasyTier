//! TCP stream and listener resources exposed by the data plane.

use std::{
    future::Future,
    net::SocketAddr,
    pin::Pin,
    task::{Context, Poll},
};

use tokio::io::{AsyncRead, AsyncWrite};

use crate::gateway::smoltcp::TcpListener;

use super::{
    DataPlaneIoGuard, DataPlaneLease, DataPlaneTcpIo, FlowData, FlowKey, FlowLease, FlowSet,
    TCP_ENTRY,
};

/// Tracks how an established stream keeps its inbound flow alive.
pub(super) enum DataPlaneTcpStreamRoute {
    Outbound { _flow: FlowLease<FlowData> },
    Accepted { _flow: FlowLease<FlowData> },
    External,
}

/// A TCP stream created by the data-plane API.
pub struct DataPlaneTcpStream {
    pub(super) stream: DataPlaneTcpIo,
    pub(super) local_addr: SocketAddr,
    pub(super) _route: DataPlaneTcpStreamRoute,
    pub(super) _data_plane_lease: Option<DataPlaneLease>,
    generation: DataPlaneIoGuard,
    read_closed: Pin<Box<dyn Future<Output = ()> + Send>>,
    write_closed: Pin<Box<dyn Future<Output = ()> + Send>>,
}

/// A TCP listener created by the data-plane API.
pub struct DataPlaneTcpListener {
    pub(super) listener: TcpListener,
    pub(super) local_addr: SocketAddr,
    pub(super) flows: FlowSet,
    pub(super) _listen_flow: FlowLease<FlowData>,
    pub(super) data_plane_lease: DataPlaneLease,
    pub(super) generation: DataPlaneIoGuard,
}

impl DataPlaneTcpStream {
    pub(super) fn new(
        stream: DataPlaneTcpIo,
        local_addr: SocketAddr,
        data_plane_lease: Option<DataPlaneLease>,
        route: DataPlaneTcpStreamRoute,
        generation: DataPlaneIoGuard,
    ) -> Self {
        Self {
            stream,
            local_addr,
            _data_plane_lease: data_plane_lease,
            _route: route,
            read_closed: generation.closed_future(),
            write_closed: generation.closed_future(),
            generation,
        }
    }

    pub fn local_addr(&self) -> SocketAddr {
        self.local_addr
    }
}

impl DataPlaneTcpListener {
    pub fn local_addr(&self) -> SocketAddr {
        self.local_addr
    }

    pub async fn accept(&mut self) -> Result<(DataPlaneTcpStream, SocketAddr), std::io::Error> {
        self.generation
            .ensure_open()
            .map_err(|error| error.into_io_error())?;
        let generation = self.generation.clone();
        let (stream, peer_addr) = tokio::select! {
            biased;
            _ = generation.closed() => {
                return Err(generation.closed_io_error());
            }
            result = self.listener.accept() => result?,
        };
        generation
            .ensure_open()
            .map_err(|error| error.into_io_error())?;
        let local_addr = stream.local_addr()?;
        let (flow, _) = FlowLease::register(
            self.flows.clone(),
            FlowKey {
                src: local_addr,
                dst: peer_addr,
                kind: TCP_ENTRY,
            },
            FlowData::DataPlaneRoute,
        );
        let accepted = DataPlaneTcpStream::new(
            Box::new(stream),
            local_addr,
            Some(self.data_plane_lease.clone()),
            DataPlaneTcpStreamRoute::Accepted { _flow: flow },
            generation,
        );
        Ok((accepted, peer_addr))
    }
}

impl AsyncRead for DataPlaneTcpStream {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        let this = self.get_mut();
        if this.generation.ensure_open().is_err() || this.read_closed.as_mut().poll(cx).is_ready() {
            return Poll::Ready(Err(this.generation.closed_io_error()));
        }
        Pin::new(&mut this.stream).poll_read(cx, buf)
    }
}

impl AsyncWrite for DataPlaneTcpStream {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<Result<usize, std::io::Error>> {
        let this = self.get_mut();
        if this.generation.ensure_open().is_err() || this.write_closed.as_mut().poll(cx).is_ready()
        {
            return Poll::Ready(Err(this.generation.closed_io_error()));
        }
        Pin::new(&mut this.stream).poll_write(cx, buf)
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), std::io::Error>> {
        let this = self.get_mut();
        if this.generation.ensure_open().is_err() || this.write_closed.as_mut().poll(cx).is_ready()
        {
            return Poll::Ready(Err(this.generation.closed_io_error()));
        }
        Pin::new(&mut this.stream).poll_flush(cx)
    }

    fn poll_shutdown(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Result<(), std::io::Error>> {
        let this = self.get_mut();
        if this.generation.ensure_open().is_err() || this.write_closed.as_mut().poll(cx).is_ready()
        {
            return Poll::Ready(Err(this.generation.closed_io_error()));
        }
        Pin::new(&mut this.stream).poll_shutdown(cx)
    }
}
