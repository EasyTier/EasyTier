use super::{reactor::Reactor, socket_allocator::SocketHandle};
use futures::future::{self, poll_fn};
use futures::{ready, Stream};
pub use smoltcp::socket::tcp;
use smoltcp::wire::{IpAddress, IpEndpoint};
use std::mem::replace;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::{
    io,
    net::SocketAddr,
    pin::Pin,
    sync::Arc,
    task::{Context, Poll},
};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

/// A TCP socket server, listening for connections.
///
/// You can accept a new connection by using the accept method.
pub struct TcpListener {
    handle: SocketHandle,
    reactor: Arc<Reactor>,
    local_addr: SocketAddr,
}

fn map_err<E: std::error::Error>(e: E) -> io::Error {
    io::Error::new(io::ErrorKind::Other, e.to_string())
}

impl TcpListener {
    pub(super) async fn new(
        reactor: Arc<Reactor>,
        local_endpoint: IpEndpoint,
    ) -> io::Result<TcpListener> {
        let handle = reactor.socket_allocator().new_tcp_socket();
        {
            let mut socket = reactor.get_socket::<tcp::Socket>(*handle);
            socket.listen(local_endpoint).map_err(map_err)?;
        }

        let local_addr = ep2sa(&local_endpoint);
        Ok(TcpListener {
            handle,
            reactor,
            local_addr,
        })
    }
    pub fn poll_accept(
        &mut self,
        cx: &mut Context<'_>,
    ) -> Poll<io::Result<(TcpStream, SocketAddr)>> {
        let mut socket = self.reactor.get_socket::<tcp::Socket>(*self.handle);

        if socket.state() == tcp::State::Established {
            drop(socket);
            return Poll::Ready(Ok(TcpStream::accept(self)?));
        }
        socket.register_send_waker(cx.waker());
        Poll::Pending
    }
    pub async fn accept(&mut self) -> io::Result<(TcpStream, SocketAddr)> {
        poll_fn(|cx| self.poll_accept(cx)).await
    }
    pub fn incoming(self) -> Incoming {
        Incoming(self)
    }
    pub fn local_addr(&self) -> io::Result<SocketAddr> {
        Ok(self.local_addr)
    }

    pub fn relisten(&mut self) {
        let mut socket = self.reactor.get_socket::<tcp::Socket>(*self.handle);
        let local_endpoint = socket.local_endpoint().unwrap();
        socket.abort();
        socket.listen(local_endpoint).unwrap();
        self.reactor.notify();
    }

    pub fn is_listening(&self) -> bool {
        let socket = self.reactor.get_socket::<tcp::Socket>(*self.handle);
        socket.is_listening()
    }
}

pub struct Incoming(TcpListener);

impl Stream for Incoming {
    type Item = io::Result<TcpStream>;
    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        let (tcp, _) = ready!(self.0.poll_accept(cx))?;
        Poll::Ready(Some(Ok(tcp)))
    }
}

fn ep2sa(ep: &IpEndpoint) -> SocketAddr {
    match ep.addr {
        IpAddress::Ipv4(v4) => SocketAddr::new(IpAddr::V4(Ipv4Addr::from(v4)), ep.port),
        IpAddress::Ipv6(v6) => SocketAddr::new(IpAddr::V6(Ipv6Addr::from(v6)), ep.port),
        #[allow(unreachable_patterns)]
        _ => unreachable!(),
    }
}

/// A TCP stream between a local and a remote socket.
pub struct TcpStream {
    handle: SocketHandle,
    reactor: Arc<Reactor>,
    local_addr: SocketAddr,
    peer_addr: SocketAddr,
}

impl TcpStream {
    pub(super) async fn connect(
        reactor: Arc<Reactor>,
        local_endpoint: IpEndpoint,
        remote_endpoint: IpEndpoint,
    ) -> io::Result<TcpStream> {
        let handle = reactor.socket_allocator().new_tcp_socket();

        reactor
            .get_socket::<tcp::Socket>(*handle)
            .connect(&mut reactor.context(), remote_endpoint, local_endpoint)
            .map_err(map_err)?;

        let local_addr = ep2sa(&local_endpoint);
        let peer_addr = ep2sa(&remote_endpoint);
        let tcp = TcpStream {
            handle,
            reactor,
            local_addr,
            peer_addr,
        };

        tcp.reactor.notify();
        future::poll_fn(|cx| tcp.poll_connected(cx)).await?;

        Ok(tcp)
    }

    fn accept(listener: &mut TcpListener) -> io::Result<(TcpStream, SocketAddr)> {
        let reactor = listener.reactor.clone();
        let new_handle = reactor.socket_allocator().new_tcp_socket();
        {
            let mut new_socket = reactor.get_socket::<tcp::Socket>(*new_handle);
            new_socket.listen(listener.local_addr).map_err(map_err)?;
        }
        let (peer_addr, local_addr) = {
            let socket = reactor.get_socket::<tcp::Socket>(*listener.handle);
            (
                // should be Some, because the state is Established
                ep2sa(&socket.remote_endpoint().unwrap()),
                ep2sa(&socket.local_endpoint().unwrap()),
            )
        };

        Ok((
            TcpStream {
                handle: replace(&mut listener.handle, new_handle),
                reactor: reactor.clone(),
                local_addr,
                peer_addr,
            },
            peer_addr,
        ))
    }

    pub fn local_addr(&self) -> io::Result<SocketAddr> {
        Ok(self.local_addr)
    }
    pub fn peer_addr(&self) -> io::Result<SocketAddr> {
        Ok(self.peer_addr)
    }
    pub fn poll_connected(&self, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let mut socket = self.reactor.get_socket::<tcp::Socket>(*self.handle);
        if socket.state() == tcp::State::Established {
            return Poll::Ready(Ok(()));
        }
        socket.register_send_waker(cx.waker());
        Poll::Pending
    }
}

impl AsyncRead for TcpStream {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let mut socket = self.reactor.get_socket::<tcp::Socket>(*self.handle);
        if !socket.may_recv() {
            return Poll::Ready(Ok(()));
        }
        if socket.can_recv() {
            let read = socket
                .recv_slice(buf.initialize_unfilled())
                .map_err(map_err)?;
            self.reactor.notify();
            buf.advance(read);
            return Poll::Ready(Ok(()));
        }
        socket.register_recv_waker(cx.waker());
        Poll::Pending
    }
}

impl AsyncWrite for TcpStream {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<Result<usize, io::Error>> {
        let mut socket = self.reactor.get_socket::<tcp::Socket>(*self.handle);
        if !socket.may_send() {
            return Poll::Ready(Err(io::ErrorKind::BrokenPipe.into()));
        }
        if socket.can_send() {
            let r = socket.send_slice(buf).map_err(map_err)?;
            self.reactor.notify();
            return Poll::Ready(Ok(r));
        }
        socket.register_send_waker(cx.waker());
        Poll::Pending
    }
    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), io::Error>> {
        let mut socket = self.reactor.get_socket::<tcp::Socket>(*self.handle);
        if !socket.may_send() {
            return Poll::Ready(Err(io::ErrorKind::BrokenPipe.into()));
        }
        if socket.send_queue() == 0 {
            return Poll::Ready(Ok(()));
        }
        socket.register_send_waker(cx.waker());
        Poll::Pending
    }
    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), io::Error>> {
        let mut socket = self.reactor.get_socket::<tcp::Socket>(*self.handle);

        if socket.is_open() {
            socket.close();
            self.reactor.notify();
        }
        if socket.state() == tcp::State::Closed {
            return Poll::Ready(Ok(()));
        }

        socket.register_send_waker(cx.waker());
        Poll::Pending
    }
}
