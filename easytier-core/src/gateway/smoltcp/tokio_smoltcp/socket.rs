use super::{
    reactor::{Reactor, TcpListenerId},
    socket_allocator::SocketHandle,
};
use futures::future::{self, poll_fn};
pub use smoltcp::socket::tcp;
use smoltcp::socket::udp;
use smoltcp::wire::{IpAddress, IpEndpoint};
use std::net::IpAddr;
use std::{
    io,
    net::SocketAddr,
    pin::Pin,
    sync::Arc,
    task::{Context, Poll},
};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

pub(super) const TCP_LISTENER_MAX_PENDING: usize = 16;

/// A TCP socket server, listening for connections.
///
/// You can accept a new connection by using the accept method.
pub struct TcpListener {
    id: TcpListenerId,
    reactor: Arc<Reactor>,
    local_addr: SocketAddr,
}

fn map_err<E: std::error::Error>(e: E) -> io::Error {
    io::Error::other(e.to_string())
}

impl TcpListener {
    pub(super) async fn new(
        reactor: Arc<Reactor>,
        local_endpoint: IpEndpoint,
    ) -> io::Result<TcpListener> {
        let id = reactor.register_tcp_listener(local_endpoint)?;
        let local_addr = ep2sa(&local_endpoint);
        Ok(TcpListener {
            id,
            reactor,
            local_addr,
        })
    }

    pub fn poll_accept(&mut self, cx: &Context<'_>) -> Poll<io::Result<(TcpStream, SocketAddr)>> {
        match self.reactor.poll_tcp_accept(self.id, cx) {
            Poll::Ready(Ok((handle, remote_endpoint, local_endpoint))) => Poll::Ready(Ok((
                TcpStream {
                    handle,
                    reactor: self.reactor.clone(),
                    local_addr: ep2sa(&local_endpoint),
                },
                ep2sa(&remote_endpoint),
            ))),
            Poll::Ready(Err(error)) => Poll::Ready(Err(error)),
            Poll::Pending => Poll::Pending,
        }
    }
    pub async fn accept(&mut self) -> io::Result<(TcpStream, SocketAddr)> {
        poll_fn(|cx| self.poll_accept(cx)).await
    }
    pub fn local_addr(&self) -> io::Result<SocketAddr> {
        Ok(self.local_addr)
    }
}

impl Drop for TcpListener {
    fn drop(&mut self) {
        self.reactor.unregister_tcp_listener(self.id);
    }
}

fn ep2sa(ep: &IpEndpoint) -> SocketAddr {
    match ep.addr {
        IpAddress::Ipv4(v4) => SocketAddr::new(IpAddr::V4(v4), ep.port),
        IpAddress::Ipv6(v6) => SocketAddr::new(IpAddr::V6(v6), ep.port),
        #[allow(unreachable_patterns)]
        _ => unreachable!(),
    }
}

fn sa2ep(addr: SocketAddr) -> IpEndpoint {
    match addr {
        SocketAddr::V4(addr) => addr.into(),
        SocketAddr::V6(addr) => addr.into(),
    }
}

/// A TCP stream between a local and a remote socket.
pub struct TcpStream {
    handle: SocketHandle,
    reactor: Arc<Reactor>,
    local_addr: SocketAddr,
}

impl TcpStream {
    pub(super) async fn connect(
        reactor: Arc<Reactor>,
        local_endpoint: IpEndpoint,
        remote_endpoint: IpEndpoint,
    ) -> io::Result<TcpStream> {
        let handle = reactor.socket_allocator().new_tcp_socket();

        // see https://github.com/spacemeowx2/tokio-smoltcp/pull/12
        let connect_result = {
            // Issue #11. We must lock the context before we call connect to
            // avoid lock inversion deadlocks, but drop it before constructing
            // the TcpStream to avoid a second mutable borror of the reactor.
            let mut context = reactor.context();
            reactor.get_socket::<tcp::Socket>(*handle).connect(
                &mut context,
                remote_endpoint,
                local_endpoint,
            )
        };
        connect_result.map_err(map_err)?;

        let local_addr = ep2sa(&local_endpoint);
        let tcp = TcpStream {
            handle,
            reactor,
            local_addr,
        };

        tcp.reactor.notify();
        future::poll_fn(|cx| tcp.poll_connected(cx)).await?;

        Ok(tcp)
    }

    pub fn local_addr(&self) -> io::Result<SocketAddr> {
        Ok(self.local_addr)
    }
    pub fn poll_connected(&self, cx: &Context<'_>) -> Poll<io::Result<()>> {
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

        if socket.may_send() {
            socket.close();
            self.reactor.notify();
        }
        if matches!(
            socket.state(),
            tcp::State::FinWait2 | tcp::State::TimeWait | tcp::State::Closed
        ) {
            return Poll::Ready(Ok(()));
        }

        socket.register_send_waker(cx.waker());
        Poll::Pending
    }
}

/// A UDP socket.
pub struct UdpSocket {
    handle: SocketHandle,
    reactor: Arc<Reactor>,
    local_addr: SocketAddr,
}

impl UdpSocket {
    pub(super) async fn new(
        reactor: Arc<Reactor>,
        local_endpoint: IpEndpoint,
    ) -> io::Result<UdpSocket> {
        let handle = reactor.socket_allocator().new_udp_socket();
        {
            let mut socket = reactor.get_socket::<udp::Socket>(*handle);
            socket.bind(local_endpoint).map_err(map_err)?;
        }

        let local_addr = ep2sa(&local_endpoint);

        Ok(UdpSocket {
            handle,
            reactor,
            local_addr,
        })
    }
    /// Note that on multiple calls to a poll_* method in the send direction, only the Waker from the Context passed to the most recent call will be scheduled to receive a wakeup.
    pub fn poll_send_to(
        &self,
        cx: &Context<'_>,
        buf: &[u8],
        target: SocketAddr,
    ) -> Poll<io::Result<usize>> {
        let mut socket = self.reactor.get_socket::<udp::Socket>(*self.handle);
        let target_ip: IpEndpoint = sa2ep(target);

        match socket.send_slice(buf, target_ip) {
            // the buffer is full
            Err(udp::SendError::BufferFull) => {}
            r => {
                r.map_err(map_err)?;
                self.reactor.notify();
                return Poll::Ready(Ok(buf.len()));
            }
        }

        socket.register_send_waker(cx.waker());
        Poll::Pending
    }
    /// See note on `poll_send_to`
    pub async fn send_to(&self, buf: &[u8], target: SocketAddr) -> io::Result<usize> {
        poll_fn(|cx| self.poll_send_to(cx, buf, target)).await
    }
    /// Note that on multiple calls to a poll_* method in the recv direction, only the Waker from the Context passed to the most recent call will be scheduled to receive a wakeup.
    pub fn poll_recv_from(
        &self,
        cx: &Context<'_>,
        buf: &mut [u8],
    ) -> Poll<io::Result<(usize, SocketAddr)>> {
        let mut socket = self.reactor.get_socket::<udp::Socket>(*self.handle);

        match socket.recv_slice(buf) {
            // the buffer is empty
            Err(udp::RecvError::Exhausted) => {}
            r => {
                let (size, metadata) = r.map_err(map_err)?;
                self.reactor.notify();
                return Poll::Ready(Ok((size, ep2sa(&metadata.endpoint))));
            }
        }

        socket.register_recv_waker(cx.waker());
        Poll::Pending
    }
    /// See note on `poll_recv_from`
    pub async fn recv_from(&self, buf: &mut [u8]) -> io::Result<(usize, SocketAddr)> {
        poll_fn(|cx| self.poll_recv_from(cx, buf)).await
    }

    pub fn poll_recv_from_limited(
        &self,
        cx: &Context<'_>,
        max_len: usize,
    ) -> Poll<io::Result<(Vec<u8>, SocketAddr, bool)>> {
        let mut socket = self.reactor.get_socket::<udp::Socket>(*self.handle);

        match socket.recv() {
            Err(udp::RecvError::Exhausted) => {}
            Err(error) => return Poll::Ready(Err(map_err(error))),
            Ok((payload, metadata)) => {
                let copy_len = payload.len().min(max_len);
                let truncated = copy_len < payload.len();
                let data = payload[..copy_len].to_vec();
                self.reactor.notify();
                return Poll::Ready(Ok((data, ep2sa(&metadata.endpoint), truncated)));
            }
        }

        socket.register_recv_waker(cx.waker());
        Poll::Pending
    }

    pub async fn recv_from_limited(
        &self,
        max_len: usize,
    ) -> io::Result<(Vec<u8>, SocketAddr, bool)> {
        poll_fn(|cx| self.poll_recv_from_limited(cx, max_len)).await
    }

    pub fn local_addr(&self) -> io::Result<SocketAddr> {
        Ok(self.local_addr)
    }
}

#[cfg(test)]
mod tests {
    use std::time::Duration as StdDuration;

    use smoltcp::{
        iface::Config,
        phy::{DeviceCapabilities, Medium},
        socket::tcp,
        time::Duration,
        wire::{HardwareAddress, Ipv4Address, TcpControl, TcpSeqNumber},
    };

    use super::super::{
        Net, NetConfig, channel_device,
        test_utils::{TcpPackets, recv_tcp, recv_tcp_for_port},
    };
    use super::{TCP_LISTENER_MAX_PENDING, TcpListener};

    const LISTEN_ADDR: Ipv4Address = Ipv4Address::new(10, 126, 126, 1);
    const LISTEN_PORT: u16 = 34569;
    const PACKETS: TcpPackets = TcpPackets::new(LISTEN_ADDR, LISTEN_PORT);

    type TestNet = (
        Net,
        tokio::sync::mpsc::Sender<std::io::Result<Vec<u8>>>,
        tokio::sync::mpsc::Receiver<Vec<u8>>,
    );

    fn test_net() -> TestNet {
        let mut capabilities = DeviceCapabilities::default();
        capabilities.max_transmission_unit = 1280;
        capabilities.medium = Medium::Ip;
        let (device, ingress, egress) = channel_device::ChannelDevice::new(capabilities);
        let net = Net::new(
            device,
            NetConfig::new(
                Config::new(HardwareAddress::Ip),
                "10.126.126.1/24".parse().unwrap(),
                Vec::new(),
                None,
            ),
        );
        (net, ingress, egress)
    }

    async fn begin_handshake(
        ingress: &tokio::sync::mpsc::Sender<std::io::Result<Vec<u8>>>,
        egress: &mut tokio::sync::mpsc::Receiver<Vec<u8>>,
        client_addr: Ipv4Address,
        client_port: u16,
        client_sequence: i32,
    ) -> TcpSeqNumber {
        ingress
            .send(Ok(PACKETS.syn(client_addr, client_port, client_sequence)))
            .await
            .unwrap();
        let syn_ack = recv_tcp_for_port(egress, client_port).await;
        assert_eq!(syn_ack.control, TcpControl::Syn);
        syn_ack.sequence
    }

    async fn finish_handshake(
        ingress: &tokio::sync::mpsc::Sender<std::io::Result<Vec<u8>>>,
        client_addr: Ipv4Address,
        client_port: u16,
        client_sequence: i32,
        server_sequence: TcpSeqNumber,
    ) {
        ingress
            .send(Ok(PACKETS.ack(
                client_addr,
                client_port,
                TcpSeqNumber(client_sequence + 1),
                server_sequence + 1,
            )))
            .await
            .unwrap();
    }

    fn listener_states(listener: &TcpListener) -> Vec<tcp::State> {
        listener
            .reactor
            .tcp_listener_handles(listener.id)
            .into_iter()
            .map(|handle| listener.reactor.get_socket::<tcp::Socket>(handle).state())
            .collect()
    }

    #[tokio::test]
    async fn duplicate_syn_does_not_consume_another_backlog_slot() {
        let (net, ingress, mut egress) = test_net();
        let listener = net
            .tcp_bind("10.126.126.1:34569".parse().unwrap())
            .await
            .unwrap();
        let client_addr = Ipv4Address::new(10, 126, 126, 2);

        {
            let sockets = listener.reactor.socket_allocator().sockets().lock();
            assert_eq!(
                sockets
                    .iter()
                    .filter(|(_, socket)| matches!(socket, smoltcp::socket::Socket::Tcp(_)))
                    .count(),
                0
            );
        }
        begin_handshake(&ingress, &mut egress, client_addr, 40000, 1000).await;

        ingress
            .send(Ok(PACKETS.syn(client_addr, 40000, 1000)))
            .await
            .unwrap();
        ingress
            .send(Ok(PACKETS.syn(client_addr, 40001, 2000)))
            .await
            .unwrap();
        recv_tcp_for_port(&mut egress, 40001).await;

        let states = listener_states(&listener);
        assert_eq!(
            states
                .iter()
                .filter(|state| **state == tcp::State::SynReceived)
                .count(),
            2
        );
    }

    #[tokio::test]
    async fn listener_accepts_new_client_while_first_handshake_is_stalled() {
        let (net, ingress, mut egress) = test_net();
        let mut listener = net
            .tcp_bind("10.126.126.1:34569".parse().unwrap())
            .await
            .unwrap();

        let first_addr = Ipv4Address::new(10, 126, 126, 2);
        begin_handshake(&ingress, &mut egress, first_addr, 40000, 1000).await;
        let states = listener_states(&listener);
        assert_eq!(
            states
                .iter()
                .filter(|state| **state == tcp::State::SynReceived)
                .count(),
            1
        );

        let second_addr = Ipv4Address::new(10, 126, 126, 3);
        let second_sequence =
            begin_handshake(&ingress, &mut egress, second_addr, 40001, 2000).await;
        for handle in listener.reactor.tcp_listener_handles(listener.id) {
            let socket = listener.reactor.get_socket::<tcp::Socket>(handle);
            assert_eq!(socket.timeout(), Some(Duration::from_secs(5)));
        }

        finish_handshake(&ingress, second_addr, 40001, 2000, second_sequence).await;
        tokio::time::timeout(StdDuration::from_secs(1), async {
            loop {
                let established_timeout = listener
                    .reactor
                    .tcp_listener_handles(listener.id)
                    .into_iter()
                    .find_map(|handle| {
                        let socket = listener.reactor.get_socket::<tcp::Socket>(handle);
                        (socket.state() == tcp::State::Established).then(|| socket.timeout())
                    });
                if let Some(timeout) = established_timeout {
                    assert_eq!(timeout, Some(Duration::from_secs(60)));
                    break;
                }
                tokio::time::sleep(StdDuration::from_millis(1)).await;
            }
        })
        .await
        .unwrap();
        let (stream, peer_addr) =
            tokio::time::timeout(StdDuration::from_secs(1), listener.accept())
                .await
                .unwrap()
                .unwrap();
        assert_eq!(peer_addr, "10.126.126.3:40001".parse().unwrap());

        let stream_socket = stream.reactor.get_socket::<tcp::Socket>(*stream.handle);
        assert_eq!(stream_socket.timeout(), Some(Duration::from_secs(60)));
        drop(stream_socket);
        assert_eq!(listener_states(&listener), vec![tcp::State::SynReceived]);

        {
            let handle = listener.reactor.tcp_listener_handles(listener.id)[0];
            let mut socket = listener.reactor.get_socket::<tcp::Socket>(handle);
            socket.set_timeout(Some(Duration::from_millis(10)));
        }
        listener.reactor.notify();
        tokio::time::timeout(StdDuration::from_secs(1), async {
            loop {
                if listener
                    .reactor
                    .tcp_listener_handles(listener.id)
                    .is_empty()
                {
                    break;
                }
                tokio::time::sleep(StdDuration::from_millis(1)).await;
            }
        })
        .await
        .unwrap();

        begin_handshake(&ingress, &mut egress, first_addr, 40002, 3000).await;
        assert_eq!(listener_states(&listener), vec![tcp::State::SynReceived]);
    }

    #[tokio::test]
    async fn listener_limits_pending_connections() {
        let (net, ingress, mut egress) = test_net();
        let mut listener = net
            .tcp_bind("10.126.126.1:34569".parse().unwrap())
            .await
            .unwrap();
        let client_addr = Ipv4Address::new(10, 126, 126, 2);
        let mut syn_ack_sequences = Vec::with_capacity(TCP_LISTENER_MAX_PENDING);

        for index in 0..TCP_LISTENER_MAX_PENDING {
            ingress
                .send(Ok(PACKETS.syn(
                    client_addr,
                    40000 + index as u16,
                    1000 + index as i32,
                )))
                .await
                .unwrap();
        }
        for _ in 0..TCP_LISTENER_MAX_PENDING {
            let syn_ack = recv_tcp(&mut egress).await;
            assert_eq!(syn_ack.control, TcpControl::Syn);
            syn_ack_sequences.push((syn_ack.dst_port, syn_ack.sequence));
        }
        syn_ack_sequences.sort_unstable_by_key(|(port, _)| *port);
        assert!(
            listener_states(&listener)
                .iter()
                .all(|state| *state == tcp::State::SynReceived)
        );

        ingress
            .send(Ok(PACKETS.syn(client_addr, 50000, 3000)))
            .await
            .unwrap();
        assert_eq!(recv_tcp(&mut egress).await.control, TcpControl::Rst);

        for (port, syn_ack_sequence) in syn_ack_sequences {
            let index = port - 40000;
            finish_handshake(
                &ingress,
                client_addr,
                port,
                1000 + index as i32,
                syn_ack_sequence,
            )
            .await;
        }

        tokio::time::timeout(StdDuration::from_secs(1), async {
            loop {
                if listener_states(&listener)
                    .iter()
                    .all(|state| *state == tcp::State::Established)
                {
                    break;
                }
                tokio::time::sleep(StdDuration::from_millis(1)).await;
            }
        })
        .await
        .unwrap();

        ingress
            .send(Ok(PACKETS.syn(client_addr, 50001, 4000)))
            .await
            .unwrap();
        assert_eq!(recv_tcp(&mut egress).await.control, TcpControl::Rst);

        let mut streams = Vec::with_capacity(TCP_LISTENER_MAX_PENDING + 1);
        let mut peer_ports = Vec::with_capacity(TCP_LISTENER_MAX_PENDING + 1);
        let (stream, peer_addr) = listener.accept().await.unwrap();
        streams.push(stream);
        peer_ports.push(peer_addr.port());

        let replacement_sequence =
            begin_handshake(&ingress, &mut egress, client_addr, 50002, 5000).await;
        finish_handshake(&ingress, client_addr, 50002, 5000, replacement_sequence).await;

        for _ in 0..TCP_LISTENER_MAX_PENDING {
            let (stream, peer_addr) =
                tokio::time::timeout(StdDuration::from_secs(1), listener.accept())
                    .await
                    .unwrap()
                    .unwrap();
            streams.push(stream);
            peer_ports.push(peer_addr.port());
        }
        peer_ports.sort_unstable();
        assert_eq!(
            peer_ports,
            (40000..40000 + TCP_LISTENER_MAX_PENDING as u16)
                .chain(std::iter::once(50002))
                .collect::<Vec<_>>()
        );
        assert!(listener_states(&listener).is_empty());
    }

    #[tokio::test]
    async fn closed_pending_connections_are_reclaimed_before_admission() {
        let (net, ingress, mut egress) = test_net();
        let listener = net
            .tcp_bind("10.126.126.1:34569".parse().unwrap())
            .await
            .unwrap();
        let client_addr = Ipv4Address::new(10, 126, 126, 2);

        for index in 0..TCP_LISTENER_MAX_PENDING {
            begin_handshake(
                &ingress,
                &mut egress,
                client_addr,
                40000 + index as u16,
                1000 + index as i32,
            )
            .await;
        }
        for handle in listener.reactor.tcp_listener_handles(listener.id) {
            listener.reactor.get_socket::<tcp::Socket>(handle).abort();
        }

        begin_handshake(&ingress, &mut egress, client_addr, 50000, 3000).await;
        assert_eq!(listener_states(&listener), vec![tcp::State::SynReceived]);
    }

    #[tokio::test]
    async fn dropping_listener_removes_pending_connections() {
        let (net, ingress, mut egress) = test_net();
        let listener = net
            .tcp_bind("10.126.126.1:34569".parse().unwrap())
            .await
            .unwrap();

        begin_handshake(
            &ingress,
            &mut egress,
            Ipv4Address::new(10, 126, 126, 2),
            40000,
            1000,
        )
        .await;
        assert_eq!(listener_states(&listener).len(), 1);

        drop(listener);
        let listener = net
            .tcp_bind("10.126.126.1:34569".parse().unwrap())
            .await
            .unwrap();
        assert!(listener_states(&listener).is_empty());
    }

    #[tokio::test]
    async fn old_syn_for_accepted_stream_does_not_create_pending_connection() {
        let (net, ingress, mut egress) = test_net();
        let mut listener = net
            .tcp_bind("10.126.126.1:34569".parse().unwrap())
            .await
            .unwrap();
        let client_addr = Ipv4Address::new(10, 126, 126, 2);

        let server_sequence =
            begin_handshake(&ingress, &mut egress, client_addr, 40000, 1000).await;
        finish_handshake(&ingress, client_addr, 40000, 1000, server_sequence).await;
        let (_stream, _) = tokio::time::timeout(StdDuration::from_secs(1), listener.accept())
            .await
            .unwrap()
            .unwrap();

        ingress
            .send(Ok(PACKETS.syn(client_addr, 40000, 1000)))
            .await
            .unwrap();
        ingress
            .send(Ok(PACKETS.syn(client_addr, 40001, 2000)))
            .await
            .unwrap();
        recv_tcp_for_port(&mut egress, 40001).await;

        assert_eq!(listener_states(&listener), vec![tcp::State::SynReceived]);
    }

    #[tokio::test]
    async fn accepts_connection_closed_by_peer_before_accept() {
        let (net, ingress, mut egress) = test_net();
        let mut listener = net
            .tcp_bind("10.126.126.1:34569".parse().unwrap())
            .await
            .unwrap();
        let client_addr = Ipv4Address::new(10, 126, 126, 2);

        let server_sequence =
            begin_handshake(&ingress, &mut egress, client_addr, 40000, 1000).await;
        finish_handshake(&ingress, client_addr, 40000, 1000, server_sequence).await;
        ingress
            .send(Ok(PACKETS.fin(
                client_addr,
                40000,
                TcpSeqNumber(1001),
                server_sequence + 1,
            )))
            .await
            .unwrap();

        let (stream, peer_addr) =
            tokio::time::timeout(StdDuration::from_secs(1), listener.accept())
                .await
                .unwrap()
                .unwrap();
        assert_eq!(peer_addr, "10.126.126.2:40000".parse().unwrap());
        let socket = stream.reactor.get_socket::<tcp::Socket>(*stream.handle);
        assert_eq!(socket.state(), tcp::State::CloseWait);
        assert_eq!(socket.timeout(), Some(Duration::from_secs(60)));
    }
}
