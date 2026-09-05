use super::{
    device::{BufferDevice, Packet},
    socket::TCP_LISTENER_MAX_PENDING,
    socket_allocator::{
        BufferSize, SocketAlloctor, SocketHandle as OwnedSocketHandle, TCP_LISTENER_TIMEOUT,
        TCP_TIMEOUT,
    },
};
use futures::{FutureExt, SinkExt, StreamExt, stream::iter};
use parking_lot::{MappedMutexGuard, Mutex, MutexGuard};
use smoltcp::{
    iface::{Context, Interface, SocketHandle as SmolSocketHandle, SocketSet},
    socket::{AnySocket, Socket, tcp},
    time::{Duration, Instant},
    wire::{
        IpAddress, IpEndpoint, IpProtocol, Ipv4Packet, Ipv6ExtHeader, Ipv6ExtHeaderRepr,
        Ipv6Packet, TcpPacket,
    },
};
use std::{
    collections::VecDeque,
    future::Future,
    io,
    sync::Arc,
    task::{Context as TaskContext, Poll, Waker},
};
use tokio::{pin, select, sync::Notify};

use crate::foundation::time::sleep;

pub(crate) type BufferInterface = Arc<Mutex<Interface>>;
const MAX_BURST_SIZE: usize = 100;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) struct TcpListenerId(u64);

struct TcpListenerEntry {
    id: TcpListenerId,
    local_endpoint: IpEndpoint,
    // Raw handles stay owned by the listener until accept transfers one to TcpStream.
    pending: Vec<SmolSocketHandle>,
    accept_waker: Option<Waker>,
}

#[derive(Default)]
struct TcpListenerRegistry {
    next_id: u64,
    entries: Vec<TcpListenerEntry>,
}

type SharedTcpListenerRegistry = Arc<Mutex<TcpListenerRegistry>>;

pub(crate) struct Reactor {
    notify: Arc<Notify>,
    iface: BufferInterface,
    socket_allocator: SocketAlloctor,
    tcp_listeners: SharedTcpListenerRegistry,
}

async fn receive(
    async_iface: &mut impl super::device::AsyncDevice,
    recv_buf: &mut VecDeque<Packet>,
) -> io::Result<()> {
    if let Some(packet) = async_iface.next().await {
        recv_buf.push_back(packet?);
    }
    Ok(())
}

fn tcp_syn_endpoints(packet: &[u8]) -> Option<(IpEndpoint, IpEndpoint)> {
    let (src_addr, dst_addr, payload) = match packet.first()? >> 4 {
        4 => {
            let packet = Ipv4Packet::new_checked(packet).ok()?;
            if packet.next_header() != IpProtocol::Tcp {
                return None;
            }
            (
                IpAddress::Ipv4(packet.src_addr()),
                IpAddress::Ipv4(packet.dst_addr()),
                packet.payload(),
            )
        }
        6 => {
            let packet = Ipv6Packet::new_checked(packet).ok()?;
            let mut next_header = packet.next_header();
            let mut payload = packet.payload();
            if next_header == IpProtocol::HopByHop {
                let header = Ipv6ExtHeader::new_checked(payload).ok()?;
                let repr = Ipv6ExtHeaderRepr::parse(&header).ok()?;
                next_header = repr.next_header;
                payload = &payload[repr.header_len() + repr.data.len()..];
            }
            if next_header != IpProtocol::Tcp {
                return None;
            }
            (
                IpAddress::Ipv6(packet.src_addr()),
                IpAddress::Ipv6(packet.dst_addr()),
                payload,
            )
        }
        _ => return None,
    };
    let packet = TcpPacket::new_checked(payload).ok()?;
    if !packet.syn() || packet.ack() || packet.rst() || packet.fin() {
        return None;
    }
    Some((
        IpEndpoint::new(src_addr, packet.src_port()),
        IpEndpoint::new(dst_addr, packet.dst_port()),
    ))
}

fn tcp_tuple_exists(
    sockets: &SocketSet<'_>,
    remote_endpoint: IpEndpoint,
    local_endpoint: IpEndpoint,
) -> bool {
    sockets.iter().any(|(_, socket)| {
        let Socket::Tcp(socket) = socket else {
            return false;
        };
        socket.state() != smoltcp::socket::tcp::State::Closed
            && socket.remote_endpoint() == Some(remote_endpoint)
            && socket.local_endpoint() == Some(local_endpoint)
    })
}

fn tcp_listener_connection_ready(state: tcp::State) -> bool {
    matches!(state, tcp::State::Established | tcp::State::CloseWait)
}

fn prepare_tcp_listener_socket(
    remote_endpoint: IpEndpoint,
    local_endpoint: IpEndpoint,
    listeners: &mut TcpListenerRegistry,
    sockets: &mut SocketSet<'static>,
    socket_allocator: &SocketAlloctor,
) -> bool {
    let Some(listener) = listeners
        .entries
        .iter_mut()
        .find(|listener| listener.local_endpoint == local_endpoint)
    else {
        return false;
    };
    if listener.pending.len() >= TCP_LISTENER_MAX_PENDING {
        return false;
    }
    // Keep the global lookup off the rejected-SYN path. Once pending is full,
    // retransmissions can still reach their exact socket without a new Listen socket.
    if tcp_tuple_exists(sockets, remote_endpoint, local_endpoint) {
        return false;
    }
    // The socket exists only for this packet. update_tcp_listeners removes it unless
    // smoltcp binds it to the SYN's four-tuple.
    match socket_allocator.add_tcp_listener_socket(sockets, local_endpoint) {
        Ok(handle) => {
            listener.pending.push(handle);
            true
        }
        Err(error) => {
            tracing::error!(
                target: "easytier_core::gateway::smoltcp",
                ?error,
                ?local_endpoint,
                "failed to allocate TCP listener socket"
            );
            false
        }
    }
}

fn update_tcp_listeners(
    listeners: &mut TcpListenerRegistry,
    sockets: &mut SocketSet<'static>,
) -> Vec<Waker> {
    let mut wakers = Vec::new();
    for listener in &mut listeners.entries {
        let mut index = 0;
        let mut ready = false;
        while index < listener.pending.len() {
            let handle = listener.pending[index];
            let state = sockets.get::<tcp::Socket>(handle).state();
            if matches!(state, tcp::State::Closed | tcp::State::Listen) {
                listener.pending.swap_remove(index);
                sockets.remove(handle);
                continue;
            }
            if tcp_listener_connection_ready(state) {
                let socket = sockets.get_mut::<tcp::Socket>(handle);
                if socket.timeout() == Some(TCP_LISTENER_TIMEOUT) {
                    socket.set_timeout(Some(TCP_TIMEOUT));
                }
                ready = true;
            }
            index += 1;
        }
        if ready && let Some(waker) = listener.accept_waker.take() {
            wakers.push(waker);
        }
    }
    wakers
}

async fn run(
    mut async_iface: impl super::device::AsyncDevice,
    iface: BufferInterface,
    mut device: BufferDevice,
    socket_allocator: SocketAlloctor,
    tcp_listeners: SharedTcpListenerRegistry,
    notify: Arc<Notify>,
    stopper: Arc<Notify>,
) -> io::Result<()> {
    let default_timeout = Duration::from_secs(60);
    let timer = sleep(default_timeout.into());
    let max_burst_size = async_iface
        .capabilities()
        .max_burst_size
        .unwrap_or(MAX_BURST_SIZE);
    let mut recv_buf = VecDeque::with_capacity(max_burst_size);
    pin!(timer);

    loop {
        let packets = device.take_send_queue();

        async_iface.send_all(&mut iter(packets).map(Ok)).await?;

        if recv_buf.is_empty() && device.need_wait() {
            let start = Instant::now();
            let deadline = {
                iface
                    .lock()
                    .poll_delay(start, &socket_allocator.sockets().lock())
                    .unwrap_or(default_timeout)
            };

            if deadline != Duration::ZERO {
                timer
                    .as_mut()
                    .reset(crate::foundation::time::Instant::now() + deadline.into());
                select! {
                    _ = &mut timer => {},
                    _ = receive(&mut async_iface,&mut recv_buf) => {}
                    _ = notify.notified() => {}
                    _ = stopper.notified() => break,
                };
            }

            while let (true, Some(Ok(p))) = (
                recv_buf.len() < max_burst_size,
                async_iface.next().now_or_never().flatten(),
            ) {
                recv_buf.push_back(p);
            }
        }

        let now = Instant::now();
        let mut iface = iface.lock();
        let mut listeners = tcp_listeners.lock();
        let mut sockets = socket_allocator.sockets().lock();
        let recv_count = device.avaliable_recv_queue().min(recv_buf.len());
        let mut listener_wakers = Vec::new();
        for packet in recv_buf.drain(..recv_count) {
            let listener_socket_added =
                if let Some((remote_endpoint, local_endpoint)) = tcp_syn_endpoints(&packet) {
                    // Advance timers, reclaim stale pending sockets, and preserve packet
                    // order before exposing a generic Listen socket.
                    iface.poll(now, &mut device, &mut sockets);
                    listener_wakers.extend(update_tcp_listeners(&mut listeners, &mut sockets));
                    prepare_tcp_listener_socket(
                        remote_endpoint,
                        local_endpoint,
                        &mut listeners,
                        &mut sockets,
                        &socket_allocator,
                    )
                } else {
                    false
                };
            device.push_recv_queue(std::iter::once(packet));
            if listener_socket_added {
                // Bind the generic Listen socket to this SYN before another packet
                // can be dispatched to it.
                iface.poll_ingress_single(now, &mut device, &mut sockets);
                listener_wakers.extend(update_tcp_listeners(&mut listeners, &mut sockets));
            }
        }

        iface.poll(now, &mut device, &mut sockets);
        listener_wakers.extend(update_tcp_listeners(&mut listeners, &mut sockets));

        // wake up all closed sockets (smoltcp seems have a bug that it doesn't wake up closed sockets)
        for (_, socket) in sockets.iter_mut() {
            if let Socket::Tcp(tcp) = socket
                && tcp.state() == smoltcp::socket::tcp::State::Closed
            {
                tcp.abort();
            }
        }
        drop(sockets);
        drop(listeners);
        drop(iface);
        for waker in listener_wakers {
            waker.wake();
        }
    }

    Ok(())
}

impl Reactor {
    pub fn new(
        async_device: impl super::device::AsyncDevice,
        iface: Interface,
        device: BufferDevice,
        buffer_size: BufferSize,
        stopper: Arc<Notify>,
    ) -> (Self, impl Future<Output = io::Result<()>> + Send) {
        let iface = Arc::new(Mutex::new(iface));
        let notify = Arc::new(Notify::new());
        let socket_allocator = SocketAlloctor::new(buffer_size);
        let tcp_listeners = Arc::new(Mutex::new(TcpListenerRegistry::default()));
        let fut = run(
            async_device,
            iface.clone(),
            device,
            socket_allocator.clone(),
            tcp_listeners.clone(),
            notify.clone(),
            stopper,
        );

        (
            Reactor {
                notify,
                iface,
                socket_allocator,
                tcp_listeners,
            },
            fut,
        )
    }
    pub fn get_socket<T: AnySocket<'static>>(
        &self,
        handle: SmolSocketHandle,
    ) -> MappedMutexGuard<'_, T> {
        MutexGuard::map(
            self.socket_allocator.sockets().lock(),
            |sockets: &mut smoltcp::iface::SocketSet<'_>| sockets.get_mut::<T>(handle),
        )
    }
    pub fn context(&self) -> MappedMutexGuard<'_, Context> {
        MutexGuard::map(self.iface.lock(), |iface| iface.context())
    }
    pub fn socket_allocator(&self) -> &SocketAlloctor {
        &self.socket_allocator
    }
    pub(super) fn register_tcp_listener(
        &self,
        local_endpoint: IpEndpoint,
    ) -> io::Result<TcpListenerId> {
        let mut listeners = self.tcp_listeners.lock();
        if listeners
            .entries
            .iter()
            .any(|listener| listener.local_endpoint == local_endpoint)
        {
            return Err(io::ErrorKind::AddrInUse.into());
        }
        let id = TcpListenerId(listeners.next_id);
        listeners.next_id += 1;
        listeners.entries.push(TcpListenerEntry {
            id,
            local_endpoint,
            pending: Vec::new(),
            accept_waker: None,
        });
        Ok(id)
    }
    pub(super) fn poll_tcp_accept(
        &self,
        id: TcpListenerId,
        cx: &TaskContext<'_>,
    ) -> Poll<io::Result<(OwnedSocketHandle, IpEndpoint, IpEndpoint)>> {
        let mut listeners = self.tcp_listeners.lock();
        let Some(listener) = listeners
            .entries
            .iter_mut()
            .find(|listener| listener.id == id)
        else {
            return Poll::Ready(Err(io::ErrorKind::NotConnected.into()));
        };
        let mut sockets = self.socket_allocator.sockets().lock();
        let mut index = 0;
        while index < listener.pending.len() {
            let handle = listener.pending[index];
            let (state, endpoints) = {
                let socket = sockets.get::<tcp::Socket>(handle);
                (
                    socket.state(),
                    (socket.remote_endpoint(), socket.local_endpoint()),
                )
            };
            if matches!(state, tcp::State::Closed | tcp::State::Listen) {
                listener.pending.swap_remove(index);
                sockets.remove(handle);
                continue;
            }
            if tcp_listener_connection_ready(state) {
                let handle = listener.pending.swap_remove(index);
                let (Some(remote_endpoint), Some(local_endpoint)) = endpoints else {
                    sockets.remove(handle);
                    return Poll::Ready(Err(io::ErrorKind::NotConnected.into()));
                };
                drop(sockets);
                drop(listeners);
                return Poll::Ready(Ok((
                    self.socket_allocator.own_socket(handle),
                    remote_endpoint,
                    local_endpoint,
                )));
            }
            index += 1;
        }
        if listener
            .accept_waker
            .as_ref()
            .is_none_or(|waker| !waker.will_wake(cx.waker()))
        {
            listener.accept_waker = Some(cx.waker().clone());
        }
        Poll::Pending
    }
    pub(super) fn unregister_tcp_listener(&self, id: TcpListenerId) {
        let mut listeners = self.tcp_listeners.lock();
        let Some(index) = listeners
            .entries
            .iter()
            .position(|listener| listener.id == id)
        else {
            return;
        };
        let listener = listeners.entries.swap_remove(index);
        let mut sockets = self.socket_allocator.sockets().lock();
        for handle in listener.pending {
            sockets.remove(handle);
        }
    }
    #[cfg(test)]
    pub(super) fn tcp_listener_handles(&self, id: TcpListenerId) -> Vec<SmolSocketHandle> {
        self.tcp_listeners
            .lock()
            .entries
            .iter()
            .find(|listener| listener.id == id)
            .map(|listener| listener.pending.clone())
            .unwrap_or_default()
    }
    pub fn notify(&self) {
        // The externally driven WASI runtime can park immediately after a
        // socket enqueues work. Keep one permit when the reactor has not
        // reached its select yet; notify_waiters() would lose that edge.
        self.notify.notify_one();
    }
    pub fn iface(&self) -> &BufferInterface {
        &self.iface
    }
}

impl Drop for Reactor {
    fn drop(&mut self) {
        for (_, socket) in self.socket_allocator.sockets().lock().iter_mut() {
            if let Socket::Tcp(tcp) = socket {
                tcp.close()
            }
        }
    }
}
