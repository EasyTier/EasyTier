use super::{
    device::{BufferDevice, Packet},
    socket_allocator::{BufferSize, SocketAlloctor},
};
use futures::{stream::iter, FutureExt, SinkExt, StreamExt};
use parking_lot::{MappedMutexGuard, Mutex, MutexGuard};
use smoltcp::{
    iface::{Context, Interface, SocketHandle},
    socket::{AnySocket, Socket},
    time::{Duration, Instant},
};
use std::{collections::VecDeque, future::Future, io, sync::Arc};
use tokio::{pin, select, sync::Notify, time::sleep};

pub(crate) type BufferInterface = Arc<Mutex<Interface>>;
const MAX_BURST_SIZE: usize = 100;

pub(crate) struct Reactor {
    notify: Arc<Notify>,
    iface: BufferInterface,
    socket_allocator: SocketAlloctor,
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

async fn run(
    mut async_iface: impl super::device::AsyncDevice,
    iface: BufferInterface,
    mut device: BufferDevice,
    socket_allocator: SocketAlloctor,
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

        async_iface
            .send_all(&mut iter(packets).map(|p| Ok(p)))
            .await?;

        if recv_buf.is_empty() && device.need_wait() {
            let start = Instant::now();
            let deadline = {
                iface
                    .lock()
                    .poll_delay(start, &socket_allocator.sockets().lock())
                    .unwrap_or(default_timeout)
            };

            timer
                .as_mut()
                .reset(tokio::time::Instant::now() + deadline.into());
            select! {
                _ = &mut timer => {},
                _ = receive(&mut async_iface,&mut recv_buf) => {}
                _ = notify.notified() => {}
                _ = stopper.notified() => break,
            };

            while let (true, Some(Ok(p))) = (
                recv_buf.len() < max_burst_size,
                async_iface.next().now_or_never().flatten(),
            ) {
                recv_buf.push_back(p);
            }
        }

        let mut iface = iface.lock();

        device.push_recv_queue(recv_buf.drain(..device.avaliable_recv_queue().min(recv_buf.len())));

        iface.poll(
            Instant::now(),
            &mut device,
            &mut socket_allocator.sockets().lock(),
        );

        // wake up all closed sockets (smoltcp seems have a bug that it doesn't wake up closed sockets)
        for (_, socket) in socket_allocator.sockets().lock().iter_mut() {
            match socket {
                Socket::Tcp(tcp) => {
                    if tcp.state() == smoltcp::socket::tcp::State::Closed {
                        tcp.abort();
                    }
                }
                #[allow(unreachable_patterns)]
                _ => {}
            }
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
        let fut = run(
            async_device,
            iface.clone(),
            device,
            socket_allocator.clone(),
            notify.clone(),
            stopper,
        );

        (
            Reactor {
                notify,
                iface: iface.clone(),
                socket_allocator,
            },
            fut,
        )
    }
    pub fn get_socket<T: AnySocket<'static>>(
        &self,
        handle: SocketHandle,
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
    pub fn notify(&self) {
        self.notify.notify_waiters();
    }
    pub fn iface(&self) -> &BufferInterface {
        &self.iface
    }
}

impl Drop for Reactor {
    fn drop(&mut self) {
        for (_, socket) in self.socket_allocator.sockets().lock().iter_mut() {
            match socket {
                Socket::Tcp(tcp) => tcp.close(),
                #[allow(unreachable_patterns)]
                _ => {}
            }
        }
    }
}
