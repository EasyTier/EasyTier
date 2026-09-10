use std::{
    fmt,
    future::Future,
    io::{self, IoSliceMut},
    pin::Pin,
    sync::{Arc, Mutex},
    task::{Context, Poll},
};

use easytier_core::{
    connectivity::transport::ConnectedUdpSession,
    socket::udp::{UdpSession, UdpSessionSocket},
};
use quinn::{
    AsyncUdpSocket, UdpPoller,
    udp::{RecvMeta, Transmit},
};
use tokio::sync::mpsc::{self, Receiver, Sender, error::TrySendError};
use tokio_util::task::AbortOnDropHandle;

const DATAGRAM_QUEUE_CAPACITY: usize = 1024;

type SendBatch = Vec<Vec<u8>>;
type WritableFuture = Pin<Box<dyn Future<Output = io::Result<()>> + Send>>;

struct ReceivedDatagram {
    payload: Vec<u8>,
    dst_ip: Option<std::net::IpAddr>,
}

pub(crate) struct QuicUdpSessionSocket {
    _session: Arc<dyn UdpSessionSocket>,
    local_addr: std::net::SocketAddr,
    peer_addr: std::net::SocketAddr,
    incoming: Mutex<Receiver<io::Result<ReceivedDatagram>>>,
    outgoing: Sender<SendBatch>,
    _recv_task: AbortOnDropHandle<()>,
    _send_task: AbortOnDropHandle<()>,
    _session_guard: Box<dyn Send + Sync>,
}

impl fmt::Debug for QuicUdpSessionSocket {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("QuicUdpSessionSocket")
            .field("local_addr", &self.local_addr)
            .field("peer_addr", &self.peer_addr)
            .finish_non_exhaustive()
    }
}

impl QuicUdpSessionSocket {
    pub(crate) fn new(connected: ConnectedUdpSession) -> io::Result<Self> {
        let (session, session_guard) = connected.into_parts();
        Self::from_session(Arc::new(session), session_guard)
    }

    pub(crate) fn from_accepted<T>(session: UdpSession, session_guard: T) -> io::Result<Self>
    where
        T: Send + Sync + 'static,
    {
        Self::from_session(Arc::new(session), Box::new(session_guard))
    }

    fn from_session(
        session: Arc<dyn UdpSessionSocket>,
        session_guard: Box<dyn Send + Sync>,
    ) -> io::Result<Self> {
        let local_addr = session.local_addr()?;
        let peer_addr = session.peer_addr()?;
        let (incoming_tx, incoming) = mpsc::channel(DATAGRAM_QUEUE_CAPACITY);
        let (outgoing, mut outgoing_rx) = mpsc::channel::<SendBatch>(DATAGRAM_QUEUE_CAPACITY);

        let recv_session = session.clone();
        let recv_errors = incoming_tx.clone();
        let recv_task = AbortOnDropHandle::new(tokio::spawn(async move {
            let mut buffer = vec![0; 64 * 1024];
            loop {
                match recv_session.recv_with_meta(&mut buffer).await {
                    Ok((length, meta)) => {
                        let datagram = ReceivedDatagram {
                            payload: buffer[..length].to_vec(),
                            dst_ip: meta.dst_ip,
                        };
                        if incoming_tx.send(Ok(datagram)).await.is_err() {
                            break;
                        }
                    }
                    Err(error) => {
                        let _ = incoming_tx.send(Err(error)).await;
                        break;
                    }
                }
            }
        }));

        let send_session = session.clone();
        let send_task = AbortOnDropHandle::new(tokio::spawn(async move {
            while let Some(batch) = outgoing_rx.recv().await {
                for datagram in batch {
                    match send_session.send(&datagram).await {
                        Ok(length) if length == datagram.len() => {}
                        Ok(_) => {
                            let _ = recv_errors
                                .send(Err(io::Error::new(
                                    io::ErrorKind::WriteZero,
                                    "QUIC UDP session partially sent a datagram",
                                )))
                                .await;
                            return;
                        }
                        Err(error) => {
                            let _ = recv_errors.send(Err(error)).await;
                            return;
                        }
                    }
                }
            }
        }));

        Ok(Self {
            _session: session,
            local_addr,
            peer_addr,
            incoming: Mutex::new(incoming),
            outgoing,
            _recv_task: recv_task,
            _send_task: send_task,
            _session_guard: session_guard,
        })
    }

    pub(crate) fn peer_addr(&self) -> std::net::SocketAddr {
        self.peer_addr
    }

    fn send_batch(&self, transmit: &Transmit<'_>) -> io::Result<()> {
        if transmit.destination != self.peer_addr {
            return Err(io::Error::new(
                io::ErrorKind::AddrNotAvailable,
                format!(
                    "QUIC UDP session is connected to {}, not {}",
                    self.peer_addr, transmit.destination
                ),
            ));
        }

        let batch = match transmit.segment_size {
            Some(0) => {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "QUIC segment size cannot be zero",
                ));
            }
            Some(segment_size) => transmit
                .contents
                .chunks(segment_size)
                .map(<[u8]>::to_vec)
                .collect(),
            None => vec![transmit.contents.to_vec()],
        };
        self.outgoing.try_send(batch).map_err(map_try_send_error)
    }
}

fn map_try_send_error(error: TrySendError<SendBatch>) -> io::Error {
    match error {
        TrySendError::Full(_) => io::Error::new(io::ErrorKind::WouldBlock, "QUIC send queue full"),
        TrySendError::Closed(_) => {
            io::Error::new(io::ErrorKind::BrokenPipe, "QUIC UDP session closed")
        }
    }
}

struct QuicUdpSessionPoller {
    outgoing: Sender<SendBatch>,
    writable: Mutex<Option<WritableFuture>>,
}

impl fmt::Debug for QuicUdpSessionPoller {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("QuicUdpSessionPoller")
            .finish_non_exhaustive()
    }
}

impl UdpPoller for QuicUdpSessionPoller {
    fn poll_writable(self: Pin<&mut Self>, context: &mut Context<'_>) -> Poll<io::Result<()>> {
        let mut writable = self.writable.lock().unwrap();
        if writable.is_none() {
            let outgoing = self.outgoing.clone();
            *writable = Some(Box::pin(async move {
                let permit = outgoing.reserve_owned().await.map_err(|_| {
                    io::Error::new(io::ErrorKind::BrokenPipe, "QUIC UDP session closed")
                })?;
                drop(permit);
                Ok(())
            }));
        }

        match writable.as_mut().unwrap().as_mut().poll(context) {
            Poll::Ready(result) => {
                *writable = None;
                Poll::Ready(result)
            }
            Poll::Pending => Poll::Pending,
        }
    }
}

impl AsyncUdpSocket for QuicUdpSessionSocket {
    fn create_io_poller(self: Arc<Self>) -> Pin<Box<dyn UdpPoller>> {
        Box::pin(QuicUdpSessionPoller {
            outgoing: self.outgoing.clone(),
            writable: Mutex::new(None),
        })
    }

    fn try_send(&self, transmit: &Transmit<'_>) -> io::Result<()> {
        self.send_batch(transmit)
    }

    fn poll_recv(
        &self,
        context: &mut Context<'_>,
        buffers: &mut [IoSliceMut<'_>],
        meta: &mut [RecvMeta],
    ) -> Poll<io::Result<usize>> {
        if buffers.is_empty() || meta.is_empty() {
            return Poll::Ready(Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "QUIC UDP recv buffers are empty",
            )));
        }

        let mut incoming = self.incoming.lock().unwrap();
        loop {
            match Pin::new(&mut *incoming).poll_recv(context) {
                Poll::Ready(Some(Ok(datagram))) => {
                    if buffers[0].len() < datagram.payload.len() {
                        tracing::debug!(
                            payload_len = datagram.payload.len(),
                            recv_buf_len = buffers[0].len(),
                            peer_addr = ?self.peer_addr,
                            "drop oversized QUIC UDP session datagram"
                        );
                        continue;
                    }
                    buffers[0][..datagram.payload.len()].copy_from_slice(&datagram.payload);
                    meta[0] = RecvMeta {
                        addr: self.peer_addr,
                        len: datagram.payload.len(),
                        stride: datagram.payload.len(),
                        ecn: None,
                        dst_ip: datagram.dst_ip,
                    };
                    return Poll::Ready(Ok(1));
                }
                Poll::Ready(Some(Err(error))) => return Poll::Ready(Err(error)),
                Poll::Ready(None) => {
                    return Poll::Ready(Err(io::Error::new(
                        io::ErrorKind::UnexpectedEof,
                        "QUIC UDP session closed",
                    )));
                }
                Poll::Pending => return Poll::Pending,
            }
        }
    }

    fn local_addr(&self) -> io::Result<std::net::SocketAddr> {
        Ok(self.local_addr)
    }

    fn may_fragment(&self) -> bool {
        false
    }
}
