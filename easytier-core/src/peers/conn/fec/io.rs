use std::{
    pin::Pin,
    sync::Arc,
    task::{Context, Poll},
};

use futures::{SinkExt, Stream, StreamExt};
use tokio::{
    sync::mpsc::{self, Receiver, Sender},
    task::JoinHandle,
};

use crate::{
    foundation::time::{Duration, Instant, sleep_until, timeout},
    packet::ZCPacket,
    tunnel::{
        StreamItem, Tunnel, TunnelError, ZCPacketSink, ZCPacketStream, filter::TunnelFilter,
        mpsc::MpscTunnelSender,
    },
};

use super::{PeerConnFec, Received, send::PendingSend, wire};

pub(crate) struct PeerConnFecIo {
    tx: Option<Sender<ZCPacket>>,
    // Own the transport's close guard after its halves move into the driver.
    _tunnel: Box<dyn Tunnel>,
    stream: Option<Pin<Box<dyn ZCPacketStream>>>,
    task: JoinHandle<()>,
    fec: Arc<PeerConnFec>,
}

impl PeerConnFecIo {
    pub(crate) fn new(
        tunnel: Box<dyn Tunnel>,
        filter: impl TunnelFilter + 'static,
        fec: Arc<PeerConnFec>,
    ) -> Self {
        let (tx, rx) = mpsc::channel(32);
        let (stream, sink) = tunnel.split();
        let filter = Arc::new(filter);
        let task = tokio::spawn(writer(rx, sink, filter.clone(), fec.clone()));
        Self {
            tx: Some(tx),
            _tunnel: tunnel,
            stream: Some(Box::pin(ReceiveStream {
                stream,
                filter,
                fec: fec.clone(),
            })),
            task,
            fec,
        }
    }

    pub(crate) fn get_stream(&mut self) -> Pin<Box<dyn ZCPacketStream>> {
        self.stream.take().unwrap()
    }

    pub(crate) fn get_sink(&self) -> MpscTunnelSender {
        MpscTunnelSender::from_sender(self.tx.as_ref().unwrap().clone())
    }

    pub(crate) fn close(&mut self) {
        self.fec.close();
        self.tx.take();
        self.task.abort();
    }
}

impl Drop for PeerConnFecIo {
    fn drop(&mut self) {
        self.fec.close();
        self.task.abort();
    }
}

struct CloseOnDrop(Arc<PeerConnFec>);

impl Drop for CloseOnDrop {
    fn drop(&mut self) {
        self.0.close();
    }
}

async fn deadline(deadline: Option<Instant>) {
    match deadline {
        Some(deadline) => sleep_until(deadline).await,
        None => futures::future::pending().await,
    }
}

async fn write_one(
    sink: &mut Pin<Box<dyn ZCPacketSink>>,
    fec: &PeerConnFec,
    pending: PendingSend,
) -> Result<(), TunnelError> {
    let PendingSend {
        packet,
        accepted,
        reservation,
    } = pending;
    let send = timeout(Duration::from_secs(7), sink.send(packet));
    tokio::pin!(send);
    let result = loop {
        fec.maintain(Instant::now());
        if fec.closed() {
            break Err(TunnelError::Shutdown);
        }
        // Keep this exact send future alive: a Sink may have accepted the
        // packet and still be waiting in flush. Maintenance must not retry it.
        // Feedback waits for the writer to become available; only cache expiry
        // can make progress during a blocked send.
        tokio::select! {
            ret = &mut send => break ret.map_err(TunnelError::from).and_then(|r| r),
            _ = fec.writer_wake.notified() => {},
            _ = deadline(fec.deadline()) => {},
        }
    };
    if result.is_ok() {
        fec.on_accepted(accepted, Instant::now());
    }
    drop(reservation);
    result
}

async fn writer<F: TunnelFilter + 'static>(
    mut rx: Receiver<ZCPacket>,
    mut sink: Pin<Box<dyn ZCPacketSink>>,
    filter: Arc<F>,
    fec: Arc<PeerConnFec>,
) {
    let _close = CloseOnDrop(fec.clone());
    let mut held = None;
    loop {
        fec.maintain(Instant::now());
        if fec.closed() {
            break;
        }
        // A waiting control packet goes first. Otherwise allow a due repair
        // between business packets, even while the producer keeps the queue full.
        let packet = if held.is_some() {
            held.take()
        } else {
            match rx.try_recv() {
                Ok(packet) => Some(packet),
                Err(mpsc::error::TryRecvError::Disconnected) => break,
                Err(mpsc::error::TryRecvError::Empty) => None,
            }
        };
        let control = packet
            .as_ref()
            .is_some_and(|packet| !wire::eligible_peer(packet.tunnel_payload()));
        let auxiliary = if control {
            None
        } else {
            fec.next_feedback(Instant::now())
                .or_else(|| fec.next_repair(Instant::now()))
        };
        let pending = if let Some(auxiliary) = auxiliary {
            held = packet;
            Some(auxiliary)
        } else if let Some(packet) = packet {
            filter
                .before_send(packet)
                .map(|packet| fec.prepare_send(packet, Instant::now()))
        } else {
            tokio::select! {
                packet = rx.recv() => match packet {
                    Some(packet) => { held = Some(packet); None },
                    None => break,
                },
                _ = fec.writer_wake.notified() => None,
                _ = deadline(fec.deadline().into_iter().chain(fec.feedback_deadline()).min()) => None,
            }
        };
        if let Some(pending) = pending
            && let Err(error) = write_one(&mut sink, &fec, pending).await
        {
            tracing::debug!(?error, "PeerConn FEC writer closed");
            break;
        }
    }
    rx.close();
    // Closing FEC immediately releases caches even if closing the raw sink
    // itself blocks. Ordinary queued packets drop with this writer.
    fec.close();
    let _ = timeout(Duration::from_secs(5), sink.close()).await;
}

struct ReceiveStream<F> {
    stream: Pin<Box<dyn ZCPacketStream>>,
    filter: Arc<F>,
    fec: Arc<PeerConnFec>,
}

impl<F: TunnelFilter + 'static> Stream for ReceiveStream<F> {
    type Item = StreamItem;

    fn poll_next(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        let this = self.get_mut();
        this.fec.reader_wake.register(cx.waker());
        for _ in 0..64 {
            if this.fec.closed() {
                return Poll::Ready(None);
            }
            if let Some(received) = this.fec.take_received() {
                let Received {
                    packet,
                    _reservation,
                } = received;
                let result = this.filter.after_received(Ok(packet));
                // Keep the restored allocation charged through filtering, right
                // up to the Stream yield (or a filter rejecting the packet).
                drop(_reservation);
                if let Some(result) = result {
                    return Poll::Ready(Some(result));
                }
                continue;
            }
            match this.stream.poll_next_unpin(cx) {
                Poll::Ready(Some(Ok(packet))) => {
                    let kind = packet
                        .peer_manager_header()
                        .map(|header| header.packet_type);
                    if matches!(kind, Some(wire::SOURCE | wire::REPAIR | wire::FEEDBACK)) {
                        if let Some(received) = this.fec.receive(packet, Instant::now()) {
                            let Received {
                                packet,
                                _reservation,
                            } = received;
                            let result = this.filter.after_received(Ok(packet));
                            drop(_reservation);
                            if let Some(result) = result {
                                return Poll::Ready(Some(result));
                            }
                        }
                    } else if let Some(result) = this.filter.after_received(Ok(packet)) {
                        return Poll::Ready(Some(result));
                    }
                }
                Poll::Ready(Some(Err(error))) => {
                    if let Some(result) = this.filter.after_received(Err(error)) {
                        return Poll::Ready(Some(result));
                    }
                }
                Poll::Ready(None) => {
                    this.fec.close();
                    return Poll::Ready(None);
                }
                Poll::Pending => return Poll::Pending,
            }
        }
        cx.waker().wake_by_ref();
        Poll::Pending
    }
}

impl<F> Drop for ReceiveStream<F> {
    fn drop(&mut self) {
        self.fec.close();
    }
}
