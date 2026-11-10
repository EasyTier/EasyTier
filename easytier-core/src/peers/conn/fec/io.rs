use std::{
    pin::Pin,
    sync::Arc,
    task::{Context, Poll},
};

use futures::{SinkExt, Stream, StreamExt};
use tokio::{sync::mpsc, task::JoinHandle};

use crate::{
    foundation::time::{Duration, Instant, sleep_until, timeout},
    packet::ZCPacket,
    tunnel::{
        StreamItem, Tunnel, TunnelError, ZCPacketSink, ZCPacketStream, filter::TunnelFilter,
        mpsc::MpscTunnelSender,
    },
};

use super::{PeerConnFec, send::Tx, wire};

pub(crate) struct PeerConnFecIo {
    sender: Option<MpscTunnelSender>,
    stream: Option<Pin<Box<dyn ZCPacketStream>>>,
    task: JoinHandle<()>,
    fec: Arc<PeerConnFec>,
    _tunnel: Box<dyn Tunnel>,
}

struct CloseOnDrop(Arc<PeerConnFec>);

impl Drop for CloseOnDrop {
    fn drop(&mut self) {
        self.0.close();
    }
}

impl PeerConnFecIo {
    pub(crate) fn new(
        tunnel: Box<dyn Tunnel>,
        filter: impl TunnelFilter + 'static,
        fec: Arc<PeerConnFec>,
    ) -> Self {
        let (stream, sink) = tunnel.split();
        let (sender, receiver) = mpsc::channel(32);
        let filter = Arc::new(filter);
        let task = tokio::spawn(writer(receiver, sink, filter.clone(), fec.clone()));
        Self {
            sender: Some(MpscTunnelSender::new(sender)),
            stream: Some(Box::pin(ReceiveStream {
                stream,
                filter,
                fec: fec.clone(),
            })),
            task,
            fec,
            _tunnel: tunnel,
        }
    }

    pub(crate) fn get_stream(&mut self) -> Pin<Box<dyn ZCPacketStream>> {
        self.stream.take().unwrap()
    }

    pub(crate) fn get_sink(&self) -> MpscTunnelSender {
        self.sender.as_ref().unwrap().clone()
    }

    pub(crate) fn close(&mut self) {
        self.sender.take();
        self.fec.close();
        self.task.abort();
    }
}

impl Drop for PeerConnFecIo {
    fn drop(&mut self) {
        self.close();
    }
}

async fn deadline(at: Option<Instant>) {
    match at {
        Some(at) => sleep_until(at).await,
        None => std::future::pending().await,
    }
}

async fn write_one(
    sink: &mut Pin<Box<dyn ZCPacketSink>>,
    packet: ZCPacket,
    fec: &PeerConnFec,
    tx: &mut Tx,
) -> Result<(), TunnelError> {
    // Preserve one send future across cache-maintenance wakeups. Retrying a
    // partially accepted Sink::send would duplicate the packet.
    let send = timeout(Duration::from_secs(7), sink.send(packet));
    tokio::pin!(send);
    loop {
        tokio::select! {
            result = &mut send => return result?,
            _ = deadline(fec.deadline().into_iter().chain(tx.expiry_deadline()).min()) => {
                let now = Instant::now();
                fec.expire(now);
                tx.expire(now);
            },
            _ = fec.writer_wake.notified() => {
                if fec.closed() { return Err(TunnelError::Shutdown); }
            }
        }
    }
}

async fn writer<F: TunnelFilter + 'static>(
    mut receiver: mpsc::Receiver<ZCPacket>,
    mut sink: Pin<Box<dyn ZCPacketSink>>,
    filter: Arc<F>,
    fec: Arc<PeerConnFec>,
) {
    let _close = CloseOnDrop(fec.clone());
    let mut tx = Tx::new(super::MAX_SYMBOL_SIZE);
    let result: Result<(), TunnelError> = async {
        loop {
            if fec.closed() {
                return Ok(());
            }
            let now = Instant::now();
            fec.expire(now);
            tx.expire(now);
            if fec.active() && tx.repairs_due(now) {
                for repair in tx.take_repairs(now) {
                    let bytes = repair.tunnel_payload().len() as u64;
                    write_one(&mut sink, repair, &fec, &mut tx).await?;
                    let mut state = fec.state.lock();
                    state.stats.tx_repairs += 1;
                    state.stats.tx_repair_bytes += bytes;
                    if let Some(metrics) = &state.metrics {
                        metrics.tx_repairs.inc();
                        metrics.tx_repair_bytes.add(bytes);
                    }
                }
            }
            let next_deadline = tx.deadline().into_iter().chain(fec.deadline()).min();
            let packet = tokio::select! {
                biased;
                _ = deadline(next_deadline) => continue,
                _ = fec.writer_wake.notified() => continue,
                packet = receiver.recv() => match packet {
                    Some(packet) => packet,
                    None => return Ok(()),
                },
            };
            let Some(packet) = filter.before_send(packet) else {
                continue;
            };
            if fec.should_encode(&packet)
                && let Some((id, frame)) = tx.prepare(&packet)
            {
                let bytes = frame.tunnel_payload().len() as u64;
                write_one(&mut sink, frame, &fec, &mut tx).await?;
                tx.accepted(id, packet.tunnel_payload(), Instant::now());
                let mut state = fec.state.lock();
                state.stats.tx_sources += 1;
                state.stats.tx_source_bytes += bytes;
                if let Some(metrics) = &state.metrics {
                    metrics.tx_sources.inc();
                    metrics.tx_source_bytes.add(bytes);
                }
            } else {
                write_one(&mut sink, packet, &fec, &mut tx).await?;
            }
        }
    }
    .await;
    if let Err(error) = result {
        tracing::debug!(?error, "UDP FEC writer stopped");
    }
    receiver.close();
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
            if let Some(packet) = this.fec.take_received(Instant::now()) {
                if let Some(result) = this.filter.after_received(Ok(packet)) {
                    return Poll::Ready(Some(result));
                }
                continue;
            }
            match this.stream.poll_next_unpin(cx) {
                Poll::Ready(Some(Ok(packet))) => {
                    // Classify before any peer filter, even while handshaking.
                    // A framed datagram may overtake the last plain handshake;
                    // changing the parser with activation would misread it.
                    let packet = if wire::classify(&packet) == wire::FrameKind::Plain {
                        Some(packet)
                    } else {
                        this.fec.receive(packet, Instant::now())
                    };
                    if let Some(packet) = packet
                        && let Some(result) = this.filter.after_received(Ok(packet))
                    {
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
