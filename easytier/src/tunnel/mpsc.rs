// this mod wrap tunnel to a mpsc tunnel, based on crossbeam_channel

use std::{
    cell::UnsafeCell,
    pin::Pin,
    sync::Arc,
    sync::atomic::{AtomicBool, Ordering},
    task::Poll,
    time::Duration,
};

use anyhow::Context;
use tokio::time::timeout;

use crate::proto::common::TunnelInfo;

use super::{Tunnel, TunnelError, ZCPacketSink, ZCPacketStream, packet_def::ZCPacket};

use tokio::sync::mpsc::{Receiver, Sender, channel, error::TrySendError};
use tokio_util::task::AbortOnDropHandle;

use futures::SinkExt;

/// A simple spinlock protecting a sink. The guard is Send because it only
/// contains an atomic flag reference (no lifetime-tied borrow like MutexGuard).
struct SpinSink {
    locked: AtomicBool,
    sink: UnsafeCell<Pin<Box<dyn ZCPacketSink>>>,
}

// SAFETY: access is serialized by the spinlock.
unsafe impl Send for SpinSink {}
unsafe impl Sync for SpinSink {}

struct SpinGuard<'a> {
    spin: &'a SpinSink,
}

impl<'a> SpinGuard<'a> {
    fn as_mut(&mut self) -> Pin<&mut dyn ZCPacketSink> {
        // SAFETY: we hold the spinlock, so we have exclusive access
        let sink = unsafe { &mut *self.spin.sink.get() };
        sink.as_mut()
    }
}

impl Drop for SpinGuard<'_> {
    fn drop(&mut self) {
        self.spin.locked.store(false, Ordering::Release);
    }
}

impl SpinSink {
    fn new(sink: Pin<Box<dyn ZCPacketSink>>) -> Self {
        Self {
            locked: AtomicBool::new(false),
            sink: UnsafeCell::new(sink),
        }
    }

    fn try_lock(&self) -> Option<SpinGuard<'_>> {
        if self
            .locked
            .compare_exchange(false, true, Ordering::Acquire, Ordering::Relaxed)
            .is_ok()
        {
            Some(SpinGuard { spin: self })
        } else {
            None
        }
    }
}

#[derive(Clone)]
pub struct MpscTunnelSender {
    channel_tx: Option<Sender<ZCPacket>>,
    direct_sink: Option<Arc<SpinSink>>,
}

impl MpscTunnelSender {
    pub async fn send(&self, item: ZCPacket) -> Result<(), TunnelError> {
        if let Some(sink) = &self.direct_sink {
            // Sync fast path: no await needed, returns immediately
            if let Some(mut guard) = sink.try_lock() {
                let waker = futures::task::noop_waker();
                let mut cx = std::task::Context::from_waker(&waker);
                match guard.as_mut().poll_ready(&mut cx) {
                    Poll::Ready(Ok(())) => {
                        guard.as_mut().start_send(item)?;
                        // poll_flush may return Pending when the consumer task hasn't
                        // drained the ring yet. The data is already in the ring buffer
                        // and will be consumed — treat Pending as success.
                        match guard.as_mut().poll_flush(&mut cx) {
                            Poll::Ready(Err(e)) => return Err(e),
                            _ => return Ok(()),
                        }
                    }
                    Poll::Ready(Err(e)) => return Err(e),
                    Poll::Pending => return Err(TunnelError::BufferFull),
                }
            }
            return Err(TunnelError::BufferFull);
        }

        // Channel mode: async with backpressure
        self.send_async(item).await
    }

    pub fn try_send(&self, item: ZCPacket) -> Result<(), TunnelError> {
        let tx = self.channel_tx.as_ref().ok_or(TunnelError::Shutdown)?;
        tx.try_send(item).map_err(|e| match e {
            TrySendError::Full(_) => TunnelError::BufferFull,
            TrySendError::Closed(_) => TunnelError::Shutdown,
        })
    }

    pub async fn send_async(&self, item: ZCPacket) -> Result<(), TunnelError> {
        let tx = self.channel_tx.as_ref().ok_or(TunnelError::Shutdown)?;
        match tx.try_send(item) {
            Ok(()) => Ok(()),
            Err(TrySendError::Full(item)) => {
                tx.send(item).await.with_context(|| "send error")?;
                Ok(())
            }
            Err(TrySendError::Closed(_)) => Err(TunnelError::Shutdown),
        }
    }
}

pub struct MpscTunnel<T> {
    tx: Option<Sender<ZCPacket>>,
    direct_sink: Option<Arc<SpinSink>>,

    tunnel: T,
    stream: Option<Pin<Box<dyn ZCPacketStream>>>,

    task: Option<AbortOnDropHandle<()>>,
}

impl<T: Tunnel> MpscTunnel<T> {
    pub fn new(tunnel: T, send_timeout: Option<Duration>) -> Self {
        let (tx, mut rx) = channel(32);
        let (stream, mut sink) = tunnel.split();

        let task = tokio::spawn(async move {
            loop {
                if let Err(e) = Self::forward_one_round(&mut rx, &mut sink, send_timeout).await {
                    tracing::error!(?e, "forward error");
                    break;
                }
            }
            rx.close();
            let close_ret = timeout(Duration::from_secs(5), sink.close()).await;
            tracing::warn!(?close_ret, "mpsc close sink");
        });

        Self {
            tx: Some(tx),
            direct_sink: None,
            tunnel,
            stream: Some(stream),
            task: Some(AbortOnDropHandle::new(task)),
        }
    }

    pub fn new_direct(tunnel: T) -> Self {
        let (stream, sink) = tunnel.split();
        Self {
            tx: None,
            direct_sink: Some(Arc::new(SpinSink::new(sink))),
            tunnel,
            stream: Some(stream),
            task: None,
        }
    }

    async fn forward_one_round(
        rx: &mut Receiver<ZCPacket>,
        sink: &mut Pin<Box<dyn ZCPacketSink>>,
        send_timeout_ms: Option<Duration>,
    ) -> Result<(), TunnelError> {
        let item = rx.recv().await.with_context(|| "recv error")?;
        if let Some(timeout_ms) = send_timeout_ms {
            Self::forward_one_round_with_timeout(rx, sink, item, timeout_ms).await
        } else {
            Self::forward_one_round_no_timeout(rx, sink, item).await
        }
    }

    async fn forward_one_round_no_timeout(
        rx: &mut Receiver<ZCPacket>,
        sink: &mut Pin<Box<dyn ZCPacketSink>>,
        initial_item: ZCPacket,
    ) -> Result<(), TunnelError> {
        sink.feed(initial_item).await?;

        while let Ok(item) = rx.try_recv() {
            if let Err(e) = sink.feed(item).await {
                tracing::error!(?e, "feed error");
                return Err(e);
            }
        }

        sink.flush().await
    }

    async fn forward_one_round_with_timeout(
        rx: &mut Receiver<ZCPacket>,
        sink: &mut Pin<Box<dyn ZCPacketSink>>,
        initial_item: ZCPacket,
        timeout_ms: Duration,
    ) -> Result<(), TunnelError> {
        match timeout(timeout_ms, async move {
            Self::forward_one_round_no_timeout(rx, sink, initial_item).await
        })
        .await
        {
            Ok(Ok(_)) => Ok(()),
            Ok(Err(e)) => {
                tracing::error!(?e, "forward error");
                Err(e)
            }
            Err(e) => {
                tracing::error!(?e, "forward timeout");
                Err(e.into())
            }
        }
    }

    pub fn get_stream(&mut self) -> Pin<Box<dyn ZCPacketStream>> {
        self.stream.take().unwrap()
    }

    pub fn get_sink(&self) -> MpscTunnelSender {
        MpscTunnelSender {
            channel_tx: self.tx.as_ref().cloned(),
            direct_sink: self.direct_sink.clone(),
        }
    }

    pub fn close(&mut self) {
        self.tx.take();
        self.direct_sink.take();
        if let Some(task) = self.task.take() {
            task.abort();
        }
    }

    pub fn tunnel_info(&self) -> Option<TunnelInfo> {
        self.tunnel.info()
    }
}

#[cfg(test)]
mod tests {
    use futures::StreamExt;

    use crate::tunnel::{
        TunnelConnector, TunnelListener,
        ring::{RING_TUNNEL_CAP, create_ring_tunnel_pair},
        tcp::{TcpTunnelConnector, TcpTunnelListener},
    };

    use super::*;
    // test slow send lock in framed tunnel
    #[tokio::test]
    async fn mpsc_slow_receiver() {
        let mut listener = TcpTunnelListener::new("tcp://127.0.0.1:11014".parse().unwrap());
        let mut connector = TcpTunnelConnector::new("tcp://127.0.0.1:11014".parse().unwrap());

        listener.listen().await.unwrap();
        let t1 = tokio::spawn(async move {
            let t = listener.accept().await.unwrap();
            let (mut stream, _sink) = t.split();
            let now = tokio::time::Instant::now();

            let mut a_counter = 0;
            let mut b_counter = 0;

            while let Some(Ok(msg)) = stream.next().await {
                tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;
                if now.elapsed().as_secs() > 5 {
                    break;
                }

                if msg.payload() == "hello".as_bytes() {
                    a_counter += 1;
                } else if msg.payload() == "hello2".as_bytes() {
                    b_counter += 1;
                }
            }

            tracing::info!("t1 exit");
            assert_ne!(a_counter, 0);
            assert_ne!(b_counter, 0);
        });

        let tunnel = connector.connect().await.unwrap();
        let mpsc_tunnel = MpscTunnel::new(tunnel, None);

        let sink1 = mpsc_tunnel.get_sink();
        let t2 = tokio::spawn(async move {
            for i in 0..1000000 {
                tokio::time::sleep(tokio::time::Duration::from_millis(50)).await;
                let a = sink1
                    .send_async(ZCPacket::new_with_payload("hello".as_bytes())).await;
                if a.is_err() {
                    tracing::info!(?a, "t2 exit with err");
                    break;
                }

                if i % 5000 == 0 {
                    tracing::info!(i, "send2 1000");
                }
            }

            tracing::info!("t2 exit");
        });

        let sink2 = mpsc_tunnel.get_sink();
        let t3 = tokio::spawn(async move {
            for i in 0..1000000 {
                tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;
                let a = sink2
                    .send_async(ZCPacket::new_with_payload("hello2".as_bytes())).await;
                if a.is_err() {
                    tracing::info!(?a, "t3 exit with err");
                    break;
                }

                if i % 5000 == 0 {
                    tracing::info!(i, "send2 1000");
                }
            }

            tracing::info!("t3 exit");
        });

        let t4 = tokio::spawn(async move {
            tokio::time::sleep(tokio::time::Duration::from_secs(5)).await;
            tracing::info!("closing");
            drop(mpsc_tunnel);
            tracing::info!("closed");
        });

        let _ = tokio::join!(t1, t2, t3, t4);
    }

    #[tokio::test]
    async fn mpsc_slow_receiver_with_send_timeout() {
        let (a, _b) = create_ring_tunnel_pair();
        let mpsc_tunnel = MpscTunnel::new(a, Some(Duration::from_secs(1)));
        let s = mpsc_tunnel.get_sink();
        for _ in 0..RING_TUNNEL_CAP {
            s.send(ZCPacket::new_with_payload(&[0; 1024]))
                .await
                .unwrap();
        }
        tokio::time::sleep(Duration::from_millis(1500)).await;
        let e = s.send(ZCPacket::new_with_payload(&[0; 1024])).await;
        assert!(e.is_ok());

        tokio::time::sleep(Duration::from_millis(1500)).await;

        let e = s.send(ZCPacket::new_with_payload(&[0; 1024])).await;
        assert!(e.is_err());
    }
}
