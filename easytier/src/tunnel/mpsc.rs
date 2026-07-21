// this mod wrap tunnel to a mpsc tunnel, based on crossbeam_channel

use std::{pin::Pin, time::Duration};

use anyhow::Context;
use tokio::time::timeout;

use crate::proto::common::TunnelInfo;

use super::{Tunnel, TunnelError, ZCPacketSink, ZCPacketStream, packet_def::ZCPacket};

use tokio::sync::mpsc::{Receiver, Sender, channel, error::TrySendError};
use tokio_util::task::AbortOnDropHandle;
// use tachyonix::{channel, Receiver, Sender, TrySendError};

use futures::SinkExt;

const MPSC_TUNNEL_CHANNEL_SIZE: usize = 32;
// Keep each timed forward round bounded even when producers never let rx become empty.
const MPSC_TUNNEL_FORWARD_BATCH_SIZE: usize = MPSC_TUNNEL_CHANNEL_SIZE;

#[derive(Clone)]
pub struct MpscTunnelSender(Sender<ZCPacket>);

impl MpscTunnelSender {
    pub async fn send(&self, item: ZCPacket) -> Result<(), TunnelError> {
        self.0.send(item).await.with_context(|| "send error")?;
        Ok(())
    }

    pub fn try_send(&self, item: ZCPacket) -> Result<(), TunnelError> {
        self.0.try_send(item).map_err(|e| match e {
            TrySendError::Full(_) => TunnelError::BufferFull,
            TrySendError::Closed(_) => TunnelError::Shutdown,
        })
    }
}

pub struct MpscTunnel<T> {
    tx: Option<Sender<ZCPacket>>,

    tunnel: T,
    stream: Option<Pin<Box<dyn ZCPacketStream>>>,

    task: AbortOnDropHandle<()>,
}

impl<T: Tunnel> MpscTunnel<T> {
    pub fn new(tunnel: T, send_timeout: Option<Duration>) -> Self {
        let (tx, mut rx) = channel(MPSC_TUNNEL_CHANNEL_SIZE);
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
            tunnel,
            stream: Some(stream),
            task: AbortOnDropHandle::new(task),
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

        for _ in 1..MPSC_TUNNEL_FORWARD_BATCH_SIZE {
            let Ok(item) = rx.try_recv() else {
                break;
            };
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
        MpscTunnelSender(self.tx.as_ref().unwrap().clone())
    }

    pub fn close(&mut self) {
        self.tx.take();
        self.task.abort();
    }

    pub fn tunnel_info(&self) -> Option<TunnelInfo> {
        self.tunnel.info()
    }
}

#[cfg(test)]
mod tests {
    use std::{
        future::Future,
        pin::Pin,
        sync::{
            Arc,
            atomic::{AtomicUsize, Ordering},
        },
        task::{Context, Poll},
    };

    use futures::{Sink, StreamExt};
    use tokio::task::JoinSet;

    use crate::tunnel::{
        SinkItem, StreamItem, TunnelConnector, TunnelListener,
        common::TunnelWrapper,
        ring::{RING_TUNNEL_CAP, create_ring_tunnel_pair},
        tcp::{TcpTunnelConnector, TcpTunnelListener},
    };

    use super::*;

    struct ProgressSink {
        delay: Duration,
        sleep: Pin<Box<tokio::time::Sleep>>,
        waiting: bool,
        sent: Arc<AtomicUsize>,
    }

    impl ProgressSink {
        fn new(delay: Duration, sent: Arc<AtomicUsize>) -> Self {
            Self {
                delay,
                sleep: Box::pin(tokio::time::sleep(Duration::ZERO)),
                waiting: false,
                sent,
            }
        }
    }

    impl Sink<SinkItem> for ProgressSink {
        type Error = TunnelError;

        fn poll_ready(
            mut self: Pin<&mut Self>,
            cx: &mut Context<'_>,
        ) -> Poll<Result<(), Self::Error>> {
            if !self.waiting {
                return Poll::Ready(Ok(()));
            }

            match self.sleep.as_mut().poll(cx) {
                Poll::Ready(()) => {
                    self.waiting = false;
                    Poll::Ready(Ok(()))
                }
                Poll::Pending => Poll::Pending,
            }
        }

        fn start_send(mut self: Pin<&mut Self>, _item: SinkItem) -> Result<(), Self::Error> {
            let wake_at = tokio::time::Instant::now() + self.delay;
            self.sleep.as_mut().reset(wake_at);
            self.waiting = true;
            self.sent.fetch_add(1, Ordering::Release);
            Ok(())
        }

        fn poll_flush(
            self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
        ) -> Poll<Result<(), Self::Error>> {
            Poll::Ready(Ok(()))
        }

        fn poll_close(
            self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
        ) -> Poll<Result<(), Self::Error>> {
            Poll::Ready(Ok(()))
        }
    }

    #[tokio::test]
    async fn mpsc_continuous_progress_does_not_timeout() {
        let sent = Arc::new(AtomicUsize::new(0));
        let tunnel = TunnelWrapper::new(
            futures::stream::pending::<StreamItem>(),
            ProgressSink::new(Duration::from_millis(1), sent.clone()),
            None,
        );
        let mpsc_tunnel = MpscTunnel::new(tunnel, Some(Duration::from_millis(200)));
        let sink = mpsc_tunnel.get_sink();

        let producer_count = 4;
        let packets_per_producer = 256;
        let total_packets = producer_count * packets_per_producer;
        let mut tasks = JoinSet::new();
        for _ in 0..producer_count {
            let sink = sink.clone();
            tasks.spawn(async move {
                for _ in 0..packets_per_producer {
                    sink.send(ZCPacket::new_with_payload(&[0; 64])).await?;
                }
                Ok::<(), TunnelError>(())
            });
        }

        while let Some(ret) = tasks.join_next().await {
            ret.expect("producer task panicked")
                .expect("producer send failed");
        }

        tokio::time::timeout(Duration::from_secs(10), async {
            while sent.load(Ordering::Acquire) < total_packets {
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .expect("forward task stopped while the sink was making progress");
    }

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
                    .send(ZCPacket::new_with_payload("hello".as_bytes()))
                    .await;
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
                    .send(ZCPacket::new_with_payload("hello2".as_bytes()))
                    .await;
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
