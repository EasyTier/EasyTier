// this mod wrap tunnel to a mpsc tunnel, based on crossbeam_channel

use std::{pin::Pin, time::Duration};

use anyhow::Context;
use tokio::time::timeout;

use crate::common::scoped_task::ScopedTask;

use super::{packet_def::ZCPacket, Tunnel, TunnelError, ZCPacketSink, ZCPacketStream};

// use tokio::sync::mpsc::{channel, error::TrySendError, Receiver, Sender};
use tachyonix::{channel, Receiver, Sender, TrySendError};

use futures::SinkExt;

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

    task: ScopedTask<()>,
}

impl<T: Tunnel> MpscTunnel<T> {
    pub fn new(tunnel: T) -> Self {
        let (tx, mut rx) = channel(32);
        let (stream, mut sink) = tunnel.split();

        let task = tokio::spawn(async move {
            loop {
                if let Err(e) = Self::forward_one_round(&mut rx, &mut sink).await {
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
            task: task.into(),
        }
    }

    async fn forward_one_round(
        rx: &mut Receiver<ZCPacket>,
        sink: &mut Pin<Box<dyn ZCPacketSink>>,
    ) -> Result<(), TunnelError> {
        let item = rx.recv().await.with_context(|| "recv error")?;

        match timeout(Duration::from_secs(10), async move {
            sink.feed(item).await?;
            while let Ok(item) = rx.try_recv() {
                match sink.feed(item).await {
                    Err(e) => {
                        tracing::error!(?e, "feed error");
                        return Err(e);
                    }
                    Ok(_) => {}
                }
            }
            sink.flush().await
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
}

impl<T: Tunnel> From<T> for MpscTunnel<T> {
    fn from(tunnel: T) -> Self {
        Self::new(tunnel)
    }
}

#[cfg(test)]
mod tests {
    use futures::StreamExt;

    use crate::tunnel::{
        tcp::{TcpTunnelConnector, TcpTunnelListener},
        TunnelConnector, TunnelListener,
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
        let mpsc_tunnel = MpscTunnel::from(tunnel);

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
}
