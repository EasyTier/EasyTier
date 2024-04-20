// this mod wrap tunnel to a mpsc tunnel, based on crossbeam_channel

use std::pin::Pin;

use anyhow::Context;
use tokio::task::JoinHandle;

use super::{packet_def::ZCPacket, Tunnel, TunnelError, ZCPacketSink, ZCPacketStream};

use tachyonix::{channel, Receiver, Sender};

use futures::{SinkExt, StreamExt};

pub type MpscTunnelSender = Sender<ZCPacket>;

struct MpscTunnel<T> {
    tx: MpscTunnelSender,

    tunnel: T,
    stream: Option<Pin<Box<dyn ZCPacketStream>>>,

    task: Option<JoinHandle<()>>,
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
        });

        Self {
            tx,
            tunnel,
            stream: Some(stream),
            task: Some(task),
        }
    }

    async fn forward_one_round(
        rx: &mut Receiver<ZCPacket>,
        sink: &mut Pin<Box<dyn ZCPacketSink>>,
    ) -> Result<(), TunnelError> {
        let item = rx.recv().await.with_context(|| "recv error")?;
        sink.feed(item).await?;
        while let Ok(item) = rx.try_recv() {
            if let Err(e) = sink.feed(item).await {
                tracing::error!(?e, "feed error");
                break;
            }
        }
        sink.flush().await
    }

    pub fn get_stream(&mut self) -> Pin<Box<dyn ZCPacketStream>> {
        self.stream.take().unwrap()
    }

    pub fn get_sink(&self) -> MpscTunnelSender {
        self.tx.clone()
    }
}

impl<T: Tunnel> From<T> for MpscTunnel<T> {
    fn from(tunnel: T) -> Self {
        Self::new(tunnel)
    }
}
