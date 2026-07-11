use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use tokio::{sync::mpsc, task::JoinHandle};

use crate::packet::ZCPacket;

/// Receives decoded data packets leaving the EasyTier peer graph.
///
/// The host decides whether packets go to a TUN device, a Go callback, or a
/// different packet backend. Core never performs that platform I/O directly.
#[async_trait]
pub trait PacketSink: Send + Sync + 'static {
    async fn write_packet(&self, packet: ZCPacket) -> anyhow::Result<()>;
}

#[async_trait]
impl PacketSink for mpsc::Sender<ZCPacket> {
    async fn write_packet(&self, packet: ZCPacket) -> anyhow::Result<()> {
        self.send(packet)
            .await
            .map_err(|_| anyhow::anyhow!("packet sink channel is closed"))
    }
}

pub(crate) struct PacketEgress {
    receiver: Mutex<Option<mpsc::Receiver<ZCPacket>>>,
    sink: Arc<dyn PacketSink>,
    task: Mutex<Option<JoinHandle<()>>>,
}

impl PacketEgress {
    pub(crate) fn new(receiver: mpsc::Receiver<ZCPacket>, sink: Arc<dyn PacketSink>) -> Self {
        Self {
            receiver: Mutex::new(Some(receiver)),
            sink,
            task: Mutex::new(None),
        }
    }

    pub(crate) fn start(&self) -> anyhow::Result<()> {
        let mut receiver = self
            .receiver
            .lock()
            .unwrap()
            .take()
            .ok_or_else(|| anyhow::anyhow!("packet egress is one-shot and already started"))?;
        let sink = self.sink.clone();
        let task = tokio::spawn(async move {
            while let Some(packet) = receiver.recv().await {
                if let Err(error) = sink.write_packet(packet).await {
                    tracing::warn!(?error, "host packet sink rejected an egress packet");
                }
            }
        });
        *self.task.lock().unwrap() = Some(task);
        Ok(())
    }

    pub(crate) async fn stop(&self) {
        let task = self.task.lock().unwrap().take();
        if let Some(task) = task {
            task.abort();
            let _ = task.await;
        }
        self.receiver.lock().unwrap().take();
    }
}

impl Drop for PacketEgress {
    fn drop(&mut self) {
        if let Some(task) = self.task.lock().unwrap().take() {
            task.abort();
        }
    }
}

#[cfg(test)]
mod tests {
    use tokio::time::{Duration, timeout};

    use super::*;

    #[tokio::test]
    async fn packet_egress_forwards_to_host_sink_and_joins_on_stop() {
        let (core_tx, core_rx) = mpsc::channel(1);
        let (host_tx, mut host_rx) = mpsc::channel(1);
        let egress = PacketEgress::new(core_rx, Arc::new(host_tx));
        egress.start().unwrap();

        core_tx
            .send(ZCPacket::new_with_payload(b"packet"))
            .await
            .unwrap();
        let packet = timeout(Duration::from_secs(1), host_rx.recv())
            .await
            .expect("packet egress did not forward to the host")
            .expect("host packet channel closed");
        assert_eq!(packet.payload(), b"packet");

        egress.stop().await;
        assert!(egress.start().is_err());
    }
}
