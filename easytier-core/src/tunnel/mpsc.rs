use std::{pin::Pin, time::Duration};

use futures::SinkExt;
use tokio::{
    sync::mpsc::{Receiver, Sender, channel, error::TrySendError},
    task::JoinHandle,
};

use crate::{
    foundation::time::timeout,
    packet::{PacketType, ZCPacket},
    proto::common::TunnelInfo,
    tunnel::{Tunnel, TunnelError, ZCPacketSink, ZCPacketStream},
};

fn is_heartbeat(packet: &ZCPacket) -> bool {
    packet.peer_manager_header().is_some_and(|header| {
        header.packet_type == PacketType::Ping as u8 || header.packet_type == PacketType::Pong as u8
    })
}

#[derive(Clone)]
pub struct MpscTunnelSender {
    sender: Sender<ZCPacket>,
    heartbeat: Option<Sender<ZCPacket>>,
}

impl MpscTunnelSender {
    fn sender(&self, item: &ZCPacket) -> &Sender<ZCPacket> {
        if let Some(heartbeat) = &self.heartbeat
            && is_heartbeat(item)
        {
            return heartbeat;
        }
        &self.sender
    }

    pub async fn send(&self, item: ZCPacket) -> Result<(), TunnelError> {
        let sender = self.sender(&item);
        match sender.try_send(item) {
            Ok(()) => Ok(()),
            Err(TrySendError::Full(item)) => {
                sender.send(item).await.map_err(|_| TunnelError::Shutdown)
            }
            Err(TrySendError::Closed(_)) => Err(TunnelError::Shutdown),
        }
    }

    pub fn try_send(&self, item: ZCPacket) -> Result<(), TunnelError> {
        self.sender(&item).try_send(item).map_err(|e| match e {
            TrySendError::Full(_) => TunnelError::BufferFull,
            TrySendError::Closed(_) => TunnelError::Shutdown,
        })
    }
}

/// Only connection writers expand batches. Internal RPC rings keep one entry
/// per RPC. Ordinary fragments stay FIFO, including pre-encrypted relay traffic.
pub(crate) struct MpscTunnelReceiver {
    receiver: Receiver<ZCPacket>,
    heartbeat: Option<Receiver<ZCPacket>>,
    pending: std::vec::IntoIter<ZCPacket>,
}

impl MpscTunnelReceiver {
    pub(crate) fn channel(connection: bool) -> (MpscTunnelSender, Self) {
        let (sender, receiver) = channel(32);
        let (heartbeat_tx, heartbeat_rx) = if connection {
            let (tx, rx) = channel(8);
            (Some(tx), Some(rx))
        } else {
            (None, None)
        };
        (
            MpscTunnelSender {
                sender,
                heartbeat: heartbeat_tx,
            },
            Self {
                receiver,
                heartbeat: heartbeat_rx,
                pending: Vec::new().into_iter(),
            },
        )
    }

    fn expand(&mut self, mut packet: ZCPacket) -> ZCPacket {
        if self.heartbeat.is_some() {
            self.pending = packet.take_batch();
        }
        packet
    }

    fn try_recv(&mut self) -> Option<ZCPacket> {
        if let Some(heartbeat) = &mut self.heartbeat
            && let Ok(packet) = heartbeat.try_recv()
        {
            return Some(packet);
        }
        if let Some(packet) = self.pending.next() {
            return Some(packet);
        }
        self.receiver
            .try_recv()
            .ok()
            .map(|packet| self.expand(packet))
    }

    pub(crate) async fn recv(&mut self) -> Option<ZCPacket> {
        if let Some(packet) = self.try_recv() {
            return Some(packet);
        }
        let packet = if let Some(heartbeat) = &mut self.heartbeat {
            tokio::select! {
                biased;
                packet = heartbeat.recv() => packet,
                packet = self.receiver.recv() => packet,
            }
        } else {
            self.receiver.recv().await
        };
        packet.map(|packet| self.expand(packet))
    }

    pub(crate) fn close(&mut self) {
        self.receiver.close();
        if let Some(heartbeat) = &mut self.heartbeat {
            heartbeat.close();
        }
    }
}

pub struct MpscTunnel<T> {
    tx: Option<MpscTunnelSender>,
    tunnel: T,
    stream: Option<Pin<Box<dyn ZCPacketStream>>>,
    task: JoinHandle<()>,
}

impl<T: Tunnel> MpscTunnel<T> {
    pub fn new(tunnel: T, send_timeout: Option<Duration>) -> Self {
        Self::new_inner(tunnel, send_timeout, false)
    }

    pub(crate) fn new_peer_conn(tunnel: T, send_timeout: Duration) -> Self {
        Self::new_inner(tunnel, Some(send_timeout), true)
    }

    fn new_inner(tunnel: T, send_timeout: Option<Duration>, connection: bool) -> Self {
        let (tx, mut rx) = MpscTunnelReceiver::channel(connection);
        let (stream, mut sink) = tunnel.split();

        let task = tokio::spawn(async move {
            loop {
                if let Err(e) = Self::forward_one_round(&mut rx, &mut sink, send_timeout).await {
                    tracing::error!(?e, "forward error");
                    break;
                }
            }
            rx.close();
            drop(rx);
            let close_ret = timeout(Duration::from_secs(5), sink.close()).await;
            tracing::warn!(?close_ret, "mpsc close sink");
        });

        Self {
            tx: Some(tx),
            tunnel,
            stream: Some(stream),
            task,
        }
    }

    async fn forward_one_round(
        rx: &mut MpscTunnelReceiver,
        sink: &mut Pin<Box<dyn ZCPacketSink>>,
        send_timeout_ms: Option<Duration>,
    ) -> Result<(), TunnelError> {
        let item = rx.recv().await.ok_or(TunnelError::Shutdown)?;
        if let Some(timeout_ms) = send_timeout_ms {
            Self::forward_one_round_with_timeout(rx, sink, item, timeout_ms).await
        } else {
            Self::forward_one_round_no_timeout(rx, sink, item).await
        }
    }

    async fn forward_one_round_no_timeout(
        rx: &mut MpscTunnelReceiver,
        sink: &mut Pin<Box<dyn ZCPacketSink>>,
        initial_item: ZCPacket,
    ) -> Result<(), TunnelError> {
        let connection = rx.heartbeat.is_some();
        let heartbeat = connection && is_heartbeat(&initial_item);
        sink.feed(initial_item).await?;
        if heartbeat {
            return sink.flush().await;
        }

        // Bound each flush/timeout round; a large RPC must not own one
        // seven-second send future. Check for Ping/Pong between every fragment.
        let limit = if connection { 8 } else { usize::MAX };
        for _ in 1..limit {
            let Some(item) = rx.try_recv() else {
                break;
            };
            let heartbeat = connection && is_heartbeat(&item);
            if let Err(e) = sink.feed(item).await {
                tracing::error!(?e, "feed error");
                return Err(e);
            }
            if heartbeat {
                break;
            }
        }

        sink.flush().await
    }

    async fn forward_one_round_with_timeout(
        rx: &mut MpscTunnelReceiver,
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
        self.tx.as_ref().unwrap().clone()
    }

    pub fn close(&mut self) {
        self.tx.take();
        self.task.abort();
    }

    pub fn tunnel_info(&self) -> Option<TunnelInfo> {
        self.tunnel.info()
    }
}

impl<T> Drop for MpscTunnel<T> {
    fn drop(&mut self) {
        self.task.abort();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn sender_falls_back_to_waiting_when_channel_is_full() {
        let (tx, mut rx) = channel(1);
        let sender = MpscTunnelSender {
            sender: tx,
            heartbeat: None,
        };
        sender
            .send(ZCPacket::new_with_payload(b"first"))
            .await
            .unwrap();

        let blocked_send = sender.send(ZCPacket::new_with_payload(b"second"));
        tokio::pin!(blocked_send);
        assert!(
            tokio::time::timeout(Duration::from_millis(10), &mut blocked_send)
                .await
                .is_err()
        );

        assert_eq!(rx.recv().await.unwrap().payload(), b"first");
        tokio::time::timeout(Duration::from_secs(1), &mut blocked_send)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(rx.recv().await.unwrap().payload(), b"second");
    }
    fn rpc_fragment(payload: &[u8]) -> ZCPacket {
        let mut packet = ZCPacket::new_with_payload(payload);
        packet.fill_peer_manager_hdr(1, 2, PacketType::RpcReq as u8);
        packet
    }

    #[tokio::test(start_paused = true)]
    async fn rpc_batch_leaves_room_for_heartbeats_on_slow_connection() {
        use crate::tunnel::ring::{RingTunnel, create_ring_socket_pair};
        use futures::StreamExt;

        let (local, remote) = create_ring_socket_pair(1);
        let mut tunnel =
            MpscTunnel::new_peer_conn(RingTunnel::new(local, None), Duration::from_secs(7));
        let sender = tunnel.get_sink();
        let (mut received, _) = RingTunnel::new(remote, None).split();
        let packets = (0u32..207)
            .map(|index| {
                let mut packet = ZCPacket::new_with_payload(&index.to_le_bytes());
                packet.fill_peer_manager_hdr(1, 2, PacketType::RpcReq as u8);
                packet
            })
            .collect();
        sender.send(ZCPacket::batch(packets)).await.unwrap();
        // Ring sockets reserve at least eight transport slots. Let the
        // writer fill those slots and wait on the next fragment.
        tokio::task::yield_now().await;
        for kind in [PacketType::Ping, PacketType::Pong] {
            let mut packet = ZCPacket::new_with_payload(b"heartbeat");
            packet.fill_peer_manager_hdr(1, 2, kind as u8);
            sender.send(packet).await.unwrap();
        }
        let mut indexes = Vec::new();
        let mut heartbeats = Vec::new();
        for _ in 0..209 {
            let packet = received.next().await.unwrap().unwrap();
            assert_eq!(packet.batch_len(), 1);
            let kind = packet.peer_manager_header().unwrap().packet_type;
            if kind == PacketType::RpcReq as u8 {
                indexes.push(u32::from_le_bytes(packet.payload().try_into().unwrap()));
            } else {
                heartbeats.push((kind, indexes.len()));
            }
            // About 2.93 KB/s for a normal RPC fragment. The complete batch
            // takes much longer than seven seconds, but each flush progresses.
            tokio::time::sleep(Duration::from_millis(400)).await;
        }
        assert_eq!(indexes, (0..207).collect::<Vec<_>>());
        assert_eq!(heartbeats.len(), 2);
        assert_eq!(heartbeats[0].0, PacketType::Ping as u8);
        assert_eq!(heartbeats[1].0, PacketType::Pong as u8);
        // Eight packets may already be buffered, and one feed may already
        // be waiting when the heartbeats arrive. Neither can be preempted.
        assert!(heartbeats.iter().all(|(_, before)| *before <= 9));
        tunnel.close();
        tokio::task::yield_now().await;
        assert!(matches!(
            sender.send(rpc_fragment(b"closed")).await,
            Err(TunnelError::Shutdown)
        ));
    }

    #[tokio::test(start_paused = true)]
    async fn stalled_writer_closes_both_queues_and_releases_pending_batch() {
        use crate::tunnel::ring::{RingTunnel, create_ring_socket_pair};

        let (local, _remote) = create_ring_socket_pair(1);
        let tunnel =
            MpscTunnel::new_peer_conn(RingTunnel::new(local, None), Duration::from_secs(7));
        let sender = tunnel.get_sink();
        sender
            .send(ZCPacket::batch(
                (0..207).map(|_| rpc_fragment(b"fragment")).collect(),
            ))
            .await
            .unwrap();
        tokio::task::yield_now().await;
        tokio::time::advance(Duration::from_secs(8)).await;
        tokio::task::yield_now().await;
        let mut ping = ZCPacket::new_with_payload(b"ping");
        ping.fill_peer_manager_hdr(1, 2, PacketType::Ping as u8);
        assert!(matches!(sender.try_send(ping), Err(TunnelError::Shutdown)));
        assert!(matches!(
            sender.try_send(rpc_fragment(b"data")),
            Err(TunnelError::Shutdown)
        ));
        drop(tunnel);
    }

    #[tokio::test]
    async fn ordinary_batches_remain_fifo_and_control_capacity_is_independent() {
        let (sender, mut receiver) = MpscTunnelReceiver::channel(true);
        for batch in 0u32..32 {
            sender
                .try_send(ZCPacket::batch(
                    (0u32..207)
                        .map(|piece| {
                            rpc_fragment(&[batch.to_le_bytes(), piece.to_le_bytes()].concat())
                        })
                        .collect(),
                ))
                .unwrap();
        }
        assert!(matches!(
            sender.try_send(rpc_fragment(b"full")),
            Err(TunnelError::BufferFull)
        ));
        let mut pong = ZCPacket::new_with_payload(b"pong");
        pong.fill_peer_manager_hdr(1, 2, PacketType::Pong as u8);
        sender.try_send(pong.clone()).unwrap();
        assert_eq!(receiver.recv().await.unwrap().payload(), b"pong");
        for batch in 0u32..32 {
            for piece in 0u32..207 {
                assert_eq!(
                    receiver.recv().await.unwrap().payload(),
                    &[batch.to_le_bytes(), piece.to_le_bytes()].concat()
                );
            }
        }
        for _ in 0..8 {
            sender.try_send(pong.clone()).unwrap();
        }
        assert!(matches!(
            sender.try_send(pong),
            Err(TunnelError::BufferFull)
        ));
    }
}
