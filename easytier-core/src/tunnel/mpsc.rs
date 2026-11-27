use std::{
    pin::Pin,
    sync::{
        Arc,
        atomic::{AtomicU32, Ordering},
    },
    time::Duration,
};

use futures::SinkExt;
use tokio::{
    sync::{
        OwnedSemaphorePermit, Semaphore,
        mpsc::{Receiver, Sender, channel, error::TrySendError},
    },
    task::JoinHandle,
};

use crate::{
    foundation::time::{Instant, timeout},
    packet::{PacketType, ZCPacket},
    peers::traffic_metrics::{TrafficKind, traffic_kind},
    proto::common::TunnelInfo,
    tunnel::{Tunnel, TunnelError, ZCPacketSink, ZCPacketStream},
};

const ORDINARY_QUEUE_CAPACITY: usize = 32;
pub(crate) const NETWORK_QUEUE_SLOTS: usize = 480;

struct QueuedPacket {
    packet: ZCPacket,
    _slot: Option<OwnedSemaphorePermit>,
    enqueued_at: Option<Instant>,
}

pub(crate) fn is_heartbeat(packet: &ZCPacket) -> bool {
    packet.peer_manager_header().is_some_and(|header| {
        header.packet_type == PacketType::Ping as u8 || header.packet_type == PacketType::Pong as u8
    })
}

fn can_expire(packet: &ZCPacket) -> bool {
    let Some(header) = packet.peer_manager_header() else {
        return false;
    };
    if header.packet_type == PacketType::ForeignNetworkPacket as u8 {
        return !header.is_encrypted()
            && packet
                .foreign_network_inner_packet_type()
                .is_some_and(|kind| traffic_kind(kind) == TrafficKind::Data);
    }
    traffic_kind(header.packet_type) == TrafficKind::Data
}

#[derive(Clone)]
pub struct MpscTunnelSender {
    sender: Sender<QueuedPacket>,
    heartbeat: Option<Sender<QueuedPacket>>,
    base_slots: Option<Arc<Semaphore>>,
    network_slots: Option<Arc<Semaphore>>,
    max_queue_delay_us: Option<Arc<AtomicU32>>,
}

impl MpscTunnelSender {
    pub(crate) fn set_network_slots(&mut self, slots: Arc<Semaphore>) {
        self.network_slots = Some(slots);
    }

    pub(crate) fn set_max_queue_delay_us(&self, delay: u32) {
        if let Some(max_queue_delay_us) = &self.max_queue_delay_us {
            max_queue_delay_us.store(delay, Ordering::Relaxed);
        }
    }

    fn prepare(
        &self,
        packet: ZCPacket,
    ) -> Result<(&Sender<QueuedPacket>, QueuedPacket), TunnelError> {
        if let Some(heartbeat) = &self.heartbeat
            && is_heartbeat(&packet)
        {
            return Ok((
                heartbeat,
                QueuedPacket {
                    packet,
                    _slot: None,
                    enqueued_at: None,
                },
            ));
        }
        if self.sender.is_closed() {
            return Err(TunnelError::Shutdown);
        }
        let slot = if let Some(base_slots) = &self.base_slots {
            Some(
                base_slots
                    .clone()
                    .try_acquire_owned()
                    .ok()
                    .or_else(|| {
                        self.network_slots
                            .as_ref()?
                            .clone()
                            .try_acquire_owned()
                            .ok()
                    })
                    .ok_or(TunnelError::BufferFull)?,
            )
        } else {
            None
        };
        let enqueued_at = (slot.is_some() && can_expire(&packet)).then(Instant::now);
        Ok((
            &self.sender,
            QueuedPacket {
                packet,
                _slot: slot,
                enqueued_at,
            },
        ))
    }

    pub async fn send(&self, item: ZCPacket) -> Result<(), TunnelError> {
        let (sender, item) = self.prepare(item)?;
        match sender.try_send(item) {
            Ok(()) => Ok(()),
            Err(TrySendError::Full(item)) => {
                sender.send(item).await.map_err(|_| TunnelError::Shutdown)
            }
            Err(TrySendError::Closed(_)) => Err(TunnelError::Shutdown),
        }
    }

    pub fn try_send(&self, item: ZCPacket) -> Result<(), TunnelError> {
        let (sender, item) = self.prepare(item)?;
        sender.try_send(item).map_err(|e| match e {
            TrySendError::Full(_) => TunnelError::BufferFull,
            TrySendError::Closed(_) => TunnelError::Shutdown,
        })
    }

    pub(crate) fn should_yield_after_send(&self) -> bool {
        self.sender.max_capacity() - self.sender.capacity() == ORDINARY_QUEUE_CAPACITY
    }
}

/// Only connection writers expand batches. Internal RPC rings keep one entry
/// per RPC. Ordinary fragments stay FIFO, including pre-encrypted relay traffic.
pub(crate) struct MpscTunnelReceiver {
    receiver: Receiver<QueuedPacket>,
    heartbeat: Option<Receiver<QueuedPacket>>,
    max_queue_delay_us: Option<Arc<AtomicU32>>,
    pending: std::vec::IntoIter<ZCPacket>,
}

impl MpscTunnelReceiver {
    pub(crate) fn channel(connection: bool) -> (MpscTunnelSender, Self) {
        let (sender, receiver) = channel(if connection {
            ORDINARY_QUEUE_CAPACITY + NETWORK_QUEUE_SLOTS
        } else {
            ORDINARY_QUEUE_CAPACITY
        });
        let (heartbeat_tx, heartbeat_rx) = if connection {
            let (tx, rx) = channel(8);
            (Some(tx), Some(rx))
        } else {
            (None, None)
        };
        let max_queue_delay_us = connection.then(|| Arc::new(AtomicU32::new(0)));
        (
            MpscTunnelSender {
                sender,
                heartbeat: heartbeat_tx,
                base_slots: connection.then(|| Arc::new(Semaphore::new(ORDINARY_QUEUE_CAPACITY))),
                network_slots: None,
                max_queue_delay_us: max_queue_delay_us.clone(),
            },
            Self {
                receiver,
                heartbeat: heartbeat_rx,
                max_queue_delay_us,
                pending: Vec::new().into_iter(),
            },
        )
    }

    fn dequeue(&mut self, queued: QueuedPacket) -> Option<ZCPacket> {
        if let Some(enqueued_at) = queued.enqueued_at
            && let Some(max_queue_delay_us) = &self.max_queue_delay_us
        {
            let limit_us = max_queue_delay_us.load(Ordering::Relaxed);
            let age = enqueued_at.elapsed();
            if limit_us != 0 && age > Duration::from_micros(limit_us.into()) {
                tracing::trace!(?age, limit_us, "dropping expired peer send packet");
                return None;
            }
        }

        let QueuedPacket { mut packet, .. } = queued;
        if self.heartbeat.is_some() {
            self.pending = packet.take_batch();
        }
        Some(packet)
    }

    fn try_recv(&mut self) -> Option<ZCPacket> {
        loop {
            if let Some(heartbeat) = &mut self.heartbeat
                && let Ok(packet) = heartbeat.try_recv()
            {
                return Some(packet.packet);
            }
            if let Some(packet) = self.pending.next() {
                if self.pending.as_slice().is_empty() {
                    self.pending = Vec::new().into_iter();
                }
                return Some(packet);
            }
            let queued = self.receiver.try_recv().ok()?;
            if let Some(packet) = self.dequeue(queued) {
                return Some(packet);
            }
        }
    }

    pub(crate) async fn recv(&mut self) -> Option<ZCPacket> {
        loop {
            if let Some(packet) = self.try_recv() {
                return Some(packet);
            }
            let queued = if let Some(heartbeat) = &mut self.heartbeat {
                tokio::select! {
                    biased;
                    packet = heartbeat.recv() => packet,
                    packet = self.receiver.recv() => packet,
                }
            } else {
                self.receiver.recv().await
            }?;
            if let Some(packet) = self.dequeue(queued) {
                return Some(packet);
            }
        }
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
        Self::new_inner(tunnel, send_timeout, MpscTunnelReceiver::channel(false))
    }

    pub(crate) fn new_peer_conn(tunnel: T, send_timeout: Duration) -> Self {
        Self::new_inner(
            tunnel,
            Some(send_timeout),
            MpscTunnelReceiver::channel(true),
        )
    }

    fn new_inner(
        tunnel: T,
        send_timeout: Option<Duration>,
        (tx, mut rx): (MpscTunnelSender, MpscTunnelReceiver),
    ) -> Self {
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
            base_slots: None,
            network_slots: None,
            max_queue_delay_us: None,
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

        assert_eq!(rx.recv().await.unwrap().packet.payload(), b"first");
        tokio::time::timeout(Duration::from_secs(1), &mut blocked_send)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(rx.recv().await.unwrap().packet.payload(), b"second");
    }
    fn rpc_fragment(payload: &[u8]) -> ZCPacket {
        let mut packet = ZCPacket::new_with_payload(payload);
        packet.fill_peer_manager_hdr(1, 2, PacketType::RpcReq as u8);
        packet
    }

    #[tokio::test(start_paused = true)]
    async fn expired_data_releases_shared_slots_and_preserves_control_and_fifo() {
        let network_slots = Arc::new(Semaphore::new(1));
        let (mut sender, mut receiver) = MpscTunnelReceiver::channel(true);
        sender.set_network_slots(network_slots.clone());
        let make_packet = |kind: PacketType, payload: &[u8]| {
            let mut packet = ZCPacket::new_with_payload(payload);
            packet.fill_peer_manager_hdr(1, 2, kind as u8);
            packet
        };
        sender
            .try_send(make_packet(PacketType::Data, b"no RTT sample"))
            .unwrap();
        tokio::time::advance(Duration::from_secs(1)).await;
        assert_eq!(receiver.recv().await.unwrap().payload(), b"no RTT sample");

        sender.set_max_queue_delay_us(50_000);
        sender
            .try_send(ZCPacket::batch(vec![
                rpc_fragment(b"rpc"),
                rpc_fragment(b"tail"),
            ]))
            .unwrap();
        for _ in 1..ORDINARY_QUEUE_CAPACITY {
            sender
                .try_send(make_packet(PacketType::Data, b"expired"))
                .unwrap();
        }
        sender
            .try_send(ZCPacket::batch(vec![
                make_packet(PacketType::Data, b"expired batch head"),
                make_packet(PacketType::Data, b"expired batch tail"),
            ]))
            .unwrap();
        assert_eq!(network_slots.available_permits(), 0);
        sender
            .try_send(make_packet(PacketType::Ping, b"ping"))
            .unwrap();
        tokio::time::advance(Duration::from_millis(51)).await;
        assert_eq!(receiver.recv().await.unwrap().payload(), b"ping");
        assert_eq!(receiver.recv().await.unwrap().payload(), b"rpc");
        assert_eq!(receiver.recv().await.unwrap().payload(), b"tail");

        sender
            .try_send(make_packet(PacketType::Data, b"fresh"))
            .unwrap();
        assert_eq!(receiver.recv().await.unwrap().payload(), b"fresh");
        assert_eq!(network_slots.available_permits(), 1);
        assert!(receiver.try_recv().is_none());
    }

    #[test]
    fn connections_compete_for_shared_slots_and_keep_their_base() {
        let network_slots = Arc::new(Semaphore::new(1));
        let (mut first, first_rx) = MpscTunnelReceiver::channel(true);
        let (mut second, second_rx) = MpscTunnelReceiver::channel(true);
        for sender in [&mut first, &mut second] {
            sender.set_network_slots(network_slots.clone());
            for _ in 0..ORDINARY_QUEUE_CAPACITY {
                sender.try_send(rpc_fragment(b"base")).unwrap();
            }
        }
        assert_eq!(network_slots.available_permits(), 1);

        let barrier = std::sync::Barrier::new(2);
        let send = |sender: &MpscTunnelSender| {
            barrier.wait();
            sender.try_send(rpc_fragment(b"borrow"))
        };
        let (first_result, second_result) = std::thread::scope(|scope| {
            let first = scope.spawn(|| send(&first));
            let second = send(&second);
            (first.join().unwrap(), second)
        });
        let (winner_rx, loser, loser_rx) = match (first_result, second_result) {
            (Ok(()), Err(TunnelError::BufferFull)) => (first_rx, second, second_rx),
            (Err(TunnelError::BufferFull), Ok(())) => (second_rx, first, first_rx),
            results => panic!("expected exactly one borrower, got {results:?}"),
        };
        assert_eq!(network_slots.available_permits(), 0);

        let (mut newcomer, _newcomer_rx) = MpscTunnelReceiver::channel(true);
        newcomer.set_network_slots(network_slots.clone());
        let (mut other, _other_rx) = MpscTunnelReceiver::channel(true);
        other.set_network_slots(Arc::new(Semaphore::new(1)));
        for _ in 0..ORDINARY_QUEUE_CAPACITY {
            newcomer.try_send(rpc_fragment(b"base")).unwrap();
            other.try_send(rpc_fragment(b"base")).unwrap();
        }
        assert!(matches!(
            newcomer.try_send(rpc_fragment(b"borrow")),
            Err(TunnelError::BufferFull)
        ));
        other.try_send(rpc_fragment(b"borrow")).unwrap();

        drop(winner_rx);
        let (channel, queued) = loser.prepare(rpc_fragment(b"borrow")).unwrap();
        assert_eq!(network_slots.available_permits(), 0);
        drop(loser_rx);
        assert!(matches!(
            channel.try_send(queued),
            Err(TrySendError::Closed(_))
        ));
        assert_eq!(network_slots.available_permits(), 1);
        newcomer.try_send(rpc_fragment(b"borrow")).unwrap();
    }

    #[test]
    fn borrowed_rpc_batch_uses_one_slot_and_expands_in_fifo_order() {
        let network_slots = Arc::new(Semaphore::new(1));
        let (mut sender, mut receiver) = MpscTunnelReceiver::channel(true);
        sender.set_network_slots(network_slots.clone());
        for _ in 0..ORDINARY_QUEUE_CAPACITY {
            sender.try_send(rpc_fragment(b"base")).unwrap();
        }

        let batch = ZCPacket::batch(vec![rpc_fragment(b"first"), rpc_fragment(b"last")]);
        sender.try_send(batch).unwrap();
        assert_eq!(network_slots.available_permits(), 0);
        assert!(matches!(
            sender.try_send(rpc_fragment(b"full")),
            Err(TunnelError::BufferFull)
        ));

        for _ in 0..ORDINARY_QUEUE_CAPACITY {
            assert_eq!(receiver.try_recv().unwrap().payload(), b"base");
        }
        assert_eq!(network_slots.available_permits(), 0);
        assert_eq!(receiver.try_recv().unwrap().payload(), b"first");
        assert_eq!(network_slots.available_permits(), 1);
        sender.try_send(rpc_fragment(b"next")).unwrap();
        let mut pong = rpc_fragment(b"pong");
        pong.fill_peer_manager_hdr(1, 2, PacketType::Pong as u8);
        sender.try_send(pong).unwrap();
        assert_eq!(receiver.try_recv().unwrap().payload(), b"pong");
        assert_eq!(receiver.try_recv().unwrap().payload(), b"last");
        assert_eq!(receiver.try_recv().unwrap().payload(), b"next");
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
