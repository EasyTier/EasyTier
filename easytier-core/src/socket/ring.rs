use std::{
    fmt::Debug,
    pin::Pin,
    sync::{Arc, Mutex},
    task::{Context, Poll, ready},
};

use async_ringbuf::{AsyncHeapCons, AsyncHeapProd, AsyncHeapRb, traits::*};
use futures::{Sink, SinkExt, Stream, StreamExt};
use uuid::Uuid;

pub const RING_SOCKET_CAPACITY: usize = 128;
const RING_SOCKET_RESERVED_CAPACITY: usize = 4;

pub type RingSocketId = Uuid;

#[derive(Debug, thiserror::Error, Clone, Copy, PartialEq, Eq)]
pub enum RingSocketError {
    #[error("ring socket already split")]
    AlreadySplit,
    #[error("ring socket closed")]
    Closed,
    #[error("ring socket full")]
    Full,
}

#[derive(Debug, thiserror::Error, Clone, Copy, PartialEq, Eq)]
pub enum RingSocketSendError<T> {
    #[error("ring socket closed")]
    Closed(T),
    #[error("ring socket full")]
    Full(T),
}

pub type RingSocketStreamItem<T> = Result<T, RingSocketError>;

/// An in-process socket primitive.
///
/// `RingSocket` is intentionally below `Tunnel`: it contains no tunnel schema,
/// no peer metadata, and no `TunnelInfo`. The core ring tunnel Module wraps it
/// into a `Tunnel` when a peer connection needs one.
pub struct RingSocket<T> {
    id: RingSocketId,
    parts: Mutex<Option<RingSocketParts<T>>>,
}

struct RingSocketParts<T> {
    recv: AsyncHeapCons<T>,
    send: AsyncHeapProd<T>,
}

impl<T> RingSocket<T> {
    pub fn pair(capacity: usize) -> (Arc<Self>, Arc<Self>) {
        Self::pair_with_ids(Uuid::new_v4(), Uuid::new_v4(), capacity)
    }

    pub fn pair_with_ids(
        first_id: RingSocketId,
        second_id: RingSocketId,
        capacity: usize,
    ) -> (Arc<Self>, Arc<Self>) {
        let capacity = std::cmp::max(RING_SOCKET_RESERVED_CAPACITY * 2, capacity);
        let first_to_second = AsyncHeapRb::new(capacity);
        let second_to_first = AsyncHeapRb::new(capacity);
        let (first_to_second_send, first_to_second_recv) = first_to_second.split();
        let (second_to_first_send, second_to_first_recv) = second_to_first.split();

        (
            Arc::new(Self {
                id: first_id,
                parts: Mutex::new(Some(RingSocketParts {
                    recv: second_to_first_recv,
                    send: first_to_second_send,
                })),
            }),
            Arc::new(Self {
                id: second_id,
                parts: Mutex::new(Some(RingSocketParts {
                    recv: first_to_second_recv,
                    send: second_to_first_send,
                })),
            }),
        )
    }

    pub fn id(&self) -> RingSocketId {
        self.id
    }

    pub fn split(&self) -> (RingSocketReceiver<T>, RingSocketSender<T>) {
        self.try_split().expect("RingSocket can only be split once")
    }

    pub fn try_split(
        &self,
    ) -> Result<(RingSocketReceiver<T>, RingSocketSender<T>), RingSocketError> {
        let parts = self
            .parts
            .lock()
            .unwrap()
            .take()
            .ok_or(RingSocketError::AlreadySplit)?;

        Ok((
            RingSocketReceiver {
                id: self.id,
                recv: parts.recv,
            },
            RingSocketSender {
                id: self.id,
                send: parts.send,
            },
        ))
    }
}

impl<T> Debug for RingSocket<T> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RingSocket")
            .field("id", &self.id)
            .finish_non_exhaustive()
    }
}

pub struct RingSocketReceiver<T> {
    id: RingSocketId,
    recv: AsyncHeapCons<T>,
}

impl<T> Stream for RingSocketReceiver<T> {
    type Item = RingSocketStreamItem<T>;

    fn poll_next(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        match ready!(self.get_mut().recv.poll_next_unpin(cx)) {
            Some(item) => Poll::Ready(Some(Ok(item))),
            None => Poll::Ready(None),
        }
    }
}

impl<T> Debug for RingSocketReceiver<T> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RingSocketReceiver")
            .field("id", &self.id)
            .field("len", &self.recv.base().occupied_len())
            .field("cap", &self.recv.base().capacity())
            .finish()
    }
}

pub struct RingSocketSender<T> {
    id: RingSocketId,
    send: AsyncHeapProd<T>,
}

impl<T> RingSocketSender<T> {
    pub fn try_send(&mut self, item: T) -> Result<(), RingSocketSendError<T>> {
        if self.send.is_closed() {
            return Err(RingSocketSendError::Closed(item));
        }

        let base = self.send.base();
        if base.occupied_len() >= base.capacity().get() - RING_SOCKET_RESERVED_CAPACITY {
            return Err(RingSocketSendError::Full(item));
        }

        self.send.try_push(item).map_err(|item| {
            if self.send.is_closed() {
                RingSocketSendError::Closed(item)
            } else {
                RingSocketSendError::Full(item)
            }
        })
    }

    pub fn force_send(&mut self, item: T) -> Result<(), RingSocketSendError<T>> {
        if self.send.is_closed() {
            return Err(RingSocketSendError::Closed(item));
        }

        self.send.try_push(item).map_err(|item| {
            if self.send.is_closed() {
                RingSocketSendError::Closed(item)
            } else {
                RingSocketSendError::Full(item)
            }
        })
    }
}

impl<T> Sink<T> for RingSocketSender<T> {
    type Error = RingSocketError;

    fn poll_ready(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        ready!(self.get_mut().send.poll_ready_unpin(cx)).map_err(|_| RingSocketError::Closed)?;
        Poll::Ready(Ok(()))
    }

    fn start_send(self: Pin<&mut Self>, item: T) -> Result<(), Self::Error> {
        self.get_mut()
            .force_send(item)
            .map_err(|error| match error {
                RingSocketSendError::Closed(_) => RingSocketError::Closed,
                RingSocketSendError::Full(_) => RingSocketError::Full,
            })
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        ready!(self.get_mut().send.poll_flush_unpin(cx)).map_err(|_| RingSocketError::Closed)?;
        Poll::Ready(Ok(()))
    }

    fn poll_close(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        ready!(self.get_mut().send.poll_close_unpin(cx)).map_err(|_| RingSocketError::Closed)?;
        Poll::Ready(Ok(()))
    }
}

impl<T> Debug for RingSocketSender<T> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RingSocketSender")
            .field("id", &self.id)
            .field("len", &self.send.base().occupied_len())
            .field("cap", &self.send.base().capacity())
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use futures::{SinkExt, StreamExt};

    use crate::packet::ZCPacket;

    use super::*;

    #[tokio::test]
    async fn ring_socket_pair_transfers_packets() {
        let (left, right) = RingSocket::<ZCPacket>::pair(8);
        let (_left_recv, mut left_send) = left.split();
        let (mut right_recv, _right_send) = right.split();

        let packet = ZCPacket::new_with_payload(&[1, 2, 3]);
        left_send.send(packet.clone()).await.unwrap();

        let received = right_recv.next().await.unwrap().unwrap();
        assert_eq!(received.payload(), packet.payload());
    }

    #[test]
    fn ring_socket_split_is_single_use() {
        let (left, _right) = RingSocket::<ZCPacket>::pair(8);

        let _first = left.try_split().unwrap();
        assert_eq!(left.try_split().unwrap_err(), RingSocketError::AlreadySplit);
    }

    #[test]
    fn ring_socket_try_send_reserves_capacity() {
        let (left, _right) = RingSocket::<ZCPacket>::pair(8);
        let (_left_recv, mut left_send) = left.split();

        for _ in 0..4 {
            left_send
                .try_send(ZCPacket::new_with_payload(&[1]))
                .unwrap();
        }

        assert!(
            left_send
                .try_send(ZCPacket::new_with_payload(&[1]))
                .is_err_and(|error| matches!(error, RingSocketSendError::Full(_)))
        );
        assert!(
            left_send
                .force_send(ZCPacket::new_with_payload(&[1]))
                .is_ok()
        );
    }

    #[test]
    fn ring_socket_sync_send_reports_closed_receiver() {
        let (left, right) = RingSocket::<ZCPacket>::pair(8);
        let (_left_recv, mut left_send) = left.split();
        let (right_recv, _right_send) = right.split();
        drop(right_recv);

        assert!(
            left_send
                .try_send(ZCPacket::new_with_payload(&[1]))
                .is_err_and(|error| matches!(error, RingSocketSendError::Closed(_)))
        );
        assert!(
            left_send
                .force_send(ZCPacket::new_with_payload(&[1]))
                .is_err_and(|error| matches!(error, RingSocketSendError::Closed(_)))
        );
    }
}
