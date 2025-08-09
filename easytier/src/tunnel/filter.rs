use std::{
    sync::Arc,
    task::{Context, Poll},
};

use auto_impl::auto_impl;
use futures::{Sink, SinkExt, Stream, StreamExt};

use crate::proto::common::TunnelInfo;

use self::stats::Throughput;

use super::*;

#[auto_impl(Arc, Box)]
pub trait TunnelFilter: Send + Sync {
    type FilterOutput;

    fn before_send(&self, data: SinkItem) -> Option<SinkItem> {
        Some(data)
    }

    fn after_received(&self, data: StreamItem) -> Option<StreamItem> {
        match data {
            Ok(v) => Some(Ok(v)),
            Err(e) => Some(Err(e)),
        }
    }

    fn filter_output(&self) -> Self::FilterOutput;
}

pub struct TunnelFilterChain<A, B> {
    a: A,
    b: B,
}

impl<A, B, OA, OB> TunnelFilter for TunnelFilterChain<A, B>
where
    A: TunnelFilter<FilterOutput = OA>,
    B: TunnelFilter<FilterOutput = OB>,
{
    type FilterOutput = (OA, OB);
    fn before_send(&self, data: SinkItem) -> Option<SinkItem> {
        let data = self.a.before_send(data)?;
        self.b.before_send(data)
    }
    fn after_received(&self, data: StreamItem) -> Option<StreamItem> {
        let data = self.b.after_received(data)?;
        self.a.after_received(data)
    }
    fn filter_output(&self) -> Self::FilterOutput {
        (self.a.filter_output(), self.b.filter_output())
    }
}

impl<A, B> TunnelFilterChain<A, B> {
    pub fn new(a: A, b: B) -> Self {
        Self { a, b }
    }

    pub fn chain<T: TunnelFilter>(self, c: T) -> TunnelFilterChain<Self, T> {
        TunnelFilterChain::new(self, c)
    }
}

pub struct EmptyFilter;
impl TunnelFilter for EmptyFilter {
    type FilterOutput = ();
    fn filter_output(&self) {}
}

pub trait ToTunnelChain {
    fn to_chain(self) -> TunnelFilterChain<EmptyFilter, Self>
    where
        Self: Sized,
    {
        TunnelFilterChain::new(EmptyFilter, self)
    }
}

impl<O, T: TunnelFilter<FilterOutput = O>> ToTunnelChain for T {}

pub struct TunnelWithFilter<T, F> {
    inner: T,
    filter: Arc<F>,
}

impl<T, F> TunnelWithFilter<T, F>
where
    T: Tunnel + Send + 'static,
    F: TunnelFilter + Send + 'static,
{
    pub fn new(inner: T, filter: F) -> Self {
        Self {
            inner,
            filter: Arc::new(filter),
        }
    }

    fn wrap_sink<S: ZCPacketSink + Unpin + 'static>(&self, sink: S) -> impl ZCPacketSink {
        struct SinkWrapper<F, S> {
            sink: S,
            filter: Arc<F>,
        }

        impl<F, S> Sink<ZCPacket> for SinkWrapper<F, S>
        where
            F: TunnelFilter + 'static,
            S: ZCPacketSink + 'static + Unpin,
        {
            type Error = SinkError;

            fn poll_ready(
                self: std::pin::Pin<&mut Self>,
                cx: &mut Context<'_>,
            ) -> Poll<Result<(), Self::Error>> {
                self.get_mut().sink.poll_ready_unpin(cx)
            }

            fn start_send(
                self: std::pin::Pin<&mut Self>,
                item: ZCPacket,
            ) -> Result<(), Self::Error> {
                let Some(item) = self.filter.before_send(item) else {
                    return Ok(());
                };
                self.get_mut().sink.start_send_unpin(item)
            }

            fn poll_flush(
                self: std::pin::Pin<&mut Self>,
                cx: &mut Context<'_>,
            ) -> Poll<Result<(), Self::Error>> {
                self.get_mut().sink.poll_flush_unpin(cx)
            }

            fn poll_close(
                self: std::pin::Pin<&mut Self>,
                cx: &mut Context<'_>,
            ) -> Poll<Result<(), Self::Error>> {
                self.get_mut().sink.poll_close_unpin(cx)
            }
        }

        SinkWrapper {
            sink,
            filter: self.filter.clone(),
        }
    }

    fn wrap_stream<S: ZCPacketStream + Unpin + 'static>(&self, stream: S) -> impl ZCPacketStream {
        struct StreamWrapper<F, S> {
            stream: S,
            filter: Arc<F>,
        }

        impl<F, S> Stream for StreamWrapper<F, S>
        where
            F: TunnelFilter + 'static,
            S: ZCPacketStream + 'static + Unpin,
        {
            type Item = StreamItem;

            fn poll_next(
                self: std::pin::Pin<&mut Self>,
                cx: &mut Context<'_>,
            ) -> Poll<Option<Self::Item>> {
                let self_mut = self.get_mut();
                loop {
                    match self_mut.stream.poll_next_unpin(cx) {
                        Poll::Ready(Some(ret)) => {
                            let Some(ret) = self_mut.filter.after_received(ret) else {
                                continue;
                            };
                            return Poll::Ready(Some(ret));
                        }
                        Poll::Ready(None) => {
                            return Poll::Ready(None);
                        }
                        Poll::Pending => {
                            return Poll::Pending;
                        }
                    }
                }
            }
        }

        StreamWrapper {
            stream,
            filter: self.filter.clone(),
        }
    }
}

impl<T, F> Tunnel for TunnelWithFilter<T, F>
where
    T: Tunnel + Send + 'static,
    F: TunnelFilter + Send + 'static,
{
    fn info(&self) -> Option<TunnelInfo> {
        self.inner.info()
    }

    fn split(&self) -> (Pin<Box<dyn ZCPacketStream>>, Pin<Box<dyn ZCPacketSink>>) {
        let (stream, sink) = self.inner.split();
        (
            Box::pin(self.wrap_stream(stream)),
            Box::pin(self.wrap_sink(sink)),
        )
    }
}

pub struct PacketRecorderTunnelFilter {
    pub received: Arc<std::sync::Mutex<Vec<ZCPacket>>>,
    pub sent: Arc<std::sync::Mutex<Vec<ZCPacket>>>,
}

impl TunnelFilter for PacketRecorderTunnelFilter {
    type FilterOutput = (Vec<ZCPacket>, Vec<ZCPacket>);

    fn before_send(&self, data: SinkItem) -> Option<SinkItem> {
        self.received.lock().unwrap().push(data.clone());
        Some(data)
    }

    fn after_received(&self, data: StreamItem) -> Option<StreamItem> {
        match data {
            Ok(v) => {
                self.sent.lock().unwrap().push(v.clone());
                Some(Ok(v))
            }
            Err(e) => Some(Err(e)),
        }
    }

    fn filter_output(&self) -> Self::FilterOutput {
        (
            self.received.lock().unwrap().clone(),
            self.sent.lock().unwrap().clone(),
        )
    }
}

impl Default for PacketRecorderTunnelFilter {
    fn default() -> Self {
        Self::new()
    }
}

impl PacketRecorderTunnelFilter {
    pub fn new() -> Self {
        Self {
            received: Arc::new(std::sync::Mutex::new(Vec::new())),
            sent: Arc::new(std::sync::Mutex::new(Vec::new())),
        }
    }
}

pub struct StatsRecorderTunnelFilter {
    throughput: Arc<Throughput>,
}

impl TunnelFilter for StatsRecorderTunnelFilter {
    type FilterOutput = Arc<Throughput>;

    fn before_send(&self, data: SinkItem) -> Option<SinkItem> {
        self.throughput.record_tx_bytes(data.buf_len() as u64);
        Some(data)
    }

    fn after_received(&self, data: StreamItem) -> Option<StreamItem> {
        match data {
            Ok(v) => {
                self.throughput.record_rx_bytes(v.buf_len() as u64);
                Some(Ok(v))
            }
            Err(e) => Some(Err(e)),
        }
    }

    fn filter_output(&self) -> Self::FilterOutput {
        self.throughput.clone()
    }
}

impl Default for StatsRecorderTunnelFilter {
    fn default() -> Self {
        Self::new()
    }
}

impl StatsRecorderTunnelFilter {
    pub fn new() -> Self {
        Self {
            throughput: Arc::new(Throughput::new()),
        }
    }

    pub fn get_throughput(&self) -> Arc<Throughput> {
        self.throughput.clone()
    }
}

#[cfg(test)]
pub mod tests {
    use std::sync::atomic::{AtomicU32, Ordering};

    use filter::ring::create_ring_tunnel_pair;

    use super::*;

    pub struct DropSendTunnelFilter {
        start: AtomicU32,
        end: AtomicU32,
        cur: AtomicU32,
    }

    impl TunnelFilter for DropSendTunnelFilter {
        type FilterOutput = ();

        fn before_send(&self, data: SinkItem) -> Option<SinkItem> {
            self.cur.fetch_add(1, Ordering::SeqCst);
            if self.cur.load(Ordering::SeqCst) >= self.start.load(Ordering::SeqCst)
                && self.cur.load(std::sync::atomic::Ordering::SeqCst)
                    < self.end.load(Ordering::SeqCst)
            {
                tracing::trace!("drop packet: {:?}", data);
                return None;
            }
            Some(data)
        }

        fn filter_output(&self) {}
    }

    impl DropSendTunnelFilter {
        pub fn new(start: u32, end: u32) -> Self {
            Self {
                start: AtomicU32::new(start),
                end: AtomicU32::new(end),
                cur: AtomicU32::new(0),
            }
        }
    }

    #[tokio::test]
    async fn test_nested_filter() {
        let filter = Arc::new(
            PacketRecorderTunnelFilter::new()
                .to_chain()
                .chain(PacketRecorderTunnelFilter::new())
                .chain(PacketRecorderTunnelFilter::new())
                .chain(PacketRecorderTunnelFilter::new()),
        );
        let (s, _b) = create_ring_tunnel_pair();
        let tunnel = TunnelWithFilter::new(s, filter.clone());

        let (_r, mut s) = tunnel.split();
        s.send(ZCPacket::new_with_payload("ab".as_bytes()))
            .await
            .unwrap();

        let out = filter.filter_output();

        let a = out.0 .0 .0 .1;
        let b = out.0 .0 .1;
        let c = out.0 .1;
        let _d = out.1;

        assert_eq!(1, a.0.len());
        assert_eq!(1, b.0.len());
        assert_eq!(1, c.0.len());
    }
}
