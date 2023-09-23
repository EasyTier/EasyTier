use std::{
    sync::Arc,
    task::{Context, Poll},
};

use easytier_rpc::TunnelInfo;
use futures::{Sink, SinkExt, Stream, StreamExt};

use self::stats::Throughput;

use super::*;
use crate::tunnels::{DatagramSink, DatagramStream, SinkError, SinkItem, StreamItem, Tunnel};

pub trait TunnelFilter {
    fn before_send(&self, data: SinkItem) -> Result<SinkItem, SinkError>;
    fn after_received(&self, data: StreamItem) -> Result<BytesMut, TunnelError>;
}

pub struct TunnelWithFilter<T, F> {
    inner: T,
    filter: Arc<F>,
}

impl<T, F> Tunnel for TunnelWithFilter<T, F>
where
    T: Tunnel + Send + Sync + 'static,
    F: TunnelFilter + Send + Sync + 'static,
{
    fn sink(&self) -> Box<dyn DatagramSink> {
        struct SinkWrapper<F> {
            sink: Pin<Box<dyn DatagramSink>>,
            filter: Arc<F>,
        }
        impl<F> Sink<SinkItem> for SinkWrapper<F>
        where
            F: TunnelFilter + Send + Sync + 'static,
        {
            type Error = SinkError;

            fn poll_ready(
                self: Pin<&mut Self>,
                cx: &mut Context<'_>,
            ) -> Poll<Result<(), Self::Error>> {
                self.get_mut().sink.poll_ready_unpin(cx)
            }

            fn start_send(self: Pin<&mut Self>, item: SinkItem) -> Result<(), Self::Error> {
                let item = self.filter.before_send(item)?;
                self.get_mut().sink.start_send_unpin(item)
            }

            fn poll_flush(
                self: Pin<&mut Self>,
                cx: &mut Context<'_>,
            ) -> Poll<Result<(), Self::Error>> {
                self.get_mut().sink.poll_flush_unpin(cx)
            }

            fn poll_close(
                self: Pin<&mut Self>,
                cx: &mut Context<'_>,
            ) -> Poll<Result<(), Self::Error>> {
                self.get_mut().sink.poll_close_unpin(cx)
            }
        }

        Box::new(SinkWrapper {
            sink: self.inner.pin_sink(),
            filter: self.filter.clone(),
        })
    }

    fn stream(&self) -> Box<dyn DatagramStream> {
        struct StreamWrapper<F> {
            stream: Pin<Box<dyn DatagramStream>>,
            filter: Arc<F>,
        }
        impl<F> Stream for StreamWrapper<F>
        where
            F: TunnelFilter + Send + Sync + 'static,
        {
            type Item = StreamItem;

            fn poll_next(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
                let self_mut = self.get_mut();
                match self_mut.stream.poll_next_unpin(cx) {
                    Poll::Ready(Some(ret)) => {
                        Poll::Ready(Some(self_mut.filter.after_received(ret)))
                    }
                    Poll::Ready(None) => Poll::Ready(None),
                    Poll::Pending => Poll::Pending,
                }
            }
        }

        Box::new(StreamWrapper {
            stream: self.inner.pin_stream(),
            filter: self.filter.clone(),
        })
    }

    fn info(&self) -> Option<TunnelInfo> {
        self.inner.info()
    }
}

impl<T, F> TunnelWithFilter<T, F>
where
    T: Tunnel + Send + Sync + 'static,
    F: TunnelFilter + Send + Sync + 'static,
{
    pub fn new(inner: T, filter: Arc<F>) -> Self {
        Self { inner, filter }
    }
}

pub struct PacketRecorderTunnelFilter {
    pub received: Arc<std::sync::Mutex<Vec<Bytes>>>,
    pub sent: Arc<std::sync::Mutex<Vec<Bytes>>>,
}

impl TunnelFilter for PacketRecorderTunnelFilter {
    fn before_send(&self, data: SinkItem) -> Result<SinkItem, SinkError> {
        self.received.lock().unwrap().push(data.clone());
        Ok(data)
    }

    fn after_received(&self, data: StreamItem) -> Result<BytesMut, TunnelError> {
        match data {
            Ok(v) => {
                self.sent.lock().unwrap().push(v.clone().into());
                Ok(v)
            }
            Err(e) => Err(e),
        }
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
    fn before_send(&self, data: SinkItem) -> Result<SinkItem, SinkError> {
        self.throughput.record_tx_bytes(data.len() as u64);
        Ok(data)
    }

    fn after_received(&self, data: StreamItem) -> Result<BytesMut, TunnelError> {
        match data {
            Ok(v) => {
                self.throughput.record_rx_bytes(v.len() as u64);
                Ok(v)
            }
            Err(e) => Err(e),
        }
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

#[macro_export]
macro_rules! define_tunnel_filter_chain {
    ($type_name:ident $(, $field_name:ident = $filter_type:ty)+) => (
        pub struct $type_name {
            $($field_name: std::sync::Arc<$filter_type>,)+
        }

        impl $type_name {
            pub fn new() -> Self {
                Self {
                    $($field_name: std::sync::Arc::new(<$filter_type>::new()),)+
                }
            }

            pub fn wrap_tunnel(&self, tunnel: impl Tunnel + 'static) -> impl Tunnel {
                $(
                    let tunnel = crate::tunnels::tunnel_filter::TunnelWithFilter::new(tunnel, self.$field_name.clone());
                )+
                tunnel
            }
        }
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tunnels::ring_tunnel::RingTunnel;
    #[tokio::test]
    async fn test_nested_filter() {
        define_tunnel_filter_chain!(
            Filter,
            a = PacketRecorderTunnelFilter,
            b = PacketRecorderTunnelFilter,
            c = PacketRecorderTunnelFilter
        );

        let filter = Filter::new();
        let tunnel = filter.wrap_tunnel(RingTunnel::new(1));

        let mut s = tunnel.pin_sink();
        s.send(Bytes::from("hello")).await.unwrap();

        assert_eq!(1, filter.a.received.lock().unwrap().len());
        assert_eq!(1, filter.b.received.lock().unwrap().len());
        assert_eq!(1, filter.c.received.lock().unwrap().len());
    }
}
