use std::{
    pin::Pin,
    sync::{Arc, Mutex},
};

use futures::{SinkExt, StreamExt, channel::mpsc};

use crate::{
    packet::ZCPacket,
    proto::common::TunnelInfo,
    tunnel::{Tunnel, TunnelError, ZCPacketSink, ZCPacketStream},
};

pub const MEMORY_TUNNEL_CAP: usize = 128;

pub struct MemoryTunnel {
    stream: Mutex<Option<mpsc::Receiver<ZCPacket>>>,
    sink: Mutex<Option<mpsc::Sender<ZCPacket>>>,
    info: Option<TunnelInfo>,
}

impl MemoryTunnel {
    pub fn new(
        stream: mpsc::Receiver<ZCPacket>,
        sink: mpsc::Sender<ZCPacket>,
        info: Option<TunnelInfo>,
    ) -> Self {
        Self {
            stream: Mutex::new(Some(stream)),
            sink: Mutex::new(Some(sink)),
            info,
        }
    }
}

impl Tunnel for MemoryTunnel {
    fn split(&self) -> (Pin<Box<dyn ZCPacketStream>>, Pin<Box<dyn ZCPacketSink>>) {
        let stream = self
            .stream
            .lock()
            .unwrap()
            .take()
            .expect("MemoryTunnel stream can only be split once")
            .map(Ok);
        let sink = self
            .sink
            .lock()
            .unwrap()
            .take()
            .expect("MemoryTunnel sink can only be split once")
            .sink_map_err(|_| TunnelError::Shutdown);
        (Box::pin(stream), Box::pin(sink))
    }

    fn info(&self) -> Option<TunnelInfo> {
        self.info.clone()
    }
}

pub fn create_memory_tunnel_pair() -> (Box<dyn Tunnel>, Box<dyn Tunnel>) {
    let (a_tx, a_rx) = mpsc::channel(MEMORY_TUNNEL_CAP);
    let (b_tx, b_rx) = mpsc::channel(MEMORY_TUNNEL_CAP);
    (
        Box::new(Arc::new(MemoryTunnel::new(a_rx, b_tx, None))),
        Box::new(Arc::new(MemoryTunnel::new(b_rx, a_tx, None))),
    )
}
