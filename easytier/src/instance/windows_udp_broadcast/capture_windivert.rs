use std::{io, sync::Arc};

use anyhow::Context;
use windivert::{
    WinDivert,
    error::WinDivertError,
    layer,
    packet::WinDivertPacket,
    prelude::{WinDivertFlags, WinDivertShutdownMode},
};

use super::{BroadcastRelayConfig, RawUdpCaptureSocket};
use crate::instance::windows_udp_broadcast::build_windivert_udp_filter;

struct WinDivertCaptureReader {
    inner: std::cell::UnsafeCell<WinDivert<layer::NetworkLayer>>,
}

unsafe impl Send for WinDivertCaptureReader {}
unsafe impl Sync for WinDivertCaptureReader {}

impl WinDivertCaptureReader {
    fn new(inner: WinDivert<layer::NetworkLayer>) -> Self {
        Self {
            inner: std::cell::UnsafeCell::new(inner),
        }
    }

    fn recv<'a>(
        &self,
        buffer: Option<&'a mut [u8]>,
    ) -> Result<WinDivertPacket<'a, layer::NetworkLayer>, WinDivertError> {
        let inner = unsafe { &*self.inner.get() };
        inner.recv(buffer)
    }

    fn shutdown(&self) -> anyhow::Result<()> {
        let inner = unsafe { &mut *self.inner.get() };
        inner
            .shutdown(WinDivertShutdownMode::Recv)
            .with_context(|| "WinDivert UDP broadcast capture shutdown failed")?;
        Ok(())
    }

    fn close(&self) -> anyhow::Result<()> {
        let inner = unsafe { &mut *self.inner.get() };
        inner
            .close(windivert::CloseAction::Nothing)
            .with_context(|| "WinDivert UDP broadcast capture close failed")?;
        Ok(())
    }
}

impl Drop for WinDivertCaptureReader {
    fn drop(&mut self) {
        if let Err(err) = self.close() {
            tracing::error!(?err, "WinDivert UDP broadcast capture close failed");
        }
    }
}

pub(super) struct WinDivertCaptureSocket {
    rx: tokio::sync::mpsc::Receiver<Vec<u8>>,
    reader: Arc<WinDivertCaptureReader>,
    buf: Vec<u8>,
}

impl WinDivertCaptureSocket {
    const CHANNEL_CAPACITY: usize = 1024;
    const MAX_PACKET_LEN: usize = 65_535;

    fn open(config: &BroadcastRelayConfig) -> anyhow::Result<Self> {
        let filter = build_windivert_udp_filter(config.physical_interfaces());
        tracing::debug!(
            filter = %filter,
            "opening WinDivert UDP broadcast capture backend"
        );

        let flags = WinDivertFlags::default().set_sniff();
        let reader = WinDivert::network(&filter, 0, flags)
            .map_err(io::Error::other)
            .with_context(|| "failed to open WinDivert UDP broadcast capture")?;
        let reader = Arc::new(WinDivertCaptureReader::new(reader));
        let reader_clone = reader.clone();
        let (tx, rx) = tokio::sync::mpsc::channel(Self::CHANNEL_CAPACITY);

        std::thread::Builder::new()
            .name("easytier-udp-broadcast-windivert".to_owned())
            .spawn(move || {
                let mut buffer = vec![0; Self::MAX_PACKET_LEN];
                loop {
                    match reader_clone.recv(Some(&mut buffer)) {
                        Ok(packet) => {
                            if tx.blocking_send(packet.data.to_vec()).is_err() {
                                break;
                            }
                        }
                        Err(err) => {
                            tracing::warn!(?err, "WinDivert UDP broadcast capture receive failed");
                            break;
                        }
                    }
                }
            })
            .with_context(|| "failed to spawn WinDivert UDP broadcast capture thread")?;

        Ok(Self {
            rx,
            reader,
            buf: Vec::new(),
        })
    }

    async fn recv(&mut self) -> io::Result<&[u8]> {
        self.buf = self.rx.recv().await.ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::BrokenPipe,
                "WinDivert UDP broadcast capture stopped",
            )
        })?;
        Ok(&self.buf)
    }
}

impl Drop for WinDivertCaptureSocket {
    fn drop(&mut self) {
        if let Err(err) = self.reader.shutdown() {
            tracing::debug!(?err, "WinDivert UDP broadcast capture shutdown failed");
        }
    }
}

pub(super) enum CaptureSocket {
    Raw(RawUdpCaptureSocket),
    WinDivert(WinDivertCaptureSocket),
}

impl CaptureSocket {
    pub(super) async fn recv(&mut self) -> io::Result<&[u8]> {
        match self {
            Self::Raw(socket) => socket.recv().await,
            Self::WinDivert(socket) => socket.recv().await,
        }
    }

    pub(super) fn backend_name(&self) -> &'static str {
        match self {
            Self::Raw(_) => "raw_socket",
            Self::WinDivert(_) => "windivert",
        }
    }

    pub(super) fn fallback_to_raw(&mut self) -> anyhow::Result<bool> {
        if matches!(self, Self::WinDivert(_)) {
            *self = Self::Raw(RawUdpCaptureSocket::open()?);
            return Ok(true);
        }
        Ok(false)
    }
}

pub(super) fn open_capture_socket(config: &BroadcastRelayConfig) -> anyhow::Result<CaptureSocket> {
    match WinDivertCaptureSocket::open(config) {
        Ok(socket) => Ok(CaptureSocket::WinDivert(socket)),
        Err(err) => {
            tracing::warn!(
                ?err,
                "WinDivert UDP broadcast capture unavailable; falling back to raw socket"
            );
            RawUdpCaptureSocket::open().map(CaptureSocket::Raw)
        }
    }
}
