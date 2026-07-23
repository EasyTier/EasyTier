use super::{BroadcastRelayConfig, RawUdpCaptureSocket};

pub(super) struct CaptureSocket(RawUdpCaptureSocket);

impl CaptureSocket {
    pub(super) async fn recv(&mut self) -> std::io::Result<&[u8]> {
        self.0.recv().await
    }

    pub(super) fn backend_name(&self) -> &'static str {
        "raw_socket"
    }

    pub(super) fn fallback_to_raw(&mut self) -> anyhow::Result<bool> {
        Ok(false)
    }
}

pub(super) fn open_capture_socket(_config: &BroadcastRelayConfig) -> anyhow::Result<CaptureSocket> {
    RawUdpCaptureSocket::open().map(CaptureSocket)
}
