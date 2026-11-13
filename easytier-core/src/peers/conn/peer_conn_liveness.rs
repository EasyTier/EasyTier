use std::sync::{
    Arc,
    atomic::{AtomicBool, AtomicU8, AtomicU16, Ordering},
};

use tokio::sync::Notify;

use crate::tunnel::{SinkItem, StreamItem, filter::TunnelFilter};

pub(super) const FEATURE: &str = "liveness-echo-v1";

#[derive(Clone, Default)]
pub(super) struct PeerConnLiveness {
    inner: Arc<PeerConnLivenessInner>,
}

#[derive(Default)]
struct PeerConnLivenessInner {
    enabled: AtomicBool,
    next_token: AtomicU8,
    active_probe: AtomicU16,
    acknowledged_probe: AtomicU16,
    pending_echo: AtomicU16,
    echo_received: Notify,
}

impl PeerConnLiveness {
    pub(super) fn new() -> Self {
        Self::default()
    }

    pub(super) fn set_enabled(&self, enabled: bool) {
        self.inner.enabled.store(enabled, Ordering::Release);
        if !enabled {
            self.inner.active_probe.store(0, Ordering::Release);
            self.inner.acknowledged_probe.store(0, Ordering::Release);
            self.inner.pending_echo.store(0, Ordering::Release);
        }
    }

    pub(super) fn set_remote_features(&self, features: &[String]) {
        self.set_enabled(features.iter().any(|feature| feature == FEATURE));
    }

    pub(super) fn start_probe(&self) -> Option<u8> {
        if !self.inner.enabled.load(Ordering::Acquire) {
            return None;
        }

        let active = self.inner.active_probe.load(Ordering::Acquire);
        if active != 0 {
            return Some(Self::decode_probe(active));
        }

        let token = self
            .inner
            .next_token
            .fetch_add(1, Ordering::Relaxed)
            .wrapping_add(1);
        self.inner.acknowledged_probe.store(0, Ordering::Release);
        self.inner
            .active_probe
            .store(Self::encode_probe(token), Ordering::Release);
        Some(token)
    }

    pub(super) async fn wait_for_echo(&self, token: u8) {
        let expected = Self::encode_probe(token);
        loop {
            let notified = self.inner.echo_received.notified();
            if self.inner.acknowledged_probe.load(Ordering::Acquire) == expected {
                return;
            }
            notified.await;
        }
    }

    pub(super) fn finish_probe(&self, token: u8) {
        let probe = Self::encode_probe(token);
        let _ =
            self.inner
                .active_probe
                .compare_exchange(probe, 0, Ordering::AcqRel, Ordering::Acquire);
        let _ = self.inner.acknowledged_probe.compare_exchange(
            probe,
            0,
            Ordering::AcqRel,
            Ordering::Acquire,
        );
    }

    fn encode_probe(token: u8) -> u16 {
        u16::from(token) + 1
    }

    fn decode_probe(probe: u16) -> u8 {
        (probe - 1) as u8
    }

    fn active_probe(&self) -> Option<u8> {
        let probe = self.inner.active_probe.load(Ordering::Acquire);
        (probe != 0).then(|| Self::decode_probe(probe))
    }

    fn queue_echo(&self, token: u8) {
        self.inner
            .pending_echo
            .store(Self::encode_probe(token), Ordering::Release);
    }

    fn take_echo(&self) -> Option<u8> {
        let echo = self.inner.pending_echo.swap(0, Ordering::AcqRel);
        (echo != 0).then(|| Self::decode_probe(echo))
    }

    fn acknowledge(&self, token: u8) {
        let probe = Self::encode_probe(token);
        if self
            .inner
            .active_probe
            .compare_exchange(probe, 0, Ordering::AcqRel, Ordering::Acquire)
            .is_ok()
        {
            self.inner
                .acknowledged_probe
                .store(probe, Ordering::Release);
            self.inner.echo_received.notify_one();
        }
    }
}

impl TunnelFilter for PeerConnLiveness {
    type FilterOutput = ();

    fn before_send(&self, mut data: SinkItem) -> Option<SinkItem> {
        if !self.inner.enabled.load(Ordering::Acquire) {
            return Some(data);
        }

        let Some(header) = data.mut_peer_manager_header() else {
            return Some(data);
        };
        header.clear_liveness_marker();
        if let Some(token) = self.take_echo() {
            header.set_liveness_echo(token);
        } else if let Some(token) = self.active_probe() {
            header.set_liveness_probe(token);
        }
        Some(data)
    }

    fn after_received(&self, data: StreamItem) -> Option<StreamItem> {
        let Ok(mut packet) = data else {
            return Some(data);
        };
        if !self.inner.enabled.load(Ordering::Acquire) {
            return Some(Ok(packet));
        }

        let Some(header) = packet.mut_peer_manager_header() else {
            return Some(Ok(packet));
        };
        let probe = header.liveness_probe_token();
        let echo = header.liveness_echo_token();
        header.clear_liveness_marker();

        match (probe, echo) {
            (Some(token), None) => self.queue_echo(token),
            (None, Some(token)) => self.acknowledge(token),
            _ => {}
        }
        Some(Ok(packet))
    }

    fn filter_output(&self) {}
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use crate::{
        packet::{PacketType, ZCPacket},
        tunnel::filter::TunnelFilter,
    };

    use super::{FEATURE, PeerConnLiveness};

    fn data_packet(from: u32, to: u32) -> ZCPacket {
        let mut packet = ZCPacket::new_with_payload(b"payload");
        packet.fill_peer_manager_hdr(from, to, PacketType::Data as u8);
        packet
    }

    #[tokio::test]
    async fn echoed_business_packet_proves_round_trip_liveness() {
        let local = PeerConnLiveness::new();
        let remote = PeerConnLiveness::new();
        local.set_enabled(true);
        remote.set_enabled(true);

        let token = local.start_probe().expect("feature enabled");
        let outbound = local.before_send(data_packet(1, 2)).unwrap();
        let received = remote.after_received(Ok(outbound)).unwrap().unwrap();
        assert_eq!(received.payload(), b"payload");
        let header = received.peer_manager_header().unwrap();
        assert_eq!(header.liveness_probe_token(), None);
        assert_eq!(header.liveness_echo_token(), None);

        let reply = remote.before_send(data_packet(2, 1)).unwrap();
        let received = local.after_received(Ok(reply)).unwrap().unwrap();
        assert_eq!(received.payload(), b"payload");
        let header = received.peer_manager_header().unwrap();
        assert_eq!(header.liveness_probe_token(), None);
        assert_eq!(header.liveness_echo_token(), None);

        tokio::time::timeout(Duration::from_millis(50), local.wait_for_echo(token))
            .await
            .expect("matching echo was not observed");
    }

    #[test]
    fn old_peer_without_feature_keeps_liveness_markers_disabled() {
        let liveness = PeerConnLiveness::new();
        liveness.set_remote_features(&[]);
        assert_eq!(liveness.start_probe(), None);

        liveness.set_remote_features(&[FEATURE.to_owned()]);
        assert!(liveness.start_probe().is_some());
    }

    #[tokio::test]
    async fn unrelated_ingress_does_not_acknowledge_an_active_probe() {
        let liveness = PeerConnLiveness::new();
        liveness.set_enabled(true);
        let token = liveness.start_probe().unwrap();

        for _ in 0..8 {
            liveness
                .after_received(Ok(data_packet(2, 1)))
                .unwrap()
                .unwrap();
        }

        assert!(
            tokio::time::timeout(Duration::from_millis(20), liveness.wait_for_echo(token))
                .await
                .is_err(),
            "unrelated one-way ingress acknowledged the local probe"
        );
    }

    #[tokio::test]
    async fn stale_echo_does_not_acknowledge_a_new_probe() {
        let liveness = PeerConnLiveness::new();
        liveness.set_enabled(true);

        let old_token = liveness.start_probe().unwrap();
        let mut old_echo = data_packet(2, 1);
        old_echo
            .mut_peer_manager_header()
            .unwrap()
            .set_liveness_echo(old_token);
        liveness.after_received(Ok(old_echo)).unwrap().unwrap();
        liveness.wait_for_echo(old_token).await;

        let new_token = liveness.start_probe().unwrap();
        assert_ne!(old_token, new_token);
        let mut stale_echo = data_packet(2, 1);
        stale_echo
            .mut_peer_manager_header()
            .unwrap()
            .set_liveness_echo(old_token);
        liveness.after_received(Ok(stale_echo)).unwrap().unwrap();

        assert!(
            tokio::time::timeout(Duration::from_millis(20), liveness.wait_for_echo(new_token))
                .await
                .is_err(),
            "stale echo acknowledged a newer probe"
        );
    }

    #[tokio::test]
    async fn simultaneous_probes_are_echoed_in_both_directions() {
        let left = PeerConnLiveness::new();
        let right = PeerConnLiveness::new();
        left.set_enabled(true);
        right.set_enabled(true);
        let left_token = left.start_probe().unwrap();
        let right_token = right.start_probe().unwrap();

        let left_probe = left.before_send(data_packet(1, 2)).unwrap();
        let right_probe = right.before_send(data_packet(2, 1)).unwrap();
        right.after_received(Ok(left_probe)).unwrap().unwrap();
        left.after_received(Ok(right_probe)).unwrap().unwrap();

        let left_echo = left.before_send(data_packet(1, 2)).unwrap();
        let right_echo = right.before_send(data_packet(2, 1)).unwrap();
        right.after_received(Ok(left_echo)).unwrap().unwrap();
        left.after_received(Ok(right_echo)).unwrap().unwrap();

        tokio::time::timeout(Duration::from_millis(50), left.wait_for_echo(left_token))
            .await
            .unwrap();
        tokio::time::timeout(Duration::from_millis(50), right.wait_for_echo(right_token))
            .await
            .unwrap();
    }
}
