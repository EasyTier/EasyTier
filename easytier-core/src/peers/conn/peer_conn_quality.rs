//! Connection health for flow migration, independent of the idle candidate RTT.

use std::{
    collections::VecDeque,
    sync::atomic::{AtomicBool, Ordering},
    time::{Duration, Instant},
};

use crossbeam_utils::atomic::AtomicCell;

pub(super) struct PeerConnQuality {
    latest: AtomicCell<Option<(Instant, u64)>>,
    degraded: AtomicBool,
    pub fast_ping: AtomicBool,
}

impl Default for PeerConnQuality {
    fn default() -> Self {
        Self {
            latest: AtomicCell::new(None),
            degraded: AtomicBool::new(false),
            fast_ping: AtomicBool::new(false),
        }
    }
}

impl PeerConnQuality {
    pub fn latency(&self) -> Option<u64> {
        self.latest
            .load()
            .and_then(|(time, rtt)| (time.elapsed() <= Duration::from_secs(5)).then_some(rtt))
    }

    pub fn is_degraded(&self) -> bool {
        self.degraded.load(Ordering::Relaxed)
    }
}

#[derive(Default)]
pub(super) struct QualityHistory {
    samples: VecDeque<(Instant, u64)>,
    baseline: Option<u64>,
    bad_samples: u32,
    recovery_samples: u32,
}

impl QualityHistory {
    pub fn record(&mut self, quality: &PeerConnQuality, rtt: Option<u64>, now: Instant) {
        let degraded = quality.is_degraded();
        // Freeze the reference from the first abnormal sample until recovery.
        // Otherwise a persistently slow path heals itself as old samples expire.
        if self.bad_samples == 0 && !degraded {
            while self
                .samples
                .front()
                .is_some_and(|(time, _)| now.duration_since(*time) > Duration::from_secs(60))
            {
                self.samples.pop_front();
            }
            self.baseline = self.samples.iter().map(|(_, rtt)| *rtt).min();
        }
        if let Some(rtt) = rtt {
            quality.latest.store(Some((now, rtt)));
        }
        let bad = rtt.is_none_or(|rtt| {
            self.baseline
                .is_some_and(|base| rtt > base.saturating_add(100_000.max(base.saturating_mul(2))))
        });
        if bad {
            self.recovery_samples = 0;
            self.bad_samples = self.bad_samples.saturating_add(1);
            if self.bad_samples >= 3 {
                if !degraded {
                    tracing::debug!(?rtt, baseline = ?self.baseline, "connection quality degraded");
                }
                quality.degraded.store(true, Ordering::Relaxed);
            }
            return;
        }
        if degraded {
            self.recovery_samples += 1;
            if self.recovery_samples < 3 {
                return;
            }
            quality.degraded.store(false, Ordering::Relaxed);
            tracing::debug!(?rtt, baseline = ?self.baseline, "connection quality recovered");
            self.samples.clear();
        }
        self.bad_samples = 0;
        self.recovery_samples = 0;
        if self.samples.len() >= 64 {
            self.samples.pop_front();
        }
        self.samples.push_back((now, rtt.unwrap()));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detects_sustained_degradation_without_aging_away_the_reference() {
        let quality = PeerConnQuality::default();
        let mut history = QualityHistory::default();
        let start = Instant::now();
        history.record(&quality, Some(15_000), start);
        history.record(&quality, Some(200_000), start + Duration::from_secs(59));
        assert!(!quality.is_degraded());
        history.record(&quality, Some(200_000), start + Duration::from_secs(60));
        history.record(&quality, Some(200_000), start + Duration::from_secs(61));
        assert!(quality.is_degraded());
        history.record(&quality, Some(200_000), start + Duration::from_secs(180));
        assert!(quality.is_degraded());
        for _ in 0..2 {
            history.record(&quality, Some(15_000), start + Duration::from_secs(181));
            assert!(quality.is_degraded());
        }
        history.record(&quality, Some(15_000), start + Duration::from_secs(181));
        assert!(!quality.is_degraded());
    }

    #[test]
    fn noise_and_isolated_failure_do_not_trigger_migration() {
        let quality = PeerConnQuality::default();
        let mut history = QualityHistory::default();
        let now = Instant::now();
        for rtt in [
            Some(15_000),
            Some(20_000),
            None,
            Some(18_000),
            Some(200_000),
            Some(15_000),
        ] {
            history.record(&quality, rtt, now);
            assert!(!quality.is_degraded());
        }
    }

    #[test]
    fn quality_failure_does_not_refresh_a_successful_rtt() {
        let quality = PeerConnQuality::default();
        let mut history = QualityHistory::default();
        let old = Instant::now() - Duration::from_secs(10);
        history.record(&quality, Some(15_000), old);
        assert!(quality.latency().is_none());
        for _ in 0..3 {
            history.record(&quality, None, Instant::now());
        }
        assert!(quality.is_degraded());
        assert!(quality.latency().is_none());
        assert_eq!(quality.latest.load(), Some((old, 15_000)));
    }
}
