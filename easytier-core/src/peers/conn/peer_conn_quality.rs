//! Probe observations and connection-local degradation for flow migration.

use std::{
    collections::VecDeque,
    sync::atomic::AtomicBool,
    time::{Duration, Instant},
};

use crossbeam_utils::atomic::AtomicCell;

pub(super) struct PeerConnQuality {
    snapshot: AtomicCell<QualitySnapshot>,
    pub fast_ping: AtomicBool,
}

impl Default for PeerConnQuality {
    fn default() -> Self {
        Self {
            snapshot: AtomicCell::new(QualitySnapshot::default()),
            fast_ping: AtomicBool::new(false),
        }
    }
}

impl PeerConnQuality {
    pub fn snapshot(&self) -> QualitySnapshot {
        self.snapshot.load()
    }

    pub fn is_degraded(&self) -> bool {
        self.snapshot().degraded
    }
}

#[derive(Clone, Copy, Debug)]
struct ProbeSample {
    started: Instant,
    completed: Instant,
    rtt: Option<u64>,
}

#[derive(Clone, Copy, Debug, Default)]
pub(super) struct QualitySnapshot {
    samples: [Option<ProbeSample>; 3],
    pub degraded: bool,
}

impl QualitySnapshot {
    pub fn latency(&self, now: Instant) -> Option<u64> {
        let mut values = [u64::MAX; 3];
        let mut count = 0;
        for sample in self.samples.iter().flatten() {
            if now.saturating_duration_since(sample.completed) <= Duration::from_secs(5)
                && let Some(rtt) = sample.rtt
            {
                values[count] = rtt;
                count += 1;
            }
        }
        values.sort_unstable();
        (count > 0).then(|| values[count / 2])
    }

    pub fn missing_probes(&self) -> usize {
        self.samples
            .iter()
            .flatten()
            .filter(|s| s.rtt.is_none())
            .count()
    }

    pub fn last_probe_started(&self) -> Option<Instant> {
        self.samples[2].map(|sample| sample.started)
    }

    pub fn is_recent(&self, now: Instant) -> bool {
        self.samples[2].is_some_and(|sample| {
            now.saturating_duration_since(sample.completed) <= Duration::from_secs(5)
        })
    }

    pub fn window(&self, now: Instant) -> Option<(Instant, Instant)> {
        let first = self.samples[0]?;
        let last = self.samples[2]?;
        (self.is_recent(now)
            && now.saturating_duration_since(first.started) <= Duration::from_secs(10))
        .then_some((first.started, last.completed))
    }

    pub fn stable_latency(&self, now: Instant) -> Option<u64> {
        self.window(now)?;
        let mut values = [0; 3];
        for (value, sample) in values.iter_mut().zip(self.samples) {
            *value = sample?.rtt?;
        }
        values.sort_unstable();
        // Stability is a property of recent observations, not of the path's
        // unloaded baseline. A successfully loaded path can remain degraded.
        (values[2] - values[0] <= 10_000.max(values[1] / 4)).then_some(values[2])
    }

    pub fn improves(&self, before: Option<u64>, now: Instant) -> bool {
        self.stable_latency(now).is_some_and(|worst| {
            // None represents three missing Pongs on the original path. Three
            // successful loaded probes then demonstrate restored measurements.
            before.is_none_or(|rtt| worst.saturating_add(10_000.max(rtt / 5)) < rtt)
        })
    }
}

#[derive(Default)]
pub(super) struct QualityHistory {
    samples: VecDeque<(Instant, u64)>,
    baseline: Option<u64>,
    bad_samples: u32,
    recovery_samples: u32,
    recent: [Option<ProbeSample>; 3],
}

impl QualityHistory {
    pub fn record(
        &mut self,
        quality: &PeerConnQuality,
        rtt: Option<u64>,
        started: Instant,
        now: Instant,
    ) {
        let degraded = quality.is_degraded();
        let mut next_degraded = degraded;
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
                next_degraded = true;
            }
        } else if degraded {
            self.recovery_samples += 1;
            if self.recovery_samples >= 3 {
                next_degraded = false;
                tracing::debug!(?rtt, baseline = ?self.baseline, "connection quality recovered");
                self.samples.clear();
            }
        }
        if !bad && !next_degraded {
            self.bad_samples = 0;
            self.recovery_samples = 0;
            if self.samples.len() >= 64 {
                self.samples.pop_front();
            }
            self.samples.push_back((now, rtt.unwrap()));
        }
        self.recent.rotate_left(1);
        self.recent[2] = Some(ProbeSample {
            started,
            completed: now,
            rtt,
        });
        quality.snapshot.store(QualitySnapshot {
            samples: self.recent,
            degraded: next_degraded,
        });
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
        history.record(&quality, Some(15_000), start, start);
        history.record(
            &quality,
            Some(200_000),
            start + Duration::from_secs(59),
            start + Duration::from_secs(59),
        );
        assert!(!quality.is_degraded());
        history.record(
            &quality,
            Some(200_000),
            start + Duration::from_secs(60),
            start + Duration::from_secs(60),
        );
        history.record(
            &quality,
            Some(200_000),
            start + Duration::from_secs(61),
            start + Duration::from_secs(61),
        );
        assert!(quality.is_degraded());
        history.record(
            &quality,
            Some(200_000),
            start + Duration::from_secs(180),
            start + Duration::from_secs(180),
        );
        assert!(quality.is_degraded());
        for _ in 0..2 {
            history.record(
                &quality,
                Some(15_000),
                start + Duration::from_secs(181),
                start + Duration::from_secs(181),
            );
            assert!(quality.is_degraded());
        }
        history.record(
            &quality,
            Some(15_000),
            start + Duration::from_secs(181),
            start + Duration::from_secs(181),
        );
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
            history.record(&quality, rtt, now, now);
            assert!(!quality.is_degraded());
        }
    }

    #[test]
    fn quality_failure_does_not_refresh_a_successful_rtt() {
        let quality = PeerConnQuality::default();
        let mut history = QualityHistory::default();
        let old = Instant::now() - Duration::from_secs(10);
        history.record(&quality, Some(15_000), old, old);
        assert!(quality.snapshot().latency(Instant::now()).is_none());
        for _ in 0..3 {
            history.record(&quality, None, Instant::now(), Instant::now());
        }
        assert!(quality.is_degraded());
        assert!(quality.snapshot().latency(Instant::now()).is_none());
        assert_eq!(quality.snapshot().missing_probes(), 3);
    }

    #[test]
    fn candidate_stability_requires_a_complete_fresh_window_without_outliers() {
        let quality = PeerConnQuality::default();
        let mut history = QualityHistory::default();
        let start = Instant::now();
        for second in 1..=2 {
            let now = start + Duration::from_secs(second);
            history.record(&quality, Some(20_000), now, now);
            assert!(quality.snapshot().stable_latency(now).is_none());
        }
        let now = start + Duration::from_secs(3);
        history.record(&quality, Some(80_000), now, now);
        assert_eq!(quality.snapshot().latency(now), Some(20_000));
        assert!(quality.snapshot().stable_latency(now).is_none());
        for second in 4..=6 {
            let now = start + Duration::from_secs(second);
            history.record(&quality, Some(20_000), now, now);
        }
        assert_eq!(
            quality
                .snapshot()
                .stable_latency(start + Duration::from_secs(6)),
            Some(20_000)
        );
        assert!(
            quality
                .snapshot()
                .stable_latency(start + Duration::from_secs(12))
                .is_none()
        );
    }
}
