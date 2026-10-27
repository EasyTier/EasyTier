use crate::{
    foundation::time::{Duration, Instant},
    packet::ZCPacket,
};

use super::wire::{self, Fragment, Header};

const TRACKED: usize = 256;
const REORDER: u64 = 32;
const INTERVAL: Duration = Duration::from_millis(200);

/// Cumulative arrival measurements, not an authenticated command or an ACK.
#[derive(Clone, Copy, Debug, Default)]
pub(super) struct Report {
    pub highest: u64,
    pub samples: u64,
    pub lost: u64,
}

impl Report {
    pub fn decode(fragment: &Fragment<'_>) -> Option<Self> {
        if fragment.header.kind != wire::FEEDBACK {
            return None;
        }
        let report = Self {
            highest: fragment.header.sequence,
            samples: fragment.header.source,
            lost: u64::from_le_bytes(fragment.payload.try_into().ok()?),
        };
        (report.samples > 0
            && report.samples <= report.highest + 1
            && report.lost <= report.samples)
            .then_some(report)
    }

    pub fn encode(self) -> ZCPacket {
        wire::encode(
            Header {
                kind: wire::FEEDBACK,
                sequence: self.highest,
                source: self.samples,
                repair: 0,
                count: 0,
            },
            &self.lost.to_le_bytes(),
        )
    }
}

pub(super) struct LossEstimator {
    arrived: [Option<u64>; TRACKED],
    next: u64,
    report: Report,
    due: Option<Instant>,
}

impl Default for LossEstimator {
    fn default() -> Self {
        Self {
            arrived: [None; TRACKED],
            next: 0,
            report: Report::default(),
            due: None,
        }
    }
}

impl LossEstimator {
    /// Observe valid wire frames before any local cache/decoder admission.
    pub fn observe(&mut self, sequence: u64, now: Instant) {
        if sequence < self.next {
            return;
        }
        let before = self.report.samples;
        // Settle overwritten ring entries before replacing their arrival marks.
        self.settle_until(sequence.saturating_sub((TRACKED - 1) as u64));
        self.arrived[sequence as usize % TRACKED] = Some(sequence);
        self.report.highest = self.report.highest.max(sequence);
        self.settle_until(self.report.highest.saturating_sub(REORDER - 1));
        if self.report.samples != before && self.due.is_none() {
            self.due = Some(now + INTERVAL);
        }
    }

    fn settle_until(&mut self, end: u64) {
        if end <= self.next {
            return;
        }
        // Large jumps take bounded work and cannot force a walk over wire IDs.
        if end - self.next > TRACKED as u64 {
            let skip_to = end - TRACKED as u64;
            let received = self
                .arrived
                .iter()
                .flatten()
                .filter(|&&seq| seq >= self.next && seq < skip_to)
                .count() as u64;
            let count = skip_to - self.next;
            self.report.samples += count;
            self.report.lost += count - received;
            self.next = skip_to;
        }
        while self.next < end {
            let slot = self.next as usize % TRACKED;
            self.report.samples += 1;
            self.report.lost += u64::from(self.arrived[slot] != Some(self.next));
            self.arrived[slot] = None;
            self.next += 1;
        }
    }

    pub fn deadline(&self) -> Option<Instant> {
        self.due
    }

    pub fn take_report(&mut self, now: Instant) -> Option<Report> {
        if self.due.is_none_or(|due| now < due) {
            return None;
        }
        self.due = None;
        Some(self.report)
    }

    pub fn snapshot(&self) -> Report {
        self.report
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reordering_and_duplicates_do_not_inflate_loss() {
        let now = Instant::now();
        let mut estimator = LossEstimator::default();
        for base in (0..256).step_by(8) {
            for seq in (base..base + 8).rev() {
                estimator.observe(seq, now);
                estimator.observe(seq, now);
            }
        }
        let report = estimator.take_report(now + INTERVAL).unwrap();
        assert_eq!(report.samples, 224);
        assert_eq!(report.lost, 0);
        assert!(estimator.take_report(now + INTERVAL).is_none());
    }

    #[test]
    fn reports_are_cumulative_and_large_jumps_are_bounded() {
        let now = Instant::now();
        let mut estimator = LossEstimator::default();
        for seq in 0..200 {
            if seq % 10 != 0 {
                estimator.observe(seq, now);
            }
        }
        let first = estimator.take_report(now + INTERVAL).unwrap();
        assert_eq!((first.samples, first.lost), (168, 17));
        estimator.observe(1_000_000, now + INTERVAL);
        let second = estimator.take_report(now + INTERVAL * 2).unwrap();
        assert_eq!(second.samples, 999_969);
        assert_eq!(second.lost, second.samples - 180);
        estimator.observe(1, now + INTERVAL * 2);
        assert!(estimator.deadline().is_none());
    }
}
