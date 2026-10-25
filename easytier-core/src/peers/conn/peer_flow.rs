//! Bounded flow bindings and one load-observed migration at a time per peer.

use std::{
    collections::{HashMap, hash_map::RandomState},
    hash::BuildHasher,
    time::{Duration, Instant},
};

use crate::packet::FlowKey;

use super::{peer_conn::PeerConnId, peer_conn_quality::QualitySnapshot};

const COOLDOWN: Duration = Duration::from_secs(30);
const OBSERVATION_TIMEOUT: Duration = Duration::from_secs(15);
const SETTLE_TIME: Duration = Duration::from_secs(3);
const MAX_BACKOFF: Duration = Duration::from_secs(300);

#[derive(Clone, Copy)]
struct TrafficSample {
    start: Instant,
    end: Instant,
    bytes: u64,
}

impl TrafficSample {
    fn rate(&self) -> u64 {
        (u128::from(self.bytes) * 1_000_000_000
            / self.end.duration_since(self.start).as_nanos().max(1))
        .min(u128::from(u64::MAX)) as u64
    }
}

pub(super) struct FlowBinding {
    pub conn_id: PeerConnId,
    pub last_active: Instant,
    pub generation: u64,
    last_migrated: Option<Instant>,
    pending_bytes: u64,
    recent: [Option<TrafficSample>; 3],
}

impl FlowBinding {
    fn rate(&self) -> Option<u64> {
        let mut total = 0u64;
        for sample in self.recent {
            let sample = sample?;
            if sample.bytes == 0 {
                return None;
            }
            total = total.saturating_add(sample.rate());
        }
        Some(total / 3)
    }

    fn observed_load(
        &self,
        trial: &FlowMigration,
        quality: &QualitySnapshot,
        now: Instant,
    ) -> bool {
        let Some(first_sent) = trial.first_sent else {
            return false;
        };
        let Some((start, end)) = quality.window(now) else {
            return false;
        };
        if start < first_sent || self.last_active < quality.last_probe_started().unwrap() {
            return false;
        }
        // Only complete traffic intervals inside the actual probe window count.
        // A burst before these probes followed by idle Pongs is not load evidence.
        let mut observed = false;
        for sample in self.recent.iter().flatten() {
            if sample.start >= start && sample.end <= end {
                if sample.bytes == 0 || sample.rate() < trial.before_rate / 2 {
                    return false;
                }
                observed = true;
            }
        }
        observed
    }
}

struct FlowMigration {
    bucket: usize,
    generation: u64,
    source: PeerConnId,
    target: PeerConnId,
    before_rtt: Option<u64>,
    before_rate: u64,
    started: Instant,
    first_sent: Option<Instant>,
}

struct MigrationRetry {
    delay: Duration,
    after: Instant,
}

#[derive(Default)]
pub(super) struct FlowBindings {
    hash: RandomState,
    pub buckets: HashMap<usize, FlowBinding>,
    generation: u64,
    last_update: Option<Instant>,
    migration: Option<FlowMigration>,
    next_migration: Option<Instant>,
    retries: HashMap<(PeerConnId, PeerConnId), MigrationRetry>,
}

impl FlowBindings {
    pub const BUCKETS: usize = 4096;
    pub const IDLE_TIMEOUT: Duration = Duration::from_secs(120);

    pub fn bucket(&self, key: FlowKey) -> usize {
        self.hash.hash_one(key) as usize % Self::BUCKETS
    }

    pub fn bind(&mut self, bucket: usize, conn_id: PeerConnId, now: Instant) -> u64 {
        self.generation = self.generation.wrapping_add(1);
        self.buckets.insert(
            bucket,
            FlowBinding {
                conn_id,
                last_active: now,
                generation: self.generation,
                last_migrated: None,
                pending_bytes: 0,
                recent: [None; 3],
            },
        );
        self.generation
    }

    pub fn record_packet(
        &mut self,
        key: FlowKey,
        conn_id: PeerConnId,
        generation: u64,
        bytes: usize,
        now: Instant,
    ) {
        let bucket = self.bucket(key);
        let Some(binding) = self.buckets.get_mut(&bucket) else {
            return;
        };
        if binding.conn_id != conn_id || binding.generation != generation {
            return;
        }
        binding.last_active = now;
        binding.pending_bytes = binding.pending_bytes.saturating_add(bytes as u64);
        if let Some(trial) = self.migration.as_mut()
            && trial.bucket == bucket
            && trial.generation == generation
        {
            trial.first_sent.get_or_insert(now);
        }
    }

    fn move_binding(&mut self, bucket: usize, conn_id: PeerConnId, now: Instant) -> u64 {
        self.generation = self.generation.wrapping_add(1);
        let binding = self.buckets.get_mut(&bucket).unwrap();
        binding.conn_id = conn_id;
        binding.generation = self.generation;
        binding.last_migrated = Some(now);
        binding.pending_bytes = 0;
        binding.recent = [None; 3];
        self.generation
    }

    fn finish(&mut self, trial: FlowMigration, success: bool, now: Instant) {
        let direction = (trial.source, trial.target);
        if success {
            self.retries.remove(&direction);
        } else {
            let delay = self
                .retries
                .get(&direction)
                .map_or(COOLDOWN, |retry| (retry.delay * 2).min(MAX_BACKOFF));
            self.retries.insert(
                direction,
                MigrationRetry {
                    delay,
                    after: now + delay,
                },
            );
        }
        self.next_migration = Some(now + if success { SETTLE_TIME } else { COOLDOWN });
        tracing::debug!(source = ?trial.source, target = ?trial.target, bucket = trial.bucket,
            success, "flow migration observation finished");
    }

    // The caller snapshots live connections before locking flow bindings. No
    // ConnMap guard or connection-selection lock is held by this controller.
    pub fn update(&mut self, connections: &HashMap<PeerConnId, QualitySnapshot>, now: Instant) {
        let start = self
            .last_update
            .replace(now)
            .unwrap_or(now - Duration::from_secs(1));
        for binding in self.buckets.values_mut() {
            if now.duration_since(start) > Duration::from_secs(2) {
                binding.recent = [None; 3];
            }
            binding.recent.rotate_left(1);
            binding.recent[2] = Some(TrafficSample {
                start,
                end: now,
                bytes: std::mem::take(&mut binding.pending_bytes),
            });
        }
        self.retries.retain(|(source, target), retry| {
            connections.contains_key(source)
                && connections.contains_key(target)
                && now.saturating_duration_since(retry.after) < MAX_BACKOFF
        });

        if let Some(trial) = self.migration.take() {
            let binding = self.buckets.get(&trial.bucket).unwrap();
            if binding.generation != trial.generation || !connections.contains_key(&trial.target) {
                // A hard failover or a new binding supersedes this observation.
                self.finish(trial, false, now);
                return;
            }
            let target = &connections[&trial.target];
            let loaded = binding.observed_load(&trial, target, now);
            if loaded && target.improves(trial.before_rtt, now) {
                self.finish(trial, true, now);
                return;
            }
            let observed = loaded && target.window(now).is_some();
            if observed || now.duration_since(trial.started) >= OBSERVATION_TIMEOUT {
                // Roll back only an observed regression against the original
                // loaded path. An idle source RTT alone cannot justify a return.
                let regressed = trial.before_rtt.is_some_and(|before| {
                    target.missing_probes() > 0
                        || target
                            .latency(now)
                            .is_some_and(|rtt| rtt > before.saturating_add(10_000.max(before / 5)))
                });
                if observed
                    && regressed
                    && let Some(source) = connections.get(&trial.source)
                    && let Some(rtt) = source.stable_latency(now)
                    && rtt
                        <= trial
                            .before_rtt
                            .unwrap()
                            .saturating_add(10_000.max(trial.before_rtt.unwrap() / 5))
                {
                    self.move_binding(trial.bucket, trial.source, now);
                }
                self.finish(trial, false, now);
                return;
            }
            self.migration = Some(trial);
            return;
        }

        if self.next_migration.is_some_and(|after| now < after) {
            return;
        }
        let candidate = self
            .buckets
            .iter()
            .filter_map(|(bucket, binding)| {
                if now.duration_since(binding.last_active) > Duration::from_secs(2)
                    || binding
                        .last_migrated
                        .is_some_and(|at| now.duration_since(at) < COOLDOWN)
                {
                    return None;
                }
                let before_rate = binding.rate()?;
                let source = connections.get(&binding.conn_id)?;
                // Slow queued probes can span more than the candidate's window.
                // Their fresh results must still allow escaping a degraded path.
                if !source.degraded || !source.is_recent(now) {
                    return None;
                }
                let before_rtt = source.latency(now);
                if before_rtt.is_none() && source.missing_probes() != 3 {
                    return None;
                }
                let (target, _) = connections
                    .iter()
                    .filter(|(id, quality)| {
                        **id != binding.conn_id
                            && self
                                .retries
                                .get(&(binding.conn_id, **id))
                                .is_none_or(|r| now >= r.after)
                            && quality.improves(before_rtt, now)
                    })
                    .min_by_key(|(_, quality)| quality.stable_latency(now))?;
                Some((*bucket, binding.conn_id, *target, before_rtt, before_rate))
            })
            .min_by_key(|(_, _, _, _, rate)| *rate);

        if let Some((bucket, source, target, before_rtt, before_rate)) = candidate {
            let generation = self.move_binding(bucket, target, now);
            self.migration = Some(FlowMigration {
                bucket,
                generation,
                source,
                target,
                before_rtt,
                before_rate,
                started: now,
                first_sent: None,
            });
            tracing::debug!(
                ?source,
                ?target,
                bucket,
                before_rate,
                "start flow migration observation"
            );
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::peers::conn::peer_conn_quality::{PeerConnQuality, QualityHistory};

    fn flow(port: u16) -> FlowKey {
        FlowKey {
            src: ([10, 0, 0, 1], port).into(),
            dst: ([10, 0, 0, 2], 5000).into(),
            protocol: 17,
        }
    }

    struct TestPeer {
        flows: FlowBindings,
        source: PeerConnId,
        target: PeerConnId,
        source_quality: PeerConnQuality,
        target_quality: PeerConnQuality,
        source_history: QualityHistory,
        target_history: QualityHistory,
        now: Instant,
    }

    impl TestPeer {
        fn new() -> Self {
            let now = Instant::now();
            let source_quality = PeerConnQuality::default();
            let mut source_history = QualityHistory::default();
            source_history.record(&source_quality, Some(10_000), now, now);
            Self {
                flows: FlowBindings::default(),
                source: PeerConnId::new_v4(),
                target: PeerConnId::new_v4(),
                source_quality,
                target_quality: PeerConnQuality::default(),
                source_history,
                target_history: QualityHistory::default(),
                now,
            }
        }

        fn add_flow(&mut self, port: u16) -> FlowKey {
            let key = (port..u16::MAX)
                .map(flow)
                .find(|key| !self.flows.buckets.contains_key(&self.flows.bucket(*key)))
                .unwrap();
            self.flows
                .bind(self.flows.bucket(key), self.source, self.now);
            key
        }

        fn connection(&self, key: FlowKey) -> PeerConnId {
            self.flows.buckets[&self.flows.bucket(key)].conn_id
        }

        fn connections(&self) -> HashMap<PeerConnId, QualitySnapshot> {
            HashMap::from([
                (self.source, self.source_quality.snapshot()),
                (self.target, self.target_quality.snapshot()),
            ])
        }

        fn tick(&mut self, source: Option<u64>, target: Option<u64>, traffic: &[(FlowKey, usize)]) {
            let start = self.now;
            self.now += Duration::from_secs(1);
            for (key, bytes) in traffic {
                let binding = &self.flows.buckets[&self.flows.bucket(*key)];
                let (id, generation) = (binding.conn_id, binding.generation);
                // Two accepted writes represent business spanning the probe.
                for offset in [100, 950] {
                    self.flows.record_packet(
                        *key,
                        id,
                        generation,
                        bytes / 2,
                        start + Duration::from_millis(offset),
                    );
                }
            }
            let probe_start = start + Duration::from_millis(200);
            let probe_end = start + Duration::from_millis(900);
            self.source_history
                .record(&self.source_quality, source, probe_start, probe_end);
            self.target_history
                .record(&self.target_quality, target, probe_start, probe_end);
            self.flows.update(&self.connections(), self.now);
        }
    }

    #[test]
    fn a_degraded_150ms_path_does_not_move_to_a_stable_200ms_path() {
        let mut peer = TestPeer::new();
        let key = peer.add_flow(1234);
        for _ in 0..10 {
            peer.tick(Some(150_000), Some(200_000), &[(key, 10_000)]);
        }
        assert!(peer.source_quality.is_degraded());
        assert!(!peer.target_quality.is_degraded());
        assert_eq!(peer.connection(key), peer.source);
        assert!(peer.flows.migration.is_none());
    }

    #[test]
    fn slow_queued_probes_do_not_prevent_leaving_a_degraded_source() {
        for rtt in [Some(4_000_000), None] {
            for age in [0, 6] {
                let mut peer = TestPeer::new();
                let key = peer.add_flow(1234);
                let last = peer.now - Duration::from_secs(age);
                let mut history = QualityHistory::default();
                let baseline = last - Duration::from_secs(20);
                history.record(&peer.source_quality, Some(10_000), baseline, baseline);
                for offset in [8, 4, 0] {
                    let completed = last - Duration::from_secs(offset);
                    history.record(
                        &peer.source_quality,
                        rtt,
                        completed - Duration::from_secs(4),
                        completed,
                    );
                }
                assert!(peer.source_quality.is_degraded());
                for _ in 0..3 {
                    let start = peer.now;
                    peer.now += Duration::from_secs(1);
                    let generation = peer.flows.buckets[&peer.flows.bucket(key)].generation;
                    peer.flows
                        .record_packet(key, peer.source, generation, 10_000, peer.now);
                    peer.target_history
                        .record(&peer.target_quality, Some(20_000), start, peer.now);
                    peer.flows.update(&peer.connections(), peer.now);
                }
                assert_eq!(
                    peer.connection(key),
                    if age == 0 { peer.target } else { peer.source }
                );
            }
        }
    }

    #[test]
    fn missing_or_unstable_probes_disqualify_a_candidate_until_three_stable_samples() {
        for bad in [None, Some(120_000)] {
            let mut peer = TestPeer::new();
            let key = peer.add_flow(1234);
            peer.tick(Some(500_000), Some(20_000), &[(key, 10_000)]);
            peer.tick(Some(500_000), bad, &[(key, 10_000)]);
            peer.tick(Some(500_000), bad, &[(key, 10_000)]);
            assert_eq!(peer.connection(key), peer.source);
            for _ in 0..2 {
                peer.tick(Some(500_000), Some(20_000), &[(key, 10_000)]);
                assert_eq!(peer.connection(key), peer.source);
            }
            peer.tick(Some(500_000), Some(20_000), &[(key, 10_000)]);
            assert_eq!(peer.connection(key), peer.target);
        }
    }

    #[test]
    fn migration_requires_three_new_probes_while_the_bucket_is_carrying_load() {
        let mut peer = TestPeer::new();
        let key = peer.add_flow(1234);
        for _ in 0..3 {
            peer.tick(Some(500_000), Some(20_000), &[(key, 10_000)]);
        }
        assert_eq!(peer.connection(key), peer.target);
        assert!(peer.flows.migration.is_some());
        for _ in 0..2 {
            peer.tick(Some(20_000), Some(100_000), &[(key, 10_000)]);
            assert!(peer.flows.migration.is_some());
        }
        peer.tick(Some(20_000), Some(100_000), &[(key, 10_000)]);
        assert!(peer.flows.migration.is_none());
        assert!(peer.flows.retries.is_empty());
        assert_eq!(peer.connection(key), peer.target);
    }

    #[test]
    fn a_burst_followed_by_idle_pongs_does_not_validate_the_trial() {
        let mut peer = TestPeer::new();
        let key = peer.add_flow(1234);
        for _ in 0..3 {
            peer.tick(Some(500_000), Some(20_000), &[(key, 10_000_000)]);
        }
        peer.tick(Some(20_000), Some(20_000), &[(key, 15_000_000)]);
        for _ in 0..3 {
            peer.tick(Some(20_000), Some(20_000), &[]);
        }
        assert!(peer.flows.migration.is_some());
        for _ in 0..11 {
            peer.tick(Some(20_000), Some(20_000), &[]);
        }
        assert!(peer.flows.migration.is_none());
        assert!(!peer.flows.retries.is_empty());
        // An unverified trial is not evidence that the idle source is better.
        assert_eq!(peer.connection(key), peer.target);
    }

    #[test]
    fn insufficient_offered_load_does_not_validate_a_faster_target() {
        let mut peer = TestPeer::new();
        let key = peer.add_flow(1234);
        for _ in 0..3 {
            peer.tick(Some(500_000), Some(20_000), &[(key, 10_000)]);
        }
        for _ in 0..4 {
            peer.tick(Some(20_000), Some(20_000), &[(key, 100)]);
        }
        assert!(peer.flows.migration.is_some());
    }

    #[test]
    fn progressive_migration_starts_with_smallest_bucket_and_stops_on_overload() {
        let mut peer = TestPeer::new();
        let small = peer.add_flow(1234);
        let large = peer.add_flow(1235);
        let traffic = [(small, 1000), (large, 100_000)];
        for _ in 0..3 {
            peer.tick(Some(500_000), Some(10_000), &traffic);
        }
        assert_eq!(peer.connection(small), peer.target);
        assert_eq!(peer.connection(large), peer.source);
        for _ in 0..3 {
            peer.tick(Some(500_000), Some(150_000), &traffic);
        }
        assert!(peer.flows.migration.is_none());
        assert!(peer.target_quality.is_degraded());
        for _ in 0..2 {
            peer.tick(Some(500_000), Some(150_000), &traffic);
            assert_eq!(peer.connection(large), peer.source);
        }
        peer.tick(Some(500_000), Some(150_000), &traffic);
        // A loaded target may still be better despite its own baseline alarm.
        assert_eq!(peer.connection(large), peer.target);
        for _ in 0..3 {
            peer.tick(Some(20_000), Some(700_000), &traffic);
        }
        assert_eq!(peer.connection(small), peer.target);
        assert_eq!(peer.connection(large), peer.source);
        assert!(peer.flows.migration.is_none());
        assert!(!peer.flows.retries.is_empty());
    }

    #[test]
    fn failed_single_flow_trials_roll_back_and_back_off_repeated_attempts() {
        let mut peer = TestPeer::new();
        let key = peer.add_flow(1234);
        for _ in 0..3 {
            peer.tick(Some(150_000), Some(20_000), &[(key, 10_000)]);
        }
        for _ in 0..3 {
            peer.tick(Some(10_000), Some(200_000), &[(key, 10_000)]);
        }
        assert_eq!(peer.connection(key), peer.source);
        for _ in 0..29 {
            peer.tick(Some(150_000), Some(20_000), &[(key, 10_000)]);
            assert_eq!(peer.connection(key), peer.source);
        }
        peer.tick(Some(150_000), Some(20_000), &[(key, 10_000)]);
        assert_eq!(peer.connection(key), peer.target);
        for _ in 0..3 {
            peer.tick(Some(10_000), Some(200_000), &[(key, 10_000)]);
        }
        assert_eq!(peer.connection(key), peer.source);
        for _ in 0..59 {
            peer.tick(Some(150_000), Some(20_000), &[(key, 10_000)]);
            assert_eq!(peer.connection(key), peer.source);
        }
        peer.tick(Some(150_000), Some(20_000), &[(key, 10_000)]);
        assert_eq!(peer.connection(key), peer.target);
    }

    #[test]
    fn a_loaded_target_can_restore_measurements_when_the_source_has_no_pongs() {
        let mut peer = TestPeer::new();
        let key = peer.add_flow(1234);
        for _ in 0..3 {
            peer.tick(None, Some(20_000), &[(key, 10_000)]);
        }
        assert_eq!(peer.connection(key), peer.target);
        for _ in 0..3 {
            peer.tick(None, Some(100_000), &[(key, 10_000)]);
        }
        assert!(peer.flows.migration.is_none());
        assert!(peer.flows.retries.is_empty());
    }

    #[test]
    fn late_enqueue_completions_and_hard_failover_cannot_change_a_new_binding() {
        let mut peer = TestPeer::new();
        let key = peer.add_flow(1234);
        let bucket = peer.flows.bucket(key);
        let old_generation = peer.flows.buckets[&bucket].generation;
        for _ in 0..3 {
            peer.tick(Some(500_000), Some(20_000), &[(key, 10_000)]);
        }
        peer.flows
            .record_packet(key, peer.source, old_generation, 100_000, peer.now);
        assert!(peer.flows.migration.as_ref().unwrap().first_sent.is_none());
        let trial_generation = peer.flows.buckets[&bucket].generation;
        peer.flows.bind(bucket, peer.source, peer.now);
        peer.flows
            .record_packet(key, peer.target, trial_generation, 100_000, peer.now);
        let mut connections = peer.connections();
        connections.remove(&peer.target);
        peer.now += Duration::from_secs(1);
        peer.flows.update(&connections, peer.now);
        assert_eq!(peer.connection(key), peer.source);
        assert!(peer.flows.migration.is_none());
        assert_eq!(peer.flows.buckets[&bucket].recent[2].unwrap().bytes, 0);
    }

    #[test]
    fn a_closed_source_cannot_receive_a_rollback() {
        let mut peer = TestPeer::new();
        let key = peer.add_flow(1234);
        for _ in 0..3 {
            peer.tick(Some(150_000), Some(20_000), &[(key, 10_000)]);
        }
        for _ in 0..2 {
            peer.tick(None, Some(200_000), &[(key, 10_000)]);
        }
        // The last loaded target sample completes after the source disappears.
        let start = peer.now;
        peer.now += Duration::from_secs(1);
        let bucket = peer.flows.bucket(key);
        let generation = peer.flows.buckets[&bucket].generation;
        peer.flows
            .record_packet(key, peer.target, generation, 10_000, peer.now);
        peer.target_history
            .record(&peer.target_quality, Some(200_000), start, peer.now);
        peer.flows.update(
            &HashMap::from([(peer.target, peer.target_quality.snapshot())]),
            peer.now,
        );
        assert_eq!(peer.connection(key), peer.target);
        assert!(peer.flows.migration.is_none());
    }
}
