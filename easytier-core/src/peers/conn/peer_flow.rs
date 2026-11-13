//! Bounded flow bindings retained until idle or their connection closes.

use std::{
    collections::{HashMap, hash_map::RandomState},
    hash::BuildHasher,
    time::{Duration, Instant},
};

use crate::packet::FlowKey;

use super::peer_conn::PeerConnId;

pub(super) struct FlowBinding {
    pub conn_id: PeerConnId,
    pub last_active: Instant,
}

#[derive(Default)]
pub(super) struct FlowBindings {
    hash: RandomState,
    pub buckets: HashMap<usize, FlowBinding>,
}

impl FlowBindings {
    pub const BUCKETS: usize = 4096;
    pub const IDLE_TIMEOUT: Duration = Duration::from_secs(120);

    pub fn bucket(&self, key: FlowKey) -> usize {
        self.hash.hash_one(key) as usize % Self::BUCKETS
    }

    pub fn bind(&mut self, bucket: usize, conn_id: PeerConnId, now: Instant) {
        self.buckets.insert(
            bucket,
            FlowBinding {
                conn_id,
                last_active: now,
            },
        );
    }
}
