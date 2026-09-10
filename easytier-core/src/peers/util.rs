use std::hash::Hash;

use dashmap::DashMap;

pub(crate) fn shrink_dashmap<K: Eq + Hash, V>(map: &DashMap<K, V>, threshold: Option<usize>) {
    let threshold = threshold.unwrap_or(16);
    if map.capacity() - map.len() > threshold {
        map.shrink_to_fit();
    }
}
