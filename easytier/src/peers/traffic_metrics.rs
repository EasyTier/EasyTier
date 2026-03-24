use std::{future::Future, sync::Arc};

use dashmap::DashMap;

use crate::common::{
    shrink_dashmap,
    stats_manager::{CounterHandle, LabelSet, LabelType, MetricName, StatsManager},
    PeerId,
};

pub(crate) const UNKNOWN_INSTANCE_ID: &str = "unknown";

#[derive(Clone, Copy)]
pub(crate) enum InstanceLabelKind {
    To,
    From,
}

#[derive(Clone)]
struct TrafficCounters {
    bytes: CounterHandle,
    packets: CounterHandle,
}

impl TrafficCounters {
    fn add_sample(&self, bytes: u64) {
        self.bytes.add(bytes);
        self.packets.inc();
    }
}

#[derive(Clone)]
enum CachedPeerTrafficCounters {
    Unknown(TrafficCounters),
    Resolved(TrafficCounters),
}

impl CachedPeerTrafficCounters {
    fn counters(&self) -> TrafficCounters {
        match self {
            CachedPeerTrafficCounters::Unknown(counters)
            | CachedPeerTrafficCounters::Resolved(counters) => counters.clone(),
        }
    }

    fn is_resolved(&self) -> bool {
        matches!(self, CachedPeerTrafficCounters::Resolved(_))
    }
}

pub(crate) struct LogicalTrafficMetrics {
    stats_mgr: Arc<StatsManager>,
    network_name: String,
    instance_bytes_metric: MetricName,
    instance_packets_metric: MetricName,
    label_kind: InstanceLabelKind,
    total: TrafficCounters,
    per_peer: DashMap<PeerId, CachedPeerTrafficCounters>,
}

impl LogicalTrafficMetrics {
    pub(crate) fn new(
        stats_mgr: Arc<StatsManager>,
        network_name: String,
        total_bytes_metric: MetricName,
        total_packets_metric: MetricName,
        instance_bytes_metric: MetricName,
        instance_packets_metric: MetricName,
        label_kind: InstanceLabelKind,
    ) -> Self {
        let label_set =
            LabelSet::new().with_label_type(LabelType::NetworkName(network_name.clone()));
        Self {
            total: TrafficCounters {
                bytes: stats_mgr.get_counter(total_bytes_metric, label_set.clone()),
                packets: stats_mgr.get_counter(total_packets_metric, label_set),
            },
            stats_mgr,
            network_name,
            instance_bytes_metric,
            instance_packets_metric,
            label_kind,
            per_peer: DashMap::new(),
        }
    }

    pub(crate) async fn record_with_resolver<F, Fut>(
        &self,
        peer_id: PeerId,
        bytes: u64,
        resolver: F,
    ) where
        F: FnOnce() -> Fut,
        Fut: Future<Output = Option<String>>,
    {
        self.total.add_sample(bytes);

        if let Some(entry) = self.per_peer.get(&peer_id) {
            if entry.value().is_resolved() {
                entry.value().counters().add_sample(bytes);
                return;
            }
        }

        let resolved_instance_id = resolver().await;
        let counters = self.get_or_update_peer_counters(peer_id, resolved_instance_id.as_deref());
        counters.add_sample(bytes);
    }

    fn get_or_update_peer_counters(
        &self,
        peer_id: PeerId,
        resolved_instance_id: Option<&str>,
    ) -> TrafficCounters {
        match self.per_peer.entry(peer_id) {
            dashmap::Entry::Occupied(mut entry) => {
                if entry.get().is_resolved() || resolved_instance_id.is_none() {
                    return entry.get().counters();
                }
                let counters = self.build_peer_counters(resolved_instance_id.unwrap());
                entry.insert(CachedPeerTrafficCounters::Resolved(counters.clone()));
                counters
            }
            dashmap::Entry::Vacant(entry) => {
                let counters =
                    self.build_peer_counters(resolved_instance_id.unwrap_or(UNKNOWN_INSTANCE_ID));
                let cached = if resolved_instance_id.is_some() {
                    CachedPeerTrafficCounters::Resolved(counters.clone())
                } else {
                    CachedPeerTrafficCounters::Unknown(counters.clone())
                };
                entry.insert(cached);
                counters
            }
        }
    }

    pub(crate) fn remove_peer(&self, peer_id: PeerId) {
        self.per_peer.remove(&peer_id);
        shrink_dashmap(&self.per_peer, None);
    }

    fn build_peer_counters(&self, instance_id: &str) -> TrafficCounters {
        let instance_label = match self.label_kind {
            InstanceLabelKind::To => LabelType::ToInstanceId(instance_id.to_string()),
            InstanceLabelKind::From => LabelType::FromInstanceId(instance_id.to_string()),
        };
        let label_set = LabelSet::new()
            .with_label_type(LabelType::NetworkName(self.network_name.clone()))
            .with_label_type(instance_label);
        TrafficCounters {
            bytes: self
                .stats_mgr
                .get_counter(self.instance_bytes_metric, label_set.clone()),
            packets: self
                .stats_mgr
                .get_counter(self.instance_packets_metric, label_set),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::common::stats_manager::LabelSet;

    fn network_labels(network_name: &str) -> LabelSet {
        LabelSet::new().with_label_type(LabelType::NetworkName(network_name.to_string()))
    }

    fn to_instance_labels(network_name: &str, instance_id: &str) -> LabelSet {
        LabelSet::new()
            .with_label_type(LabelType::NetworkName(network_name.to_string()))
            .with_label_type(LabelType::ToInstanceId(instance_id.to_string()))
    }

    #[tokio::test]
    async fn logical_traffic_metrics_upgrade_unknown_instance_label() {
        let stats_mgr = Arc::new(StatsManager::new());
        let metrics = LogicalTrafficMetrics::new(
            stats_mgr.clone(),
            "default".to_string(),
            MetricName::TrafficBytesTx,
            MetricName::TrafficPacketsTx,
            MetricName::TrafficBytesTxByInstance,
            MetricName::TrafficPacketsTxByInstance,
            InstanceLabelKind::To,
        );
        let peer_id = 42;
        let resolved_instance_id = "87ede5a2-9c3d-492d-9bbe-989b9d07e742";

        metrics
            .record_with_resolver(peer_id, 100, || async { None })
            .await;
        metrics
            .record_with_resolver(peer_id, 200, || async {
                Some(resolved_instance_id.to_string())
            })
            .await;

        assert_eq!(
            stats_mgr
                .get_metric(MetricName::TrafficBytesTx, &network_labels("default"))
                .unwrap()
                .value,
            300
        );
        assert!(stats_mgr
            .get_metric(
                MetricName::TrafficBytesTx,
                &to_instance_labels("default", UNKNOWN_INSTANCE_ID),
            )
            .is_none());
        assert!(stats_mgr
            .get_metric(
                MetricName::TrafficBytesTx,
                &to_instance_labels("default", resolved_instance_id),
            )
            .is_none());
        assert_eq!(
            stats_mgr
                .get_metric(
                    MetricName::TrafficBytesTxByInstance,
                    &to_instance_labels("default", UNKNOWN_INSTANCE_ID),
                )
                .unwrap()
                .value,
            100
        );
        assert_eq!(
            stats_mgr
                .get_metric(
                    MetricName::TrafficBytesTxByInstance,
                    &to_instance_labels("default", resolved_instance_id),
                )
                .unwrap()
                .value,
            200
        );
        assert_eq!(
            stats_mgr
                .get_metric(
                    MetricName::TrafficPacketsTxByInstance,
                    &to_instance_labels("default", UNKNOWN_INSTANCE_ID),
                )
                .unwrap()
                .value,
            1
        );
        assert_eq!(
            stats_mgr
                .get_metric(
                    MetricName::TrafficPacketsTxByInstance,
                    &to_instance_labels("default", resolved_instance_id),
                )
                .unwrap()
                .value,
            1
        );
    }

    #[tokio::test]
    async fn logical_traffic_metrics_remove_peer_clears_cached_counters() {
        let stats_mgr = Arc::new(StatsManager::new());
        let metrics = LogicalTrafficMetrics::new(
            stats_mgr.clone(),
            "default".to_string(),
            MetricName::TrafficBytesTx,
            MetricName::TrafficPacketsTx,
            MetricName::TrafficBytesTxByInstance,
            MetricName::TrafficPacketsTxByInstance,
            InstanceLabelKind::To,
        );
        let peer_id = 42;
        let resolved_instance_id = "87ede5a2-9c3d-492d-9bbe-989b9d07e742";

        metrics
            .record_with_resolver(peer_id, 100, || async {
                Some(resolved_instance_id.to_string())
            })
            .await;
        metrics.remove_peer(peer_id);
        metrics
            .record_with_resolver(peer_id, 200, || async { None })
            .await;

        assert_eq!(
            stats_mgr
                .get_metric(MetricName::TrafficBytesTx, &network_labels("default"))
                .unwrap()
                .value,
            300
        );
        assert_eq!(
            stats_mgr
                .get_metric(
                    MetricName::TrafficBytesTxByInstance,
                    &to_instance_labels("default", resolved_instance_id),
                )
                .unwrap()
                .value,
            100
        );
        assert_eq!(
            stats_mgr
                .get_metric(
                    MetricName::TrafficBytesTxByInstance,
                    &to_instance_labels("default", UNKNOWN_INSTANCE_ID),
                )
                .unwrap()
                .value,
            200
        );
    }
}
