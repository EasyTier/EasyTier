use std::{future::Future, sync::Arc};

use dashmap::DashMap;
use futures::future::BoxFuture;

use crate::common::{
    shrink_dashmap,
    stats_manager::{CounterHandle, LabelSet, LabelType, MetricName, StatsManager},
    PeerId,
};
use crate::proto::peer_rpc::RoutePeerInfo;
use crate::tunnel::packet_def::PacketType;

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
pub(crate) struct AggregateTrafficMetrics {
    tx: TrafficCounters,
    rx: TrafficCounters,
}

impl AggregateTrafficMetrics {
    pub(crate) fn control(stats_mgr: Arc<StatsManager>, network_name: String) -> Self {
        Self::new(
            stats_mgr,
            network_name,
            MetricName::TrafficControlBytesTx,
            MetricName::TrafficControlPacketsTx,
            MetricName::TrafficControlBytesRx,
            MetricName::TrafficControlPacketsRx,
        )
    }

    fn new(
        stats_mgr: Arc<StatsManager>,
        network_name: String,
        tx_bytes_metric: MetricName,
        tx_packets_metric: MetricName,
        rx_bytes_metric: MetricName,
        rx_packets_metric: MetricName,
    ) -> Self {
        let label_set =
            LabelSet::new().with_label_type(LabelType::NetworkName(network_name.clone()));
        Self {
            tx: TrafficCounters {
                bytes: stats_mgr.get_counter(tx_bytes_metric, label_set.clone()),
                packets: stats_mgr.get_counter(tx_packets_metric, label_set.clone()),
            },
            rx: TrafficCounters {
                bytes: stats_mgr.get_counter(rx_bytes_metric, label_set.clone()),
                packets: stats_mgr.get_counter(rx_packets_metric, label_set),
            },
        }
    }

    pub(crate) fn record_tx(&self, bytes: u64) {
        self.tx.add_sample(bytes);
    }

    pub(crate) fn record_rx(&self, bytes: u64) {
        self.rx.add_sample(bytes);
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

    pub(crate) fn clear_peer_cache(&self) {
        self.per_peer.clear();
        shrink_dashmap(&self.per_peer, None);
    }

    #[cfg(test)]
    fn peer_cache_size(&self) -> usize {
        self.per_peer.len()
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

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum TrafficKind {
    Data,
    Control,
}

pub(crate) fn traffic_kind(packet_type: u8) -> TrafficKind {
    if packet_type == PacketType::Data as u8
        || packet_type == PacketType::KcpSrc as u8
        || packet_type == PacketType::KcpDst as u8
        || packet_type == PacketType::QuicSrc as u8
        || packet_type == PacketType::QuicDst as u8
        || packet_type == PacketType::DataWithKcpSrcModified as u8
        || packet_type == PacketType::DataWithQuicSrcModified as u8
    {
        TrafficKind::Data
    } else {
        TrafficKind::Control
    }
}

#[derive(Clone)]
struct TrafficMetricGroup {
    data: Arc<LogicalTrafficMetrics>,
    control: Arc<LogicalTrafficMetrics>,
}

impl TrafficMetricGroup {
    fn select(&self, kind: TrafficKind) -> &Arc<LogicalTrafficMetrics> {
        match kind {
            TrafficKind::Data => &self.data,
            TrafficKind::Control => &self.control,
        }
    }
}

type InstanceIdResolver = dyn Fn(PeerId) -> BoxFuture<'static, Option<String>> + Send + Sync;

pub(crate) struct TrafficMetricRecorder {
    my_peer_id: PeerId,
    tx_metrics: TrafficMetricGroup,
    rx_metrics: TrafficMetricGroup,
    resolve_instance_id: Arc<InstanceIdResolver>,
}

impl TrafficMetricRecorder {
    pub(crate) fn new<F, Fut>(
        my_peer_id: PeerId,
        tx_data: Arc<LogicalTrafficMetrics>,
        tx_control: Arc<LogicalTrafficMetrics>,
        rx_data: Arc<LogicalTrafficMetrics>,
        rx_control: Arc<LogicalTrafficMetrics>,
        resolve_instance_id: F,
    ) -> Self
    where
        F: Fn(PeerId) -> Fut + Send + Sync + 'static,
        Fut: Future<Output = Option<String>> + Send + 'static,
    {
        Self {
            my_peer_id,
            tx_metrics: TrafficMetricGroup {
                data: tx_data,
                control: tx_control,
            },
            rx_metrics: TrafficMetricGroup {
                data: rx_data,
                control: rx_control,
            },
            resolve_instance_id: Arc::new(move |peer_id| Box::pin(resolve_instance_id(peer_id))),
        }
    }

    pub(crate) async fn record_tx(&self, peer_id: PeerId, packet_type: u8, bytes: u64) {
        if peer_id == self.my_peer_id {
            return;
        }
        self.tx_metrics
            .select(traffic_kind(packet_type))
            .record_with_resolver(peer_id, bytes, || self.resolve_instance_id(peer_id))
            .await;
    }

    pub(crate) async fn record_rx(&self, peer_id: PeerId, packet_type: u8, bytes: u64) {
        if peer_id == self.my_peer_id {
            return;
        }
        self.rx_metrics
            .select(traffic_kind(packet_type))
            .record_with_resolver(peer_id, bytes, || self.resolve_instance_id(peer_id))
            .await;
    }

    pub(crate) fn remove_peer(&self, peer_id: PeerId) {
        self.tx_metrics.data.remove_peer(peer_id);
        self.tx_metrics.control.remove_peer(peer_id);
        self.rx_metrics.data.remove_peer(peer_id);
        self.rx_metrics.control.remove_peer(peer_id);
    }

    pub(crate) fn clear_peer_cache(&self) {
        self.tx_metrics.data.clear_peer_cache();
        self.tx_metrics.control.clear_peer_cache();
        self.rx_metrics.data.clear_peer_cache();
        self.rx_metrics.control.clear_peer_cache();
    }

    fn resolve_instance_id(&self, peer_id: PeerId) -> BoxFuture<'static, Option<String>> {
        (self.resolve_instance_id)(peer_id)
    }
}

pub(crate) fn route_peer_info_instance_id(route_peer_info: &RoutePeerInfo) -> Option<String> {
    let instance_id = route_peer_info.inst_id.as_ref()?;
    let instance_id: uuid::Uuid = (*instance_id).into();
    if instance_id.is_nil() {
        None
    } else {
        Some(instance_id.to_string())
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

    #[tokio::test]
    async fn logical_traffic_metrics_clear_peer_cache_resets_all_cached_peers() {
        let stats_mgr = Arc::new(StatsManager::new());
        let metrics = LogicalTrafficMetrics::new(
            stats_mgr,
            "default".to_string(),
            MetricName::TrafficBytesTx,
            MetricName::TrafficPacketsTx,
            MetricName::TrafficBytesTxByInstance,
            MetricName::TrafficPacketsTxByInstance,
            InstanceLabelKind::To,
        );

        metrics
            .record_with_resolver(1, 100, || async {
                Some("87ede5a2-9c3d-492d-9bbe-989b9d07e742".to_string())
            })
            .await;
        metrics
            .record_with_resolver(2, 200, || async { None })
            .await;

        assert_eq!(metrics.peer_cache_size(), 2);

        metrics.clear_peer_cache();

        assert_eq!(metrics.peer_cache_size(), 0);
    }
}
