use std::sync::Arc;

use easytier_core::rpc_impl::metrics::{RpcMetricLabels, RpcMetricStatus, RpcMetrics};

use crate::common::stats_manager::{LabelSet, LabelType, MetricName, StatsManager};

pub use easytier_core::peers::peer_rpc::*;

pub struct StatsRpcMetrics {
    stats_manager: Arc<StatsManager>,
}

impl StatsRpcMetrics {
    pub fn new(stats_manager: Arc<StatsManager>) -> Self {
        Self { stats_manager }
    }
}

fn base_labels(labels: &RpcMetricLabels) -> LabelSet {
    LabelSet::new()
        .with_label_type(LabelType::NetworkName(labels.network_name.clone()))
        .with_label_type(LabelType::SrcPeerId(labels.src_peer_id))
        .with_label_type(LabelType::DstPeerId(labels.dst_peer_id))
        .with_label_type(LabelType::ServiceName(labels.service_name.clone()))
        .with_label_type(LabelType::MethodName(labels.method_name.clone()))
}

fn labels_with_status(labels: &RpcMetricLabels, status: RpcMetricStatus) -> LabelSet {
    base_labels(labels).with_label_type(LabelType::Status(status.as_str().to_string()))
}

fn record_client_tx(stats_manager: &StatsManager, labels: &RpcMetricLabels) {
    stats_manager
        .get_counter(MetricName::PeerRpcClientTx, base_labels(labels))
        .inc();
}

fn record_client_rx(stats_manager: &StatsManager, labels: &RpcMetricLabels, duration_ms: u64) {
    let labels = labels_with_status(labels, RpcMetricStatus::Success);
    stats_manager
        .get_counter(MetricName::PeerRpcClientRx, labels.clone())
        .inc();
    stats_manager
        .get_counter(MetricName::PeerRpcDuration, labels)
        .add(duration_ms);
}

fn record_client_error(
    stats_manager: &StatsManager,
    labels: &RpcMetricLabels,
    error_type: Option<String>,
    duration_ms: u64,
) {
    let mut labels = labels_with_status(labels, RpcMetricStatus::Error);
    if let Some(error_type) = error_type {
        labels = labels.with_label_type(LabelType::ErrorType(error_type));
    }
    stats_manager
        .get_counter(MetricName::PeerRpcErrors, labels.clone())
        .inc();
    stats_manager
        .get_counter(MetricName::PeerRpcDuration, labels)
        .add(duration_ms);
}

fn record_server_rx(stats_manager: &StatsManager, labels: &RpcMetricLabels) {
    stats_manager
        .get_counter(MetricName::PeerRpcServerRx, base_labels(labels))
        .inc();
}

fn record_server_tx(stats_manager: &StatsManager, labels: &RpcMetricLabels, duration_ms: u64) {
    let labels = labels_with_status(labels, RpcMetricStatus::Success);
    stats_manager
        .get_counter(MetricName::PeerRpcServerTx, labels.clone())
        .inc();
    stats_manager
        .get_counter(MetricName::PeerRpcDuration, labels)
        .add(duration_ms);
}

fn record_server_error(stats_manager: &StatsManager, labels: &RpcMetricLabels, duration_ms: u64) {
    let labels = labels_with_status(labels, RpcMetricStatus::Error);
    stats_manager
        .get_counter(MetricName::PeerRpcErrors, labels.clone())
        .inc();
    stats_manager
        .get_counter(MetricName::PeerRpcDuration, labels)
        .add(duration_ms);
}

impl RpcMetrics for StatsRpcMetrics {
    fn client_tx(&self, labels: &RpcMetricLabels) {
        record_client_tx(&self.stats_manager, labels);
    }

    fn client_rx(&self, labels: &RpcMetricLabels, duration_ms: u64) {
        record_client_rx(&self.stats_manager, labels, duration_ms);
    }

    fn client_error(&self, labels: &RpcMetricLabels, error_type: Option<String>, duration_ms: u64) {
        record_client_error(&self.stats_manager, labels, error_type, duration_ms);
    }

    fn server_rx(&self, labels: &RpcMetricLabels) {
        record_server_rx(&self.stats_manager, labels);
    }

    fn server_tx(&self, labels: &RpcMetricLabels, duration_ms: u64) {
        record_server_tx(&self.stats_manager, labels, duration_ms);
    }

    fn server_error(
        &self,
        labels: &RpcMetricLabels,
        _error_type: Option<String>,
        duration_ms: u64,
    ) {
        record_server_error(&self.stats_manager, labels, duration_ms);
    }
}

impl RpcMetrics for StatsManager {
    fn client_tx(&self, labels: &RpcMetricLabels) {
        record_client_tx(self, labels);
    }

    fn client_rx(&self, labels: &RpcMetricLabels, duration_ms: u64) {
        record_client_rx(self, labels, duration_ms);
    }

    fn client_error(&self, labels: &RpcMetricLabels, error_type: Option<String>, duration_ms: u64) {
        record_client_error(self, labels, error_type, duration_ms);
    }

    fn server_rx(&self, labels: &RpcMetricLabels) {
        record_server_rx(self, labels);
    }

    fn server_tx(&self, labels: &RpcMetricLabels, duration_ms: u64) {
        record_server_tx(self, labels, duration_ms);
    }

    fn server_error(
        &self,
        labels: &RpcMetricLabels,
        _error_type: Option<String>,
        duration_ms: u64,
    ) {
        record_server_error(self, labels, duration_ms);
    }
}

#[cfg(test)]
pub mod tests {
    use super::PeerRpcManager;
    use crate::proto::tests::{GreetingServer, GreetingService};

    pub fn register_service(rpc_mgr: &PeerRpcManager, domain: &str, delay_ms: u64, prefix: &str) {
        rpc_mgr.rpc_server().registry().register(
            GreetingServer::new(GreetingService {
                delay_ms,
                prefix: prefix.to_string(),
            }),
            domain,
        );
    }
}
