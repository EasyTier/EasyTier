use std::sync::Arc;

use crate::config::PeerId;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RpcMetricLabels {
    pub network_name: String,
    pub src_peer_id: PeerId,
    pub dst_peer_id: PeerId,
    pub service_name: String,
    pub method_name: String,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RpcMetricStatus {
    Success,
    Error,
}

impl RpcMetricStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Success => "success",
            Self::Error => "error",
        }
    }
}

pub trait RpcMetrics: Send + Sync + 'static {
    fn client_tx(&self, _labels: &RpcMetricLabels) {}

    fn client_rx(&self, _labels: &RpcMetricLabels, _duration_ms: u64) {}

    fn client_error(
        &self,
        _labels: &RpcMetricLabels,
        _error_type: Option<String>,
        _duration_ms: u64,
    ) {
    }

    fn server_rx(&self, _labels: &RpcMetricLabels) {}

    fn server_tx(&self, _labels: &RpcMetricLabels, _duration_ms: u64) {}

    fn server_error(
        &self,
        _labels: &RpcMetricLabels,
        _error_type: Option<String>,
        _duration_ms: u64,
    ) {
    }
}

pub type ArcRpcMetrics = Arc<dyn RpcMetrics>;

pub trait RpcMetricsProvider: Send + Sync + 'static {
    fn into_rpc_metrics(self) -> Option<ArcRpcMetrics>;
}

impl RpcMetricsProvider for () {
    fn into_rpc_metrics(self) -> Option<ArcRpcMetrics> {
        None
    }
}

impl RpcMetricsProvider for ArcRpcMetrics {
    fn into_rpc_metrics(self) -> Option<ArcRpcMetrics> {
        Some(self)
    }
}

impl<T> RpcMetricsProvider for Arc<T>
where
    T: RpcMetrics,
{
    fn into_rpc_metrics(self) -> Option<ArcRpcMetrics> {
        Some(self)
    }
}
