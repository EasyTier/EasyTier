use crate::rpc_impl::metrics::{RpcMetricLabels, RpcMetricStatus, RpcMetrics};
use dashmap::DashMap;
use quanta::Instant;
use serde::{Deserialize, Serialize};
use std::cell::UnsafeCell;
use std::fmt;
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio_util::task::AbortOnDropHandle;

use crate::foundation::time::interval;

/// Predefined metric names for type safety
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum MetricName {
    /// RPC calls sent to peers
    PeerRpcClientTx,
    /// RPC calls received from peers
    PeerRpcClientRx,
    /// RPC calls sent to peers
    PeerRpcServerTx,
    /// RPC calls received from peers
    PeerRpcServerRx,
    /// RPC call duration in milliseconds
    PeerRpcDuration,
    /// RPC errors
    PeerRpcErrors,

    /// Data-plane traffic bytes sent
    TrafficBytesTx,
    /// Data-plane traffic bytes sent, grouped by destination instance
    TrafficBytesTxByInstance,
    /// Data-plane traffic bytes received
    TrafficBytesRx,
    /// Data-plane traffic bytes received, grouped by source instance
    TrafficBytesRxByInstance,
    /// Control-plane traffic bytes sent
    TrafficControlBytesTx,
    /// Control-plane traffic bytes sent, grouped by destination instance
    TrafficControlBytesTxByInstance,
    /// Control-plane traffic bytes received
    TrafficControlBytesRx,
    /// Control-plane traffic bytes received, grouped by source instance
    TrafficControlBytesRxByInstance,
    /// Traffic bytes forwarded
    TrafficBytesForwarded,
    /// Control-plane traffic bytes forwarded
    TrafficControlBytesForwarded,
    /// Traffic bytes sent to self
    TrafficBytesSelfTx,
    /// Traffic bytes received from self
    TrafficBytesSelfRx,
    /// Traffic bytes forwarded for foreign network, rx to local
    TrafficBytesForeignForwardRx,
    /// Traffic bytes forwarded for foreign network, tx from local
    TrafficBytesForeignForwardTx,
    /// Traffic bytes forwarded for foreign network, forward
    TrafficBytesForeignForwardForwarded,

    /// Data-plane traffic packets sent
    TrafficPacketsTx,
    /// Data-plane traffic packets sent, grouped by destination instance
    TrafficPacketsTxByInstance,
    /// Data-plane traffic packets received
    TrafficPacketsRx,
    /// Data-plane traffic packets received, grouped by source instance
    TrafficPacketsRxByInstance,
    /// Control-plane traffic packets sent
    TrafficControlPacketsTx,
    /// Control-plane traffic packets sent, grouped by destination instance
    TrafficControlPacketsTxByInstance,
    /// Control-plane traffic packets received
    TrafficControlPacketsRx,
    /// Control-plane traffic packets received, grouped by source instance
    TrafficControlPacketsRxByInstance,
    /// Traffic packets forwarded
    TrafficPacketsForwarded,
    /// Control-plane traffic packets forwarded
    TrafficControlPacketsForwarded,
    /// Traffic packets sent to self
    TrafficPacketsSelfTx,
    /// Traffic packets received from self
    TrafficPacketsSelfRx,
    /// Traffic packets forwarded for foreign network, rx to local
    TrafficPacketsForeignForwardRx,
    /// Traffic packets forwarded for foreign network, tx from local
    TrafficPacketsForeignForwardTx,
    /// Traffic packets forwarded for foreign network, forward
    TrafficPacketsForeignForwardForwarded,

    /// UDP broadcast relay packets captured from the raw socket
    UdpBroadcastRelayPacketsCaptured,
    /// UDP broadcast relay packets ignored before forwarding
    UdpBroadcastRelayPacketsIgnored,
    /// UDP broadcast relay packets forwarded
    UdpBroadcastRelayPacketsForwarded,
    /// UDP broadcast relay packets that failed to forward
    UdpBroadcastRelayPacketsForwardFailed,

    /// Compression bytes before compression
    CompressionBytesRxBefore,
    /// Compression bytes after compression
    CompressionBytesRxAfter,
    /// Compression bytes before compression
    CompressionBytesTxBefore,
    /// Compression bytes after compression
    CompressionBytesTxAfter,

    TcpProxyConnect,
}

impl fmt::Display for MetricName {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            MetricName::PeerRpcClientTx => write!(f, "peer_rpc_client_tx"),
            MetricName::PeerRpcClientRx => write!(f, "peer_rpc_client_rx"),
            MetricName::PeerRpcServerTx => write!(f, "peer_rpc_server_tx"),
            MetricName::PeerRpcServerRx => write!(f, "peer_rpc_server_rx"),
            MetricName::PeerRpcDuration => write!(f, "peer_rpc_duration_ms"),
            MetricName::PeerRpcErrors => write!(f, "peer_rpc_errors"),

            MetricName::TrafficBytesTx => write!(f, "traffic_bytes_tx"),
            MetricName::TrafficBytesTxByInstance => write!(f, "traffic_bytes_tx_by_instance"),
            MetricName::TrafficBytesRx => write!(f, "traffic_bytes_rx"),
            MetricName::TrafficBytesRxByInstance => write!(f, "traffic_bytes_rx_by_instance"),
            MetricName::TrafficControlBytesTx => write!(f, "traffic_control_bytes_tx"),
            MetricName::TrafficControlBytesTxByInstance => {
                write!(f, "traffic_control_bytes_tx_by_instance")
            }
            MetricName::TrafficControlBytesRx => write!(f, "traffic_control_bytes_rx"),
            MetricName::TrafficControlBytesRxByInstance => {
                write!(f, "traffic_control_bytes_rx_by_instance")
            }
            MetricName::TrafficBytesForwarded => write!(f, "traffic_bytes_forwarded"),
            MetricName::TrafficControlBytesForwarded => {
                write!(f, "traffic_control_bytes_forwarded")
            }
            MetricName::TrafficBytesSelfTx => write!(f, "traffic_bytes_self_tx"),
            MetricName::TrafficBytesSelfRx => write!(f, "traffic_bytes_self_rx"),
            MetricName::TrafficBytesForeignForwardRx => {
                write!(f, "traffic_bytes_foreign_forward_rx")
            }
            MetricName::TrafficBytesForeignForwardTx => {
                write!(f, "traffic_bytes_foreign_forward_tx")
            }
            MetricName::TrafficBytesForeignForwardForwarded => {
                write!(f, "traffic_bytes_foreign_forward_forwarded")
            }

            MetricName::TrafficPacketsTx => write!(f, "traffic_packets_tx"),
            MetricName::TrafficPacketsTxByInstance => {
                write!(f, "traffic_packets_tx_by_instance")
            }
            MetricName::TrafficPacketsRx => write!(f, "traffic_packets_rx"),
            MetricName::TrafficPacketsRxByInstance => {
                write!(f, "traffic_packets_rx_by_instance")
            }
            MetricName::TrafficControlPacketsTx => write!(f, "traffic_control_packets_tx"),
            MetricName::TrafficControlPacketsTxByInstance => {
                write!(f, "traffic_control_packets_tx_by_instance")
            }
            MetricName::TrafficControlPacketsRx => write!(f, "traffic_control_packets_rx"),
            MetricName::TrafficControlPacketsRxByInstance => {
                write!(f, "traffic_control_packets_rx_by_instance")
            }
            MetricName::TrafficPacketsForwarded => write!(f, "traffic_packets_forwarded"),
            MetricName::TrafficControlPacketsForwarded => {
                write!(f, "traffic_control_packets_forwarded")
            }
            MetricName::TrafficPacketsSelfTx => write!(f, "traffic_packets_self_tx"),
            MetricName::TrafficPacketsSelfRx => write!(f, "traffic_packets_self_rx"),
            MetricName::TrafficPacketsForeignForwardRx => {
                write!(f, "traffic_packets_foreign_forward_rx")
            }
            MetricName::TrafficPacketsForeignForwardTx => {
                write!(f, "traffic_packets_foreign_forward_tx")
            }
            MetricName::TrafficPacketsForeignForwardForwarded => {
                write!(f, "traffic_packets_foreign_forward_forwarded")
            }

            MetricName::UdpBroadcastRelayPacketsCaptured => {
                write!(f, "udp_broadcast_relay_packets_captured")
            }
            MetricName::UdpBroadcastRelayPacketsIgnored => {
                write!(f, "udp_broadcast_relay_packets_ignored")
            }
            MetricName::UdpBroadcastRelayPacketsForwarded => {
                write!(f, "udp_broadcast_relay_packets_forwarded")
            }
            MetricName::UdpBroadcastRelayPacketsForwardFailed => {
                write!(f, "udp_broadcast_relay_packets_forward_failed")
            }

            MetricName::CompressionBytesRxBefore => write!(f, "compression_bytes_rx_before"),
            MetricName::CompressionBytesRxAfter => write!(f, "compression_bytes_rx_after"),
            MetricName::CompressionBytesTxBefore => write!(f, "compression_bytes_tx_before"),
            MetricName::CompressionBytesTxAfter => write!(f, "compression_bytes_tx_after"),

            MetricName::TcpProxyConnect => write!(f, "tcp_proxy_connect"),
        }
    }
}

/// Predefined label types for type safety
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum LabelType {
    /// Network Name
    NetworkName(String),
    /// Destination instance ID
    ToInstanceId(String),
    /// Source instance ID
    FromInstanceId(String),
    /// Source peer ID
    SrcPeerId(u32),
    /// Destination peer ID
    DstPeerId(u32),
    /// Service name
    ServiceName(String),
    /// Method name
    MethodName(String),
    /// Protocol type
    Protocol(String),
    /// Direction (tx/rx)
    Direction(String),
    /// Compression algorithm
    CompressionAlgo(String),
    /// Error type
    ErrorType(String),
    /// Status
    Status(String),
    /// Dst Ip
    DstIp(String),
    /// Mapped Dst Ip
    MappedDstIp(String),
}

impl fmt::Display for LabelType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            LabelType::NetworkName(name) => write!(f, "network_name={}", name),
            LabelType::ToInstanceId(id) => write!(f, "to_instance_id={}", id),
            LabelType::FromInstanceId(id) => write!(f, "from_instance_id={}", id),
            LabelType::SrcPeerId(id) => write!(f, "src_peer_id={}", id),
            LabelType::DstPeerId(id) => write!(f, "dst_peer_id={}", id),
            LabelType::ServiceName(name) => write!(f, "service_name={}", name),
            LabelType::MethodName(name) => write!(f, "method_name={}", name),
            LabelType::Protocol(proto) => write!(f, "protocol={}", proto),
            LabelType::Direction(dir) => write!(f, "direction={}", dir),
            LabelType::CompressionAlgo(algo) => write!(f, "compression_algo={}", algo),
            LabelType::ErrorType(err) => write!(f, "error_type={}", err),
            LabelType::Status(status) => write!(f, "status={}", status),
            LabelType::DstIp(ip) => write!(f, "dst_ip={}", ip),
            LabelType::MappedDstIp(ip) => write!(f, "mapped_dst_ip={}", ip),
        }
    }
}

impl LabelType {
    pub fn key(&self) -> &'static str {
        match self {
            LabelType::NetworkName(_) => "network_name",
            LabelType::ToInstanceId(_) => "to_instance_id",
            LabelType::FromInstanceId(_) => "from_instance_id",
            LabelType::SrcPeerId(_) => "src_peer_id",
            LabelType::DstPeerId(_) => "dst_peer_id",
            LabelType::ServiceName(_) => "service_name",
            LabelType::MethodName(_) => "method_name",
            LabelType::Protocol(_) => "protocol",
            LabelType::Direction(_) => "direction",
            LabelType::CompressionAlgo(_) => "compression_algo",
            LabelType::ErrorType(_) => "error_type",
            LabelType::Status(_) => "status",
            LabelType::DstIp(_) => "dst_ip",
            LabelType::MappedDstIp(_) => "mapped_dst_ip",
        }
    }

    pub fn value(&self) -> String {
        match self {
            LabelType::NetworkName(name) => name.clone(),
            LabelType::ToInstanceId(id) => id.clone(),
            LabelType::FromInstanceId(id) => id.clone(),
            LabelType::SrcPeerId(id) => id.to_string(),
            LabelType::DstPeerId(id) => id.to_string(),
            LabelType::ServiceName(name) => name.clone(),
            LabelType::MethodName(name) => name.clone(),
            LabelType::Protocol(proto) => proto.clone(),
            LabelType::Direction(dir) => dir.clone(),
            LabelType::CompressionAlgo(algo) => algo.clone(),
            LabelType::ErrorType(err) => err.clone(),
            LabelType::Status(status) => status.clone(),
            LabelType::DstIp(ip) => ip.clone(),
            LabelType::MappedDstIp(ip) => ip.clone(),
        }
    }
}

/// Label represents a key-value pair for metric identification
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct Label {
    pub key: String,
    pub value: String,
}

impl Label {
    pub fn new(key: impl Into<String>, value: impl Into<String>) -> Self {
        Self {
            key: key.into(),
            value: value.into(),
        }
    }

    pub fn from_label_type(label_type: &LabelType) -> Self {
        Self {
            key: label_type.key().to_string(),
            value: label_type.value(),
        }
    }
}

/// LabelSet represents a collection of labels for a metric
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct LabelSet {
    labels: Vec<Label>,
}

impl LabelSet {
    pub fn new() -> Self {
        Self { labels: Vec::new() }
    }

    pub fn with_label(mut self, key: impl Into<String>, value: impl Into<String>) -> Self {
        self.labels.push(Label::new(key, value));
        self.labels.sort_by(|a, b| a.key.cmp(&b.key)); // Keep labels sorted for consistent hashing
        self
    }

    /// Add a typed label to the set
    pub fn with_label_type(mut self, label_type: LabelType) -> Self {
        self.labels.push(Label::from_label_type(&label_type));
        self.labels.sort_by(|a, b| a.key.cmp(&b.key)); // Keep labels sorted for consistent hashing
        self
    }

    /// Create a LabelSet from multiple LabelTypes
    pub fn from_label_types(label_types: &[LabelType]) -> Self {
        let mut labels = Vec::new();
        for label_type in label_types {
            labels.push(Label::from_label_type(label_type));
        }
        labels.sort_by(|a, b| a.key.cmp(&b.key)); // Keep labels sorted for consistent hashing
        Self { labels }
    }

    pub fn labels(&self) -> &[Label] {
        &self.labels
    }

    /// Generate a string key for this label set
    pub fn to_key(&self) -> String {
        if self.labels.is_empty() {
            return String::new();
        }

        let mut parts = Vec::with_capacity(self.labels.len());
        for label in &self.labels {
            parts.push(format!("{}={}", label.key, label.value));
        }
        parts.join(",")
    }
}

impl Default for LabelSet {
    fn default() -> Self {
        Self::new()
    }
}

/// UnsafeCounter provides a high-performance counter using UnsafeCell
#[derive(Debug)]
pub struct UnsafeCounter {
    value: UnsafeCell<u64>,
}

impl Default for UnsafeCounter {
    fn default() -> Self {
        Self::new()
    }
}

impl UnsafeCounter {
    pub fn new() -> Self {
        Self {
            value: UnsafeCell::new(0),
        }
    }

    pub fn new_with_value(initial: u64) -> Self {
        Self {
            value: UnsafeCell::new(initial),
        }
    }

    /// Increment the counter by the given amount
    /// # Safety
    /// This method is unsafe because it uses UnsafeCell. The caller must ensure
    /// that no other thread is accessing this counter simultaneously.
    pub unsafe fn add(&self, delta: u64) {
        let ptr = self.value.get();
        unsafe {
            *ptr = (*ptr).saturating_add(delta);
        }
    }

    /// Increment the counter by 1
    /// # Safety
    /// This method is unsafe because it uses UnsafeCell. The caller must ensure
    /// that no other thread is accessing this counter simultaneously.
    pub unsafe fn inc(&self) {
        unsafe {
            self.add(1);
        }
    }

    /// Get the current value of the counter
    /// # Safety
    /// This method is unsafe because it uses UnsafeCell. The caller must ensure
    /// that no other thread is modifying this counter simultaneously.
    pub unsafe fn get(&self) -> u64 {
        let ptr = self.value.get();
        unsafe { *ptr }
    }

    /// Reset the counter to zero
    /// # Safety
    /// This method is unsafe because it uses UnsafeCell. The caller must ensure
    /// that no other thread is accessing this counter simultaneously.
    pub unsafe fn reset(&self) {
        let ptr = self.value.get();
        unsafe {
            *ptr = 0;
        }
    }

    /// Set the counter to a specific value
    /// # Safety
    /// This method is unsafe because it uses UnsafeCell. The caller must ensure
    /// that no other thread is accessing this counter simultaneously.
    pub unsafe fn set(&self, value: u64) {
        let ptr = self.value.get();
        unsafe {
            *ptr = value;
        }
    }
}

// UnsafeCounter is Send + Sync because the safety is guaranteed by the caller
unsafe impl Send for UnsafeCounter {}
unsafe impl Sync for UnsafeCounter {}

/// MetricData contains both the counter and last update timestamp
/// Uses UnsafeCell for lock-free access
#[derive(Debug)]
struct MetricData {
    counter: UnsafeCounter,
    last_updated: UnsafeCell<Instant>,
}

impl MetricData {
    fn new() -> Self {
        Self {
            counter: UnsafeCounter::new(),
            last_updated: UnsafeCell::new(Instant::now()),
        }
    }

    /// Update the last_updated timestamp
    /// # Safety
    /// This method is unsafe because it uses UnsafeCell. The caller must ensure
    /// that no other thread is accessing this timestamp simultaneously.
    unsafe fn touch(&self) {
        let ptr = self.last_updated.get();
        unsafe {
            *ptr = Instant::now();
        }
    }

    /// Get the last updated timestamp
    /// # Safety
    /// This method is unsafe because it uses UnsafeCell. The caller must ensure
    /// that no other thread is modifying this timestamp simultaneously.
    unsafe fn get_last_updated(&self) -> Instant {
        let ptr = self.last_updated.get();
        unsafe { *ptr }
    }
}

// MetricData is Send + Sync because the safety is guaranteed by the caller
unsafe impl Send for MetricData {}
unsafe impl Sync for MetricData {}

/// MetricKey uniquely identifies a metric with its name and labels
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct MetricKey {
    name: MetricName,
    labels: LabelSet,
}

impl MetricKey {
    fn new(name: MetricName, labels: LabelSet) -> Self {
        Self { name, labels }
    }
}

impl fmt::Display for MetricKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let label_str = self.labels.to_key();
        if label_str.is_empty() {
            f.write_str(self.name.to_string().as_str())
        } else {
            f.write_str(format!("{}[{}]", self.name, label_str).as_str())
        }
    }
}

/// CounterHandle provides a safe interface to a MetricData
/// It ensures thread-local access patterns for performance
#[derive(Clone)]
pub struct CounterHandle {
    metric_data: Arc<MetricData>,
    _key: MetricKey, // Keep key for debugging purposes
}

impl CounterHandle {
    fn new(metric_data: Arc<MetricData>, key: MetricKey) -> Self {
        Self {
            metric_data,
            _key: key,
        }
    }

    /// Increment the counter by the given amount
    pub fn add(&self, delta: u64) {
        unsafe {
            self.metric_data.counter.add(delta);
            self.metric_data.touch();
        }
    }

    /// Increment the counter by 1
    pub fn inc(&self) {
        unsafe {
            self.metric_data.counter.inc();
            self.metric_data.touch();
        }
    }

    /// Get the current value of the counter
    pub fn get(&self) -> u64 {
        unsafe { self.metric_data.counter.get() }
    }

    /// Reset the counter to zero
    pub fn reset(&self) {
        unsafe {
            self.metric_data.counter.reset();
            self.metric_data.touch();
        }
    }

    /// Set the counter to a specific value
    pub fn set(&self, value: u64) {
        unsafe {
            self.metric_data.counter.set(value);
            self.metric_data.touch();
        }
    }
}

/// MetricSnapshot represents a point-in-time view of a metric
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MetricSnapshot {
    pub name: MetricName,
    pub labels: LabelSet,
    pub value: u64,
}

impl MetricSnapshot {
    pub fn name_str(&self) -> String {
        self.name.to_string()
    }
}

/// StatsManager manages global statistics with high performance counters
pub struct StatsManager {
    counters: Arc<DashMap<MetricKey, Arc<MetricData>>>,
    cleanup_task: Mutex<Option<AbortOnDropHandle<()>>>,
}

impl StatsManager {
    /// Create a new StatsManager
    pub fn new() -> Self {
        let manager = Self {
            counters: Arc::new(DashMap::new()),
            cleanup_task: Mutex::new(None),
        };
        manager.start_cleanup_task();
        manager
    }

    pub(crate) fn start_cleanup_task(&self) {
        let mut cleanup_task = self.cleanup_task.lock().unwrap();
        if cleanup_task
            .as_ref()
            .is_some_and(|task| !task.is_finished())
        {
            return;
        }
        cleanup_task.take();
        let Ok(runtime) = tokio::runtime::Handle::try_current() else {
            return;
        };
        let counters = Arc::downgrade(&self.counters);
        *cleanup_task = Some(AbortOnDropHandle::new(runtime.spawn(async move {
            let mut interval = interval(Duration::from_secs(60)); // Check every minute
            loop {
                interval.tick().await;

                let Some(cutoff_time) = Instant::now().checked_sub(Duration::from_secs(180)) else {
                    continue;
                };

                let Some(counters) = counters.upgrade() else {
                    break;
                };

                counters.retain(|_, metric_data: &mut Arc<MetricData>| {
                    Arc::strong_count(metric_data) > 1
                        || unsafe { metric_data.get_last_updated() > cutoff_time }
                });
                counters.shrink_to_fit();
            }
        })));
    }

    pub(crate) async fn stop_cleanup_task(&self) {
        let task = self.cleanup_task.lock().unwrap().take();
        if let Some(task) = task {
            task.abort();
            let _ = task.await;
        }
    }

    /// Get or create a counter with the given name and labels
    pub fn get_counter(&self, name: MetricName, labels: LabelSet) -> CounterHandle {
        let key = MetricKey::new(name, labels);

        let metric_data = self
            .counters
            .entry(key.clone())
            .or_insert_with(|| Arc::new(MetricData::new()))
            .clone();

        CounterHandle::new(metric_data, key)
    }

    /// Get all metric snapshots
    pub fn get_all_metrics(&self) -> Vec<MetricSnapshot> {
        let mut metrics = Vec::new();

        for entry in self.counters.iter() {
            let key = entry.key();
            let metric_data = entry.value();

            let value = unsafe { metric_data.counter.get() };

            metrics.push(MetricSnapshot {
                name: key.name,
                labels: key.labels.clone(),
                value,
            });
        }

        // Sort by metric name and then by labels for consistent output
        metrics.sort_by(|a, b| {
            a.name
                .to_string()
                .cmp(&b.name.to_string())
                .then_with(|| a.labels.to_key().cmp(&b.labels.to_key()))
        });

        metrics
    }

    /// Clear all metrics
    pub fn clear(&self) {
        self.counters.clear();
    }

    /// Export metrics in Prometheus format
    pub fn export_prometheus(&self) -> String {
        let metrics = self.get_all_metrics();
        let mut output = String::new();

        let mut current_metric = String::new();

        for metric in metrics {
            let metric_name_str = metric.name.to_string();
            if metric_name_str != current_metric {
                if !current_metric.is_empty() {
                    output.push('\n');
                }
                output.push_str(&format!("# TYPE {} counter\n", metric_name_str));
                current_metric = metric_name_str.clone();
            }

            if metric.labels.labels().is_empty() {
                output.push_str(&format!("{} {}\n", metric_name_str, metric.value));
            } else {
                let label_str = metric
                    .labels
                    .labels()
                    .iter()
                    .map(|l| format!("{}=\"{}\"", l.key, l.value))
                    .collect::<Vec<_>>()
                    .join(",");
                output.push_str(&format!(
                    "{}{{{}}} {}\n",
                    metric_name_str, label_str, metric.value
                ));
            }
        }

        output
    }
}

impl Default for StatsManager {
    fn default() -> Self {
        Self::new()
    }
}

pub struct StatsRpcMetrics {
    stats_manager: Arc<StatsManager>,
}

impl StatsRpcMetrics {
    pub fn new(stats_manager: Arc<StatsManager>) -> Self {
        Self { stats_manager }
    }
}

fn rpc_base_labels(labels: &RpcMetricLabels) -> LabelSet {
    LabelSet::new()
        .with_label_type(LabelType::NetworkName(labels.network_name.clone()))
        .with_label_type(LabelType::SrcPeerId(labels.src_peer_id))
        .with_label_type(LabelType::DstPeerId(labels.dst_peer_id))
        .with_label_type(LabelType::ServiceName(labels.service_name.clone()))
        .with_label_type(LabelType::MethodName(labels.method_name.clone()))
}

fn rpc_labels_with_status(labels: &RpcMetricLabels, status: RpcMetricStatus) -> LabelSet {
    rpc_base_labels(labels).with_label_type(LabelType::Status(status.as_str().to_string()))
}

fn record_rpc_client_tx(stats_manager: &StatsManager, labels: &RpcMetricLabels) {
    stats_manager
        .get_counter(MetricName::PeerRpcClientTx, rpc_base_labels(labels))
        .inc();
}

fn record_rpc_client_rx(stats_manager: &StatsManager, labels: &RpcMetricLabels, duration_ms: u64) {
    let labels = rpc_labels_with_status(labels, RpcMetricStatus::Success);
    stats_manager
        .get_counter(MetricName::PeerRpcClientRx, labels.clone())
        .inc();
    stats_manager
        .get_counter(MetricName::PeerRpcDuration, labels)
        .add(duration_ms);
}

fn record_rpc_client_error(
    stats_manager: &StatsManager,
    labels: &RpcMetricLabels,
    error_type: Option<String>,
    duration_ms: u64,
) {
    let mut labels = rpc_labels_with_status(labels, RpcMetricStatus::Error);
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

fn record_rpc_server_rx(stats_manager: &StatsManager, labels: &RpcMetricLabels) {
    stats_manager
        .get_counter(MetricName::PeerRpcServerRx, rpc_base_labels(labels))
        .inc();
}

fn record_rpc_server_tx(stats_manager: &StatsManager, labels: &RpcMetricLabels, duration_ms: u64) {
    let labels = rpc_labels_with_status(labels, RpcMetricStatus::Success);
    stats_manager
        .get_counter(MetricName::PeerRpcServerTx, labels.clone())
        .inc();
    stats_manager
        .get_counter(MetricName::PeerRpcDuration, labels)
        .add(duration_ms);
}

fn record_rpc_server_error(
    stats_manager: &StatsManager,
    labels: &RpcMetricLabels,
    duration_ms: u64,
) {
    let labels = rpc_labels_with_status(labels, RpcMetricStatus::Error);
    stats_manager
        .get_counter(MetricName::PeerRpcErrors, labels.clone())
        .inc();
    stats_manager
        .get_counter(MetricName::PeerRpcDuration, labels)
        .add(duration_ms);
}

impl RpcMetrics for StatsRpcMetrics {
    fn client_tx(&self, labels: &RpcMetricLabels) {
        record_rpc_client_tx(&self.stats_manager, labels);
    }

    fn client_rx(&self, labels: &RpcMetricLabels, duration_ms: u64) {
        record_rpc_client_rx(&self.stats_manager, labels, duration_ms);
    }

    fn client_error(&self, labels: &RpcMetricLabels, error_type: Option<String>, duration_ms: u64) {
        record_rpc_client_error(&self.stats_manager, labels, error_type, duration_ms);
    }

    fn server_rx(&self, labels: &RpcMetricLabels) {
        record_rpc_server_rx(&self.stats_manager, labels);
    }

    fn server_tx(&self, labels: &RpcMetricLabels, duration_ms: u64) {
        record_rpc_server_tx(&self.stats_manager, labels, duration_ms);
    }

    fn server_error(
        &self,
        labels: &RpcMetricLabels,
        _error_type: Option<String>,
        duration_ms: u64,
    ) {
        record_rpc_server_error(&self.stats_manager, labels, duration_ms);
    }
}

impl RpcMetrics for StatsManager {
    fn client_tx(&self, labels: &RpcMetricLabels) {
        record_rpc_client_tx(self, labels);
    }

    fn client_rx(&self, labels: &RpcMetricLabels, duration_ms: u64) {
        record_rpc_client_rx(self, labels, duration_ms);
    }

    fn client_error(&self, labels: &RpcMetricLabels, error_type: Option<String>, duration_ms: u64) {
        record_rpc_client_error(self, labels, error_type, duration_ms);
    }

    fn server_rx(&self, labels: &RpcMetricLabels) {
        record_rpc_server_rx(self, labels);
    }

    fn server_tx(&self, labels: &RpcMetricLabels, duration_ms: u64) {
        record_rpc_server_tx(self, labels, duration_ms);
    }

    fn server_error(
        &self,
        labels: &RpcMetricLabels,
        _error_type: Option<String>,
        duration_ms: u64,
    ) {
        record_rpc_server_error(self, labels, duration_ms);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    impl StatsManager {
        pub(crate) fn cleanup_task_is_stopped(&self) -> bool {
            self.cleanup_task.lock().unwrap().is_none()
        }

        fn get_simple_counter(&self, name: MetricName) -> CounterHandle {
            self.get_counter(name, LabelSet::new())
        }

        fn get_metrics_by_prefix(&self, prefix: &str) -> Vec<MetricSnapshot> {
            self.get_all_metrics()
                .into_iter()
                .filter(|m| m.name.to_string().starts_with(prefix))
                .collect()
        }

        pub(crate) fn get_metric(
            &self,
            name: MetricName,
            labels: &LabelSet,
        ) -> Option<MetricSnapshot> {
            let key = MetricKey::new(name, labels.clone());

            if let Some(metric_data) = self.counters.get(&key) {
                let value = unsafe { metric_data.counter.get() };
                Some(MetricSnapshot {
                    name,
                    labels: labels.clone(),
                    value,
                })
            } else {
                None
            }
        }

        fn metric_count(&self) -> usize {
            self.counters.len()
        }
    }

    #[test]
    fn cleanup_task_can_start_after_sync_construction() {
        let stats = StatsManager::new();
        assert!(stats.cleanup_task_is_stopped());

        tokio::runtime::Builder::new_current_thread()
            .enable_time()
            .build()
            .unwrap()
            .block_on(async {
                stats.start_cleanup_task();
                assert!(!stats.cleanup_task_is_stopped());
                stats.stop_cleanup_task().await;
            });

        assert!(stats.cleanup_task_is_stopped());
    }

    #[test]
    fn cleanup_task_restarts_after_its_runtime_stops() {
        let first_runtime = tokio::runtime::Builder::new_current_thread()
            .enable_time()
            .build()
            .unwrap();
        let stats = first_runtime.block_on(async {
            let stats = StatsManager::new();
            assert!(!stats.cleanup_task_is_stopped());
            stats
        });
        drop(first_runtime);
        assert!(
            stats
                .cleanup_task
                .lock()
                .unwrap()
                .as_ref()
                .unwrap()
                .is_finished()
        );

        tokio::runtime::Builder::new_current_thread()
            .enable_time()
            .build()
            .unwrap()
            .block_on(async {
                stats.start_cleanup_task();
                assert!(
                    !stats
                        .cleanup_task
                        .lock()
                        .unwrap()
                        .as_ref()
                        .unwrap()
                        .is_finished()
                );
                stats.stop_cleanup_task().await;
            });
    }

    #[tokio::test]
    async fn test_label_set() {
        let labels = LabelSet::new()
            .with_label("peer_id", "peer1")
            .with_label("method", "ping");

        assert_eq!(labels.to_key(), "method=ping,peer_id=peer1");

        let instance_labels = LabelSet::new()
            .with_label_type(LabelType::NetworkName("default".to_string()))
            .with_label_type(LabelType::ToInstanceId(
                "87ede5a2-9c3d-492d-9bbe-989b9d07e742".to_string(),
            ))
            .with_label_type(LabelType::FromInstanceId(
                "9b7d4368-b688-4897-a1f4-b6caaed9e8a6".to_string(),
            ));

        assert_eq!(
            instance_labels.to_key(),
            "from_instance_id=9b7d4368-b688-4897-a1f4-b6caaed9e8a6,network_name=default,to_instance_id=87ede5a2-9c3d-492d-9bbe-989b9d07e742"
        );
    }

    #[tokio::test]
    async fn test_unsafe_counter() {
        let counter = UnsafeCounter::new();

        unsafe {
            assert_eq!(counter.get(), 0);
            counter.inc();
            assert_eq!(counter.get(), 1);
            counter.add(5);
            assert_eq!(counter.get(), 6);
            counter.set(10);
            assert_eq!(counter.get(), 10);
            counter.reset();
            assert_eq!(counter.get(), 0);
        }
    }

    #[tokio::test]
    async fn test_stats_manager() {
        let stats = StatsManager::new();

        // Test simple counter
        let counter1 = stats.get_simple_counter(MetricName::PeerRpcClientTx);
        counter1.inc();
        counter1.add(5);

        // Test counter with labels
        let labels = LabelSet::new()
            .with_label("peer_id", "peer1")
            .with_label("method", "ping");
        let counter2 = stats.get_counter(MetricName::PeerRpcClientTx, labels.clone());
        counter2.add(3);

        // Check metrics
        let metrics = stats.get_all_metrics();
        assert_eq!(metrics.len(), 2);

        // Find the simple counter
        let simple_metric = metrics
            .iter()
            .find(|m| m.labels.labels().is_empty())
            .unwrap();
        assert_eq!(simple_metric.name, MetricName::PeerRpcClientTx);
        assert_eq!(simple_metric.value, 6);

        // Find the labeled counter
        let labeled_metric = metrics
            .iter()
            .find(|m| !m.labels.labels().is_empty())
            .unwrap();
        assert_eq!(labeled_metric.name, MetricName::PeerRpcClientTx);
        assert_eq!(labeled_metric.value, 3);
        assert_eq!(labeled_metric.labels, labels);
    }

    #[tokio::test]
    async fn test_prometheus_export() {
        let stats = StatsManager::new();

        let counter1 = stats.get_simple_counter(MetricName::TrafficBytesTx);
        counter1.set(100);

        let labels = LabelSet::new().with_label("status", "success");
        let counter2 = stats.get_counter(MetricName::PeerRpcClientTx, labels);
        counter2.set(50);

        let traffic_labels = LabelSet::new()
            .with_label_type(LabelType::NetworkName("default".to_string()))
            .with_label_type(LabelType::ToInstanceId(
                "87ede5a2-9c3d-492d-9bbe-989b9d07e742".to_string(),
            ));
        let counter3 = stats.get_counter(MetricName::TrafficBytesTxByInstance, traffic_labels);
        counter3.set(25);

        let prometheus_output = stats.export_prometheus();

        assert!(prometheus_output.contains("# TYPE peer_rpc_client_tx counter"));
        assert!(prometheus_output.contains("peer_rpc_client_tx{status=\"success\"} 50"));
        assert!(prometheus_output.contains("# TYPE traffic_bytes_tx counter"));
        assert!(prometheus_output.contains("traffic_bytes_tx 100"));
        assert!(prometheus_output.contains("# TYPE traffic_bytes_tx_by_instance counter"));
        assert!(prometheus_output.contains(
            "traffic_bytes_tx_by_instance{network_name=\"default\",to_instance_id=\"87ede5a2-9c3d-492d-9bbe-989b9d07e742\"} 25"
        ));
    }

    #[tokio::test]
    async fn test_get_metric() {
        let stats = StatsManager::new();

        let labels = LabelSet::new().with_label("peer", "test");
        let counter = stats.get_counter(MetricName::PeerRpcClientTx, labels.clone());
        counter.set(42);

        let metric = stats
            .get_metric(MetricName::PeerRpcClientTx, &labels)
            .unwrap();
        assert_eq!(metric.value, 42);

        let non_existent = stats.get_metric(MetricName::PeerRpcErrors, &LabelSet::new());
        assert!(non_existent.is_none());
    }

    #[tokio::test]
    async fn test_metrics_by_prefix() {
        let stats = StatsManager::new();

        stats
            .get_simple_counter(MetricName::PeerRpcClientTx)
            .set(10);
        stats.get_simple_counter(MetricName::PeerRpcErrors).set(2);
        stats
            .get_simple_counter(MetricName::TrafficBytesTx)
            .set(100);

        let rpc_metrics = stats.get_metrics_by_prefix("peer_rpc");
        assert_eq!(rpc_metrics.len(), 2);

        let traffic_metrics = stats.get_metrics_by_prefix("traffic_");
        assert_eq!(traffic_metrics.len(), 1);
    }

    #[tokio::test]
    async fn test_cleanup_mechanism() {
        let stats = StatsManager::new();

        // 创建一些计数器
        let counter1 = stats.get_simple_counter(MetricName::PeerRpcClientTx);
        counter1.set(10);

        let labels = LabelSet::new().with_label("test", "value");
        let counter2 = stats.get_counter(MetricName::TrafficBytesTx, labels);
        counter2.set(20);

        // 验证计数器存在
        assert_eq!(stats.metric_count(), 2);

        // 注意：实际的清理测试需要等待3分钟，这在单元测试中不现实
        // 这里我们只验证清理机制的基本结构是否正确
        // 清理逻辑在后台线程中运行，会自动删除超过3分钟未更新的条目

        // 验证计数器仍然可以正常工作
        counter1.inc();
        assert_eq!(counter1.get(), 11);

        counter2.add(5);
        assert_eq!(counter2.get(), 25);
    }

    #[tokio::test]
    async fn test_cleanup_keeps_metrics_with_live_handles() {
        let stats = StatsManager::new();
        let counter = stats.get_simple_counter(MetricName::TrafficBytesForwarded);
        counter.set(1);

        let cutoff_time = Instant::now().checked_add(Duration::from_secs(1)).unwrap();
        stats
            .counters
            .retain(|_, metric_data: &mut Arc<MetricData>| {
                Arc::strong_count(metric_data) > 1
                    || unsafe { metric_data.get_last_updated() > cutoff_time }
            });

        assert_eq!(stats.metric_count(), 1);
        assert_eq!(stats.get_all_metrics().len(), 1);

        drop(counter);
        stats
            .counters
            .retain(|_, metric_data: &mut Arc<MetricData>| {
                Arc::strong_count(metric_data) > 1
                    || unsafe { metric_data.get_last_updated() > cutoff_time }
            });
        assert_eq!(stats.metric_count(), 0);
    }

    #[tokio::test]
    async fn test_prometheus_export_format() {
        let stats_manager = StatsManager::new();

        // Create test metrics
        let counter = stats_manager.get_counter(
            MetricName::PeerRpcClientTx,
            LabelSet::new()
                .with_label_type(LabelType::SrcPeerId(123))
                .with_label_type(LabelType::ServiceName("test".to_string())),
        );
        counter.add(42);

        // Export to Prometheus format
        let prometheus_text = stats_manager.export_prometheus();

        println!("{}", prometheus_text);

        // Verify the format
        assert!(prometheus_text.contains("peer_rpc_client_tx"));
        assert!(prometheus_text.contains("42"));
        assert!(prometheus_text.contains("src_peer_id=\"123\""));
        assert!(prometheus_text.contains("service_name=\"test\""));
    }
}
