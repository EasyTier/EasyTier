use std::{
    fmt,
    future::Future,
    net::{Ipv4Addr, SocketAddr},
    pin::Pin,
    sync::Arc,
    time::Duration,
};

use async_trait::async_trait;
use tokio::sync::oneshot;

const UPNP_RENEW_INTERVAL: Duration = Duration::from_secs(240);

pub(crate) trait UdpPortMappingLease: Send + Sync + fmt::Debug {
    fn public_addr_resolved(&self, _mapped_addr: SocketAddr) {}
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UdpPortMappingBackend {
    Igd,
    NatPmp,
}

impl UdpPortMappingBackend {
    pub fn name(self) -> &'static str {
        match self {
            Self::Igd => "igd",
            Self::NatPmp => "nat-pmp",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UdpPortMappingAttemptPhase {
    Discovery,
    Establishment,
}

#[derive(Debug)]
pub struct UdpPortMappingAttemptError {
    phase: UdpPortMappingAttemptPhase,
    source: anyhow::Error,
}

impl UdpPortMappingAttemptError {
    pub fn discovery(source: impl Into<anyhow::Error>) -> Self {
        Self {
            phase: UdpPortMappingAttemptPhase::Discovery,
            source: source.into(),
        }
    }

    pub fn establishment(source: impl Into<anyhow::Error>) -> Self {
        Self {
            phase: UdpPortMappingAttemptPhase::Establishment,
            source: source.into(),
        }
    }

    pub(crate) fn phase(&self) -> UdpPortMappingAttemptPhase {
        self.phase
    }

    pub(crate) fn source(&self) -> &anyhow::Error {
        &self.source
    }
}

impl fmt::Display for UdpPortMappingAttemptError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.source.fmt(f)
    }
}

impl std::error::Error for UdpPortMappingAttemptError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        Some(self.source.as_ref())
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UdpPortMappingEstablished {
    pub local_listener: url::Url,
    pub mapped_listener: url::Url,
    pub backend: UdpPortMappingBackend,
}

#[async_trait]
pub trait ActiveUdpPortMapping: Send + Sync + fmt::Debug {
    fn backend(&self) -> UdpPortMappingBackend;

    fn local_addr(&self) -> SocketAddr;

    fn gateway_external_port(&self) -> u16;

    async fn renew(&self) -> anyhow::Result<()>;

    async fn remove(&self) -> anyhow::Result<()>;
}

pub type UdpPortMappingLifecycle = Pin<Box<dyn Future<Output = ()> + Send + 'static>>;

#[async_trait]
pub trait UdpPortMappingPlatform: Send + Sync + 'static {
    async fn establish_udp_port_mapping(
        &self,
        backend: UdpPortMappingBackend,
        local_listener: &url::Url,
    ) -> Result<Box<dyn ActiveUdpPortMapping>, UdpPortMappingAttemptError>;

    fn spawn_udp_port_mapping_lifecycle(
        &self,
        _local_listener: url::Url,
        lifecycle: UdpPortMappingLifecycle,
    ) {
        tokio::spawn(lifecycle);
    }
}

pub trait UdpPortMappingEventSink: Send + Sync + 'static {
    fn publish_udp_port_mapping_established(&self, _event: UdpPortMappingEstablished) {}
}

impl UdpPortMappingEventSink for () {}

struct ManagedUdpPortMappingLease {
    events: Arc<dyn UdpPortMappingEventSink>,
    local_listener: url::Url,
    backend: UdpPortMappingBackend,
    gateway_external_port: u16,
    stop_tx: Option<oneshot::Sender<()>>,
}

impl fmt::Debug for ManagedUdpPortMappingLease {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("UdpPortMappingLease")
            .field("backend", &self.backend.name())
            .field("gateway_external_port", &self.gateway_external_port)
            .finish()
    }
}

impl Drop for ManagedUdpPortMappingLease {
    fn drop(&mut self) {
        if let Some(stop_tx) = self.stop_tx.take() {
            let _ = stop_tx.send(());
        }
    }
}

impl UdpPortMappingLease for ManagedUdpPortMappingLease {
    fn public_addr_resolved(&self, mapped_addr: SocketAddr) {
        self.events
            .publish_udp_port_mapping_established(UdpPortMappingEstablished {
                local_listener: self.local_listener.clone(),
                mapped_listener: udp_url(mapped_addr),
                backend: self.backend,
            });
        tracing::info!(
            local_listener = %self.local_listener,
            backend = self.backend.name(),
            gateway_external_port = self.gateway_external_port,
            stun_mapped_addr = %mapped_addr,
            "udp public addr resolved after port mapping"
        );
    }
}

pub(crate) async fn start_udp_port_mapping(
    platform: Arc<dyn UdpPortMappingPlatform>,
    events: Arc<dyn UdpPortMappingEventSink>,
    local_listener: &url::Url,
) -> anyhow::Result<Option<Box<dyn UdpPortMappingLease>>> {
    if !should_map_udp_listener(local_listener) {
        return Ok(None);
    }

    let mapping = discover_udp_port_mapping(platform.as_ref(), local_listener).await?;
    let backend = mapping.backend();
    let gateway_external_port = mapping.gateway_external_port();
    tracing::info!(
        %local_listener,
        backend = backend.name(),
        local_addr = %mapping.local_addr(),
        gateway_external_port,
        "udp port mapping established"
    );

    let (stop_tx, stop_rx) = oneshot::channel();
    platform.spawn_udp_port_mapping_lifecycle(
        local_listener.clone(),
        Box::pin(run_udp_port_mapping_lifecycle(
            local_listener.clone(),
            mapping,
            stop_rx,
        )),
    );

    Ok(Some(Box::new(ManagedUdpPortMappingLease {
        events,
        local_listener: local_listener.clone(),
        backend,
        gateway_external_port,
        stop_tx: Some(stop_tx),
    })))
}

async fn discover_udp_port_mapping(
    platform: &dyn UdpPortMappingPlatform,
    local_listener: &url::Url,
) -> anyhow::Result<Box<dyn ActiveUdpPortMapping>> {
    let igd_error = match platform
        .establish_udp_port_mapping(UdpPortMappingBackend::Igd, local_listener)
        .await
    {
        Ok(mapping) => return Ok(mapping),
        Err(error) => error,
    };
    match igd_error.phase() {
        UdpPortMappingAttemptPhase::Discovery => tracing::debug!(
            igd_err = ?igd_error.source(),
            %local_listener,
            "igd gateway discovery failed, retry with nat-pmp"
        ),
        UdpPortMappingAttemptPhase::Establishment => tracing::debug!(
            igd_err = ?igd_error.source(),
            %local_listener,
            "igd udp port mapping failed, retry with nat-pmp"
        ),
    }

    match platform
        .establish_udp_port_mapping(UdpPortMappingBackend::NatPmp, local_listener)
        .await
    {
        Ok(mapping) => Ok(mapping),
        Err(nat_pmp_error) => Err(combined_mapping_error(
            local_listener,
            igd_error,
            nat_pmp_error,
        )),
    }
}

fn combined_mapping_error(
    local_listener: &url::Url,
    igd_error: UdpPortMappingAttemptError,
    nat_pmp_error: UdpPortMappingAttemptError,
) -> anyhow::Error {
    let igd_label = match igd_error.phase() {
        UdpPortMappingAttemptPhase::Discovery => "igd discovery error",
        UdpPortMappingAttemptPhase::Establishment => "igd error",
    };
    let nat_pmp_label = match nat_pmp_error.phase() {
        UdpPortMappingAttemptPhase::Discovery => "nat-pmp discovery error",
        UdpPortMappingAttemptPhase::Establishment => "nat-pmp error",
    };
    anyhow::anyhow!(
        "udp port mapping failed for {local_listener}: {igd_label}: {}; {nat_pmp_label}: {}",
        igd_error.source(),
        nat_pmp_error.source(),
    )
}

async fn run_udp_port_mapping_lifecycle(
    local_listener: url::Url,
    mapping: Box<dyn ActiveUdpPortMapping>,
    mut stop_rx: oneshot::Receiver<()>,
) {
    loop {
        tokio::select! {
            _ = tokio::time::sleep(UPNP_RENEW_INTERVAL) => {
                if let Err(error) = mapping.renew().await {
                    tracing::warn!(
                        err = ?error,
                        %local_listener,
                        backend = mapping.backend().name(),
                        gateway_external_port = mapping.gateway_external_port(),
                        "failed to renew udp port mapping"
                    );
                }
            }
            _ = &mut stop_rx => break,
        }
    }

    if let Err(error) = mapping.remove().await {
        tracing::debug!(
            err = ?error,
            %local_listener,
            backend = mapping.backend().name(),
            gateway_external_port = mapping.gateway_external_port(),
            "failed to remove udp port mapping"
        );
    }
}

pub(crate) fn should_map_udp_listener(local_listener: &url::Url) -> bool {
    if local_listener.scheme() != "udp" {
        return false;
    }

    let Some(host) = listener_ipv4_host(local_listener) else {
        return false;
    };

    if host.is_loopback() || host.is_broadcast() {
        return false;
    }

    host.is_unspecified() || host.is_private() || host.is_link_local()
}

fn listener_ipv4_host(local_listener: &url::Url) -> Option<Ipv4Addr> {
    local_listener.host_str()?.parse().ok()
}

fn udp_url(addr: SocketAddr) -> url::Url {
    let mut url = url::Url::parse("udp://0.0.0.0").expect("static UDP URL should be valid");
    url.set_ip_host(addr.ip())
        .expect("socket IP should be a valid URL host");
    url.set_port(Some(addr.port()))
        .expect("UDP URL should accept a port");
    url
}

#[cfg(test)]
mod tests {
    use std::sync::{
        Mutex,
        atomic::{AtomicUsize, Ordering},
    };

    use super::*;

    #[derive(Debug)]
    struct MockMapping {
        backend: UdpPortMappingBackend,
        removals: Arc<AtomicUsize>,
    }

    #[async_trait]
    impl ActiveUdpPortMapping for MockMapping {
        fn backend(&self) -> UdpPortMappingBackend {
            self.backend
        }

        fn local_addr(&self) -> SocketAddr {
            "192.168.1.5:11010".parse().unwrap()
        }

        fn gateway_external_port(&self) -> u16 {
            41010
        }

        async fn renew(&self) -> anyhow::Result<()> {
            Ok(())
        }

        async fn remove(&self) -> anyhow::Result<()> {
            self.removals.fetch_add(1, Ordering::SeqCst);
            Ok(())
        }
    }

    struct MockPlatform {
        attempts: Mutex<Vec<UdpPortMappingBackend>>,
        igd_phase: Option<UdpPortMappingAttemptPhase>,
        removals: Arc<AtomicUsize>,
    }

    #[async_trait]
    impl UdpPortMappingPlatform for MockPlatform {
        async fn establish_udp_port_mapping(
            &self,
            backend: UdpPortMappingBackend,
            _local_listener: &url::Url,
        ) -> Result<Box<dyn ActiveUdpPortMapping>, UdpPortMappingAttemptError> {
            self.attempts.lock().unwrap().push(backend);
            if backend == UdpPortMappingBackend::Igd
                && let Some(phase) = self.igd_phase
            {
                return Err(match phase {
                    UdpPortMappingAttemptPhase::Discovery => {
                        UdpPortMappingAttemptError::discovery(anyhow::anyhow!("no igd"))
                    }
                    UdpPortMappingAttemptPhase::Establishment => {
                        UdpPortMappingAttemptError::establishment(anyhow::anyhow!("igd denied"))
                    }
                });
            }
            Ok(Box::new(MockMapping {
                backend,
                removals: self.removals.clone(),
            }))
        }
    }

    #[test]
    fn mapping_requires_private_or_unspecified_ipv4_listener() {
        assert!(should_map_udp_listener(
            &"udp://0.0.0.0:11010".parse().unwrap()
        ));
        assert!(should_map_udp_listener(
            &"udp://192.168.1.10:11010".parse().unwrap()
        ));
        assert!(!should_map_udp_listener(
            &"udp://127.0.0.1:11010".parse().unwrap()
        ));
        assert!(!should_map_udp_listener(
            &"udp://8.8.8.8:11010".parse().unwrap()
        ));
        assert!(!should_map_udp_listener(
            &"tcp://0.0.0.0:11010".parse().unwrap()
        ));
    }

    #[tokio::test]
    async fn falls_back_from_igd_to_nat_pmp_and_removes_on_drop() {
        let removals = Arc::new(AtomicUsize::new(0));
        let platform = Arc::new(MockPlatform {
            attempts: Mutex::new(Vec::new()),
            igd_phase: Some(UdpPortMappingAttemptPhase::Discovery),
            removals: removals.clone(),
        });

        let lease = start_udp_port_mapping(
            platform.clone(),
            Arc::new(()),
            &"udp://0.0.0.0:11010".parse().unwrap(),
        )
        .await
        .unwrap()
        .unwrap();
        assert_eq!(
            *platform.attempts.lock().unwrap(),
            vec![UdpPortMappingBackend::Igd, UdpPortMappingBackend::NatPmp]
        );

        drop(lease);
        tokio::time::timeout(Duration::from_secs(1), async {
            while removals.load(Ordering::SeqCst) == 0 {
                tokio::task::yield_now().await;
            }
        })
        .await
        .unwrap();
        assert_eq!(removals.load(Ordering::SeqCst), 1);
    }
}
