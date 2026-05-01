//! This example demonstrates how to make a QUIC connection that ignores the server certificate.
//!
//! Checkout the `README.md` for guidance.

use super::{FromUrl, IpVersion, Tunnel, TunnelConnector, TunnelError, TunnelListener};
use crate::common::global_ctx::ArcGlobalCtx;
use crate::tunnel::common::bind;
use crate::tunnel::{
    TunnelInfo,
    common::{FramedReader, FramedWriter, TunnelWrapper},
};
use anyhow::Context;
use derivative::Derivative;
use derive_more::{Deref, DerefMut};
use parking_lot::RwLock;
use quinn::{
    ClientConfig, ConnectError, Connection, Endpoint, EndpointConfig, ServerConfig,
    TransportConfig, congestion::BbrConfig, default_runtime,
};
use std::net::{Ipv4Addr, Ipv6Addr};
use std::sync::OnceLock;
use std::{net::SocketAddr, sync::Arc, time::Duration};
use tokio::net::UdpSocket;

// region config
pub fn transport_config() -> Arc<TransportConfig> {
    let mut config = TransportConfig::default();

    config
        .max_concurrent_bidi_streams(u8::MAX.into())
        .max_concurrent_uni_streams(0u8.into())
        .keep_alive_interval(Some(Duration::from_secs(5)))
        .initial_mtu(1200)
        .min_mtu(1200)
        .enable_segmentation_offload(true)
        .congestion_controller_factory(Arc::new(BbrConfig::default()));

    Arc::new(config)
}

pub fn server_config() -> ServerConfig {
    let mut config = quinn_plaintext::server_config();
    config.transport_config(transport_config());
    config
}

pub fn client_config() -> ClientConfig {
    let mut config = quinn_plaintext::client_config();
    config.transport_config(transport_config());
    config
}

pub fn endpoint_config() -> EndpointConfig {
    let mut config = EndpointConfig::default();
    config.max_udp_payload_size(1200).unwrap();
    config
}
//endregion

//region rw pool
#[derive(Derivative)]
#[derivative(Default(bound = ""))]
#[derive(Debug, Deref, DerefMut)]
struct RwPoolInner<Item> {
    #[deref]
    #[deref_mut]
    pool: Vec<Item>,
    enabled: bool,
}

#[derive(Debug)]
struct RwPool<Item> {
    ephemeral: RwLock<RwPoolInner<Item>>,
    persistent: RwLock<RwPoolInner<Item>>,
    capacity: usize,
}

impl<Item> RwPool<Item> {
    fn new(capacity: usize) -> Self {
        Self {
            ephemeral: RwLock::new(RwPoolInner::default()),
            persistent: RwLock::new(RwPoolInner::default()),
            capacity,
        }
    }

    /// return the capacity of the ephemeral pool;
    /// if `ephemeral` or `persistent` is None, read lock `self`'s pool
    fn capacity(
        &self,
        ephemeral: Option<&RwPoolInner<Item>>,
        persistent: Option<&RwPoolInner<Item>>,
    ) -> usize {
        let guard;
        let ephemeral = if let Some(ephemeral) = ephemeral {
            ephemeral
        } else {
            guard = self.ephemeral.read();
            &guard
        };

        let guard;
        let persistent = if let Some(persistent) = persistent {
            persistent
        } else {
            guard = self.persistent.read();
            &guard
        };

        (self.capacity * ephemeral.enabled as usize).saturating_sub(persistent.len())
    }

    fn is_full(&self) -> bool {
        let pool = self.ephemeral.read();
        pool.len() >= self.capacity(Some(&pool), None)
    }

    fn is_enabled(&self) -> bool {
        self.ephemeral.read().enabled
    }

    fn enable(&self) {
        self.ephemeral.write().enabled = true;
        self.resize();
    }

    fn disable(&self) {
        self.ephemeral.write().enabled = false;
        self.resize();
    }

    /// push an item to the persistent pool
    fn push(&self, item: Item) {
        self.persistent.write().push(item);
        self.resize();
    }

    fn len(&self) -> usize {
        self.persistent.read().len() + self.ephemeral.read().len()
    }

    /// try to push an item to the ephemeral pool, return the item if full
    fn try_push(&self, item: Item) -> Option<Item> {
        let mut pool = self.ephemeral.write();
        if pool.len() < self.capacity(Some(&pool), None) {
            pool.push(item);
            return None;
        }
        Some(item)
    }

    fn resize(&self) {
        let resize = {
            let pool = self.ephemeral.read();
            pool.capacity() != self.capacity(Some(&pool), None)
        };
        if resize {
            let mut pool = self.ephemeral.write();
            let capacity = self.capacity(Some(&pool), None);
            pool.reserve_exact(capacity);
            pool.truncate(capacity);
            pool.shrink_to(capacity);
        }
    }

    fn with_iter<F, R>(&self, f: F) -> R
    where
        F: FnOnce(&mut dyn Iterator<Item = &Item>) -> R,
    {
        let ephemeral = self.ephemeral.read();
        let persistent = self.persistent.read();
        f(&mut persistent.iter().chain(ephemeral.iter()))
    }
}

impl RwPool<Endpoint> {
    fn retain_endpoints<F>(&self, mut keep: F) -> usize
    where
        F: FnMut(&Endpoint) -> bool,
    {
        let persistent_removed = {
            let mut persistent = self.persistent.write();
            let before = persistent.len();
            persistent.retain(|endpoint| keep(endpoint));
            before - persistent.len()
        };

        let ephemeral_removed = {
            let mut ephemeral = self.ephemeral.write();
            let before = ephemeral.len();
            ephemeral.retain(|endpoint| keep(endpoint));
            before - ephemeral.len()
        };

        let removed = persistent_removed + ephemeral_removed;
        if removed > 0 {
            self.resize();
        }
        removed
    }

    fn remove_by_local_addr(&self, local_addr: SocketAddr) -> usize {
        self.retain_endpoints(|endpoint| endpoint.local_addr().ok() != Some(local_addr))
    }

    fn contains_local_addr(&self, local_addr: SocketAddr) -> bool {
        self.with_iter(|iter| {
            for endpoint in iter {
                if endpoint.local_addr().ok() == Some(local_addr) {
                    return true;
                }
            }
            false
        })
    }
}
//endregion

//region endpoint manager
#[derive(Debug)]
pub struct QuicEndpointManager {
    ipv4: RwPool<Endpoint>,
    ipv6: RwPool<Endpoint>,
    both: RwPool<Endpoint>,
}

static QUIC_ENDPOINT_MANAGER: OnceLock<QuicEndpointManager> = OnceLock::new();

impl QuicEndpointManager {
    fn try_create(addr: SocketAddr, dual_stack: bool) -> Result<Endpoint, TunnelError> {
        let socket = bind::<UdpSocket>()
            .addr(addr)
            .only_v6(addr.is_ipv6() && !dual_stack)
            .call()?;
        let runtime = default_runtime().ok_or(TunnelError::InternalError(
            "no async runtime found".to_owned(),
        ))?;
        let mut endpoint = Endpoint::new_with_abstract_socket(
            endpoint_config(),
            None,
            runtime.wrap_udp_socket(socket.into_std()?)?,
            runtime,
        )?;
        endpoint.set_default_client_config(client_config());
        Ok(endpoint)
    }

    fn create<F>(
        &self,
        mut selector: F,
    ) -> Result<(&RwPool<Endpoint>, Option<Endpoint>), TunnelError>
    where
        F: FnMut(&QuicEndpointManager) -> (&RwPool<Endpoint>, Option<(SocketAddr, bool)>),
    {
        loop {
            let (pool, r) = selector(self);
            let Some((addr, dual_stack)) = r else {
                return Ok((pool, None));
            };

            let endpoint = Self::try_create(addr, dual_stack);
            if let Err(error) = endpoint.as_ref()
                && dual_stack
            {
                tracing::warn!(?error, "create dual stack quic endpoint failed");
                self.both.disable();
                self.ipv4.enable();
                self.ipv6.enable();
                continue;
            }

            return Ok((pool, Some(endpoint?)));
        }
    }
}

impl QuicEndpointManager {
    fn new(capacity: usize) -> Self {
        let ipv4 = RwPool::new(capacity.div_ceil(2));
        let ipv6 = RwPool::new(capacity.div_ceil(2));
        let both = RwPool::new(capacity);
        both.enable();
        Self { ipv4, ipv6, both }
    }

    fn load(global_ctx: &ArcGlobalCtx) -> &Self {
        let capacity = global_ctx
            .config
            .get_flags()
            .multi_thread
            .then(std::thread::available_parallelism)
            .and_then(|r| r.ok())
            .map(|n| n.get())
            .unwrap_or(1);

        let mgr = QUIC_ENDPOINT_MANAGER.get();
        match mgr {
            Some(mgr) => {
                for pool in [&mgr.ipv4, &mgr.ipv6, &mgr.both] {
                    pool.resize();
                }
            }
            None => {
                let _ = QUIC_ENDPOINT_MANAGER.set(Self::new(capacity));
            }
        }

        QUIC_ENDPOINT_MANAGER.get().unwrap()
    }

    fn client_pool(&self, ip_version: IpVersion) -> &RwPool<Endpoint> {
        let dual_stack = self.both.is_enabled();
        match ip_version {
            IpVersion::V4 if !dual_stack => &self.ipv4,
            _ => {
                if dual_stack {
                    &self.both
                } else {
                    &self.ipv6
                }
            }
        }
    }

    /// Get a QUIC endpoint to be used as a server
    ///
    /// # Arguments
    /// * `addr`: listen address
    fn server(global_ctx: &ArcGlobalCtx, addr: SocketAddr) -> Result<Endpoint, TunnelError> {
        let mgr = Self::load(global_ctx);

        let (pool, endpoint) = mgr.create(|mgr| {
            let dual_stack = addr.ip() == Ipv6Addr::UNSPECIFIED && mgr.both.is_enabled();
            let pool = if addr.is_ipv4() {
                &mgr.ipv4
            } else if dual_stack {
                &mgr.both
            } else {
                &mgr.ipv6
            };
            (pool, Some((addr, dual_stack)))
        })?;

        let endpoint = endpoint.expect("server endpoint creation should not return None");
        endpoint.set_server_config(Some(server_config()));
        pool.push(endpoint.clone());

        Ok(endpoint)
    }

    fn client_endpoint(&self, ip_version: IpVersion) -> Result<Endpoint, TunnelError> {
        let (pool, endpoint) = self.create(|mgr| {
            let dual_stack = mgr.both.is_enabled();
            let (pool, addr) = match ip_version {
                IpVersion::V4 if !dual_stack => (&mgr.ipv4, (Ipv4Addr::UNSPECIFIED, 0).into()),
                _ => {
                    let pool = if dual_stack { &mgr.both } else { &mgr.ipv6 };
                    (pool, (Ipv6Addr::UNSPECIFIED, 0).into())
                }
            };
            if pool.is_full() {
                (pool, None)
            } else {
                (pool, Some((addr, dual_stack)))
            }
        })?;

        if let Some(endpoint) = endpoint {
            pool.try_push(endpoint);
        }

        Ok(pool.with_iter(|iter| iter.min_by_key(|e| e.open_connections()).unwrap().clone()))
    }

    fn remove_endpoint(&self, endpoint: &Endpoint) -> usize {
        let Ok(local_addr) = endpoint.local_addr() else {
            return 0;
        };
        self.remove_endpoint_by_local_addr(local_addr)
    }

    fn remove_endpoint_by_local_addr(&self, local_addr: SocketAddr) -> usize {
        [&self.ipv4, &self.ipv6, &self.both]
            .into_iter()
            .map(|pool| pool.remove_by_local_addr(local_addr))
            .sum()
    }

    fn contains_local_addr(&self, local_addr: SocketAddr) -> bool {
        [&self.ipv4, &self.ipv6, &self.both]
            .into_iter()
            .any(|pool| pool.contains_local_addr(local_addr))
    }

    async fn connect(
        global_ctx: &ArcGlobalCtx,
        addr: SocketAddr,
    ) -> Result<(Endpoint, Connection), TunnelError> {
        let ip_version = if addr.ip().is_ipv4() {
            IpVersion::V4
        } else {
            IpVersion::V6
        };
        Self::load(global_ctx)
            .connect_with_ip_version(addr, ip_version)
            .await
    }

    async fn connect_with_ip_version(
        &self,
        addr: SocketAddr,
        ip_version: IpVersion,
    ) -> Result<(Endpoint, Connection), TunnelError> {
        let max_endpoint_stopping_retries = self.client_pool(ip_version).len().saturating_add(1);
        let mut endpoint_stopping_retries = 0;

        loop {
            let endpoint = self.client_endpoint(ip_version)?;
            let connecting = match endpoint.connect(addr, "localhost") {
                Ok(connecting) => connecting,
                Err(ConnectError::EndpointStopping) => {
                    let local_addr = endpoint.local_addr().ok();
                    let removed = self.remove_endpoint(&endpoint);
                    endpoint_stopping_retries += 1;
                    tracing::warn!(
                        ?addr,
                        ?local_addr,
                        removed,
                        "removed stopped quic endpoint and retry connect"
                    );
                    if endpoint_stopping_retries > max_endpoint_stopping_retries {
                        return Err(anyhow::Error::new(ConnectError::EndpointStopping)
                            .context(format!("failed to create connection to {}", addr))
                            .into());
                    }
                    continue;
                }
                Err(e) => {
                    return Err(anyhow::Error::new(e)
                        .context(format!("failed to create connection to {}", addr))
                        .into());
                }
            };
            let connection = connecting
                .await
                .with_context(|| format!("failed to connect to {}", addr))?;

            return Ok((endpoint, connection));
        }
    }
}
//endregion

struct ConnWrapper {
    conn: Connection,
}

impl Drop for ConnWrapper {
    fn drop(&mut self) {
        self.conn.close(0u32.into(), b"done");
    }
}

pub struct QuicTunnelListener {
    addr: url::Url,
    global_ctx: ArcGlobalCtx,
    endpoint: Option<Endpoint>,
}

impl QuicTunnelListener {
    pub fn new(addr: url::Url, global_ctx: ArcGlobalCtx) -> Self {
        QuicTunnelListener {
            addr,
            global_ctx,
            endpoint: None,
        }
    }

    async fn do_accept(&self) -> Result<Box<dyn Tunnel>, super::TunnelError> {
        // accept a single connection
        let conn = self
            .endpoint
            .as_ref()
            .unwrap()
            .accept()
            .await
            .ok_or_else(|| anyhow::anyhow!("accept failed, no incoming"))?;
        let conn = conn.await.with_context(|| "accept connection failed")?;
        let remote_addr = conn.remote_address();
        let (w, r) = conn.accept_bi().await.with_context(|| "accept_bi failed")?;

        let arc_conn = Arc::new(ConnWrapper { conn });

        let info = TunnelInfo {
            tunnel_type: "quic".to_owned(),
            local_addr: Some(self.local_url().into()),
            remote_addr: Some(
                super::build_url_from_socket_addr(&remote_addr.to_string(), "quic").into(),
            ),
            resolved_remote_addr: Some(
                super::build_url_from_socket_addr(&remote_addr.to_string(), "quic").into(),
            ),
        };

        Ok(Box::new(TunnelWrapper::new(
            FramedReader::new_with_associate_data(r, 2000, Some(Box::new(arc_conn.clone()))),
            FramedWriter::new_with_associate_data(w, Some(Box::new(arc_conn))),
            Some(info),
        )))
    }
}

impl Drop for QuicTunnelListener {
    fn drop(&mut self) {
        let Some(endpoint) = &self.endpoint else {
            return;
        };
        let Ok(local_addr) = endpoint.local_addr() else {
            return;
        };
        QuicEndpointManager::load(&self.global_ctx).remove_endpoint_by_local_addr(local_addr);
    }
}

#[async_trait::async_trait]
impl TunnelListener for QuicTunnelListener {
    async fn listen(&mut self) -> Result<(), TunnelError> {
        let addr = SocketAddr::from_url(self.addr.clone(), IpVersion::Both).await?;
        let endpoint = QuicEndpointManager::server(&self.global_ctx, addr)?;
        self.addr
            .set_port(Some(endpoint.local_addr()?.port()))
            .unwrap();
        self.endpoint = Some(endpoint);

        Ok(())
    }

    async fn accept(&mut self) -> Result<Box<dyn Tunnel>, super::TunnelError> {
        loop {
            match self.do_accept().await {
                Ok(ret) => return Ok(ret),
                Err(e) => {
                    tracing::warn!(?e, "accept fail");
                    tokio::time::sleep(Duration::from_millis(1)).await;
                }
            }
        }
    }

    fn local_url(&self) -> url::Url {
        self.addr.clone()
    }
}

pub struct QuicTunnelConnector {
    addr: url::Url,
    global_ctx: ArcGlobalCtx,
    ip_version: IpVersion,
    resolved_addr: Option<SocketAddr>,
}

impl QuicTunnelConnector {
    pub fn new(addr: url::Url, global_ctx: ArcGlobalCtx) -> Self {
        QuicTunnelConnector {
            addr,
            global_ctx,
            ip_version: IpVersion::Both,
            resolved_addr: None,
        }
    }
}

#[async_trait::async_trait]
impl TunnelConnector for QuicTunnelConnector {
    async fn connect(&mut self) -> Result<Box<dyn Tunnel>, TunnelError> {
        let addr = match self.resolved_addr {
            Some(addr) => addr,
            None => SocketAddr::from_url(self.addr.clone(), self.ip_version).await?,
        };
        let (endpoint, connection) = QuicEndpointManager::connect(&self.global_ctx, addr).await?;

        let local_addr = endpoint.local_addr()?;

        let (w, r) = connection
            .open_bi()
            .await
            .with_context(|| "open_bi failed")?;

        let info = TunnelInfo {
            tunnel_type: "quic".to_owned(),
            local_addr: Some(
                super::build_url_from_socket_addr(&local_addr.to_string(), "quic").into(),
            ),
            remote_addr: Some(self.addr.clone().into()),
            resolved_remote_addr: Some(
                super::build_url_from_socket_addr(&connection.remote_address().to_string(), "quic")
                    .into(),
            ),
        };

        let arc_conn = Arc::new(ConnWrapper { conn: connection });
        Ok(Box::new(TunnelWrapper::new(
            FramedReader::new_with_associate_data(r, 4500, Some(Box::new(arc_conn.clone()))),
            FramedWriter::new_with_associate_data(w, Some(Box::new(arc_conn))),
            Some(info),
        )))
    }

    fn remote_url(&self) -> url::Url {
        self.addr.clone()
    }

    fn set_ip_version(&mut self, ip_version: IpVersion) {
        self.ip_version = ip_version;
    }

    fn set_resolved_addr(&mut self, addr: SocketAddr) {
        self.resolved_addr = Some(addr);
    }
}

#[cfg(test)]
mod tests {
    use crate::common::global_ctx::tests::get_mock_global_ctx_with_network;
    use crate::tunnel::{
        TunnelConnector,
        common::tests::{_tunnel_bench, _tunnel_pingpong},
    };
    use std::sync::LazyLock;
    use tokio::runtime::{Builder, Runtime};

    use super::*;

    // Shared runtime for all tests to avoid endpoint invalidation across runtimes
    static RUNTIME: LazyLock<Runtime> =
        LazyLock::new(|| Builder::new_multi_thread().enable_all().build().unwrap());

    fn global_ctx() -> ArcGlobalCtx {
        let identity = crate::common::config::NetworkIdentity::default();
        get_mock_global_ctx_with_network(Some(identity))
    }

    fn stopped_client_endpoint() -> (Endpoint, SocketAddr) {
        let rt = Builder::new_current_thread().enable_all().build().unwrap();
        let endpoint = rt.block_on(async {
            QuicEndpointManager::try_create((Ipv4Addr::UNSPECIFIED, 0).into(), false).unwrap()
        });
        let local_addr = endpoint.local_addr().unwrap();
        drop(rt);
        assert!(matches!(
            endpoint.connect("127.0.0.1:1".parse().unwrap(), "localhost"),
            Err(ConnectError::EndpointStopping)
        ));
        (endpoint, local_addr)
    }

    #[test]
    fn quic_pingpong() {
        RUNTIME.block_on(quic_pingpong_impl())
    }
    async fn quic_pingpong_impl() {
        let listener = QuicTunnelListener::new("quic://[::]:21011".parse().unwrap(), global_ctx());
        let connector =
            QuicTunnelConnector::new("quic://127.0.0.1:21011".parse().unwrap(), global_ctx());
        _tunnel_pingpong(listener, connector).await
    }

    #[test]
    fn quic_bench() {
        RUNTIME.block_on(quic_bench_impl())
    }
    async fn quic_bench_impl() {
        let listener = QuicTunnelListener::new("quic://[::]:21012".parse().unwrap(), global_ctx());
        let connector =
            QuicTunnelConnector::new("quic://127.0.0.1:21012".parse().unwrap(), global_ctx());
        _tunnel_bench(listener, connector).await
    }

    #[test]
    fn ipv6_pingpong() {
        RUNTIME.block_on(ipv6_pingpong_impl())
    }
    async fn ipv6_pingpong_impl() {
        let listener = QuicTunnelListener::new("quic://[::1]:31015".parse().unwrap(), global_ctx());
        let connector =
            QuicTunnelConnector::new("quic://[::1]:31015".parse().unwrap(), global_ctx());
        _tunnel_pingpong(listener, connector).await
    }

    #[test]
    fn ipv6_domain_pingpong() {
        RUNTIME.block_on(ipv6_domain_pingpong_impl())
    }
    async fn ipv6_domain_pingpong_impl() {
        let listener = QuicTunnelListener::new("quic://[::1]:31016".parse().unwrap(), global_ctx());
        let mut connector = QuicTunnelConnector::new(
            "quic://test.easytier.top:31016".parse().unwrap(),
            global_ctx(),
        );
        connector.set_ip_version(IpVersion::V6);
        _tunnel_pingpong(listener, connector).await;

        let listener =
            QuicTunnelListener::new("quic://127.0.0.1:31016".parse().unwrap(), global_ctx());
        let mut connector = QuicTunnelConnector::new(
            "quic://test.easytier.top:31016".parse().unwrap(),
            global_ctx(),
        );
        connector.set_ip_version(IpVersion::V4);
        _tunnel_pingpong(listener, connector).await;
    }

    #[test]
    fn alloc_port() {
        RUNTIME.block_on(alloc_port_impl())
    }
    async fn alloc_port_impl() {
        // v4
        let mut listener =
            QuicTunnelListener::new("quic://0.0.0.0:0".parse().unwrap(), global_ctx());
        listener.listen().await.unwrap();
        let port = listener.local_url().port().unwrap();
        assert!(port > 0);

        // v6
        let mut listener = QuicTunnelListener::new("quic://[::]:0".parse().unwrap(), global_ctx());
        listener.listen().await.unwrap();
        let port = listener.local_url().port().unwrap();
        assert!(port > 0);
    }

    #[test]
    fn listener_drop_removes_persistent_endpoint() {
        RUNTIME.block_on(listener_drop_removes_persistent_endpoint_impl())
    }
    async fn listener_drop_removes_persistent_endpoint_impl() {
        let global_ctx = global_ctx();
        let endpoint_addr = {
            let mut listener =
                QuicTunnelListener::new("quic://127.0.0.1:0".parse().unwrap(), global_ctx.clone());
            listener.listen().await.unwrap();
            let endpoint_addr = listener.endpoint.as_ref().unwrap().local_addr().unwrap();
            assert!(QuicEndpointManager::load(&global_ctx).contains_local_addr(endpoint_addr));
            endpoint_addr
        };

        assert!(!QuicEndpointManager::load(&global_ctx).contains_local_addr(endpoint_addr));
    }

    #[test]
    fn connect_removes_stopped_endpoints_and_retries() {
        let (stopped_endpoint_a, stopped_addr_a) = stopped_client_endpoint();
        let (stopped_endpoint_b, stopped_addr_b) = stopped_client_endpoint();

        RUNTIME.block_on(async move {
            let mgr = QuicEndpointManager::new(2);
            mgr.both.push(stopped_endpoint_a);
            mgr.both.push(stopped_endpoint_b);
            assert!(mgr.contains_local_addr(stopped_addr_a));
            assert!(mgr.contains_local_addr(stopped_addr_b));

            let err = mgr
                .connect_with_ip_version("127.0.0.1:0".parse().unwrap(), IpVersion::V4)
                .await
                .unwrap_err();
            let err = format!("{:?}", err);
            assert!(
                err.contains("invalid remote address"),
                "unexpected error: {}",
                err
            );
            assert!(!mgr.contains_local_addr(stopped_addr_a));
            assert!(!mgr.contains_local_addr(stopped_addr_b));
        });
    }

    #[test]
    fn invalid_peer_addr() {
        RUNTIME.block_on(invalid_peer_addr_impl())
    }
    async fn invalid_peer_addr_impl() {
        let mut connector =
            QuicTunnelConnector::new("quic://127.0.0.1:0".parse().unwrap(), global_ctx());
        let err = format!("{:?}", connector.connect().await.unwrap_err());
        assert!(
            err.contains("invalid remote address"),
            "unexpected error: {}",
            err
        );
    }
}
