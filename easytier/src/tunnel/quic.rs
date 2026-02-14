//! This example demonstrates how to make a QUIC connection that ignores the server certificate.
//!
//! Checkout the `README.md` for guidance.

use super::{
    check_scheme_and_get_socket_addr, IpVersion, Tunnel, TunnelConnector, TunnelError,
    TunnelListener,
};
use crate::common::global_ctx::ArcGlobalCtx;
use crate::tunnel::{
    common::{setup_sokcet2, FramedReader, FramedWriter, TunnelWrapper},
    TunnelInfo,
};
use anyhow::Context;
use derivative::Derivative;
use derive_more::{Deref, DerefMut};
use parking_lot::RwLock;
use quinn::{
    congestion::BbrConfig, default_runtime, ClientConfig, Connection, Endpoint, EndpointConfig,
    ServerConfig, TransportConfig,
};
use std::net::{Ipv4Addr, Ipv6Addr};
use std::sync::OnceLock;
use std::{net::SocketAddr, sync::Arc, time::Duration};

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
    config.max_udp_payload_size(65527).unwrap();
    config
}

struct ConnWrapper {
    conn: Connection,
}

impl Drop for ConnWrapper {
    fn drop(&mut self) {
        self.conn.close(0u32.into(), b"done");
    }
}

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

#[derive(Debug)]
pub struct QuicEndpointManager {
    ipv4: RwPool<Endpoint>,
    ipv6: RwPool<Endpoint>,
    both: RwPool<Endpoint>,
}

static QUIC_ENDPOINT_MANAGER: OnceLock<QuicEndpointManager> = OnceLock::new();

impl QuicEndpointManager {
    fn try_create(addr: SocketAddr, dual_stack: bool) -> std::io::Result<Endpoint> {
        let socket = socket2::Socket::new(
            socket2::Domain::for_address(addr),
            socket2::Type::DGRAM,
            Some(socket2::Protocol::UDP),
        )?;
        setup_sokcet2(&socket, &addr).map_err(std::io::Error::other)?;
        if dual_stack {
            socket.set_only_v6(false)?;
        }
        let socket = std::net::UdpSocket::from(socket);
        let runtime = default_runtime().ok_or(std::io::Error::other("no async runtime found"))?;
        let mut endpoint = Endpoint::new_with_abstract_socket(
            endpoint_config(),
            None,
            runtime.wrap_udp_socket(socket)?,
            runtime,
        )?;
        endpoint.set_default_client_config(client_config());
        Ok(endpoint)
    }

    fn create<F>(&self, mut selector: F) -> std::io::Result<(&RwPool<Endpoint>, Option<Endpoint>)>
    where
        F: FnMut(&QuicEndpointManager) -> (&RwPool<Endpoint>, Option<(SocketAddr, bool)>),
    {
        loop {
            let (pool, r) = selector(self);
            let Some((addr, dual_stack)) = r else {
                return Ok((pool, None));
            };

            let endpoint = Self::try_create(addr, dual_stack);
            if let Err(e) = endpoint.as_ref() {
                if dual_stack {
                    tracing::warn!("create dual stack quic endpoint failed: {:?}", e);
                    self.both.disable();
                    self.ipv4.enable();
                    self.ipv6.enable();
                    continue;
                }
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

    /// Get a QUIC endpoint to be used as a server
    ///
    /// # Arguments
    /// * `addr`: listen address
    fn server(global_ctx: &ArcGlobalCtx, addr: SocketAddr) -> std::io::Result<Endpoint> {
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

    /// Get a quic endpoint to be used as a client
    ///
    /// # Arguments
    /// * `ip_version`: the IP version of the remote address
    fn client(global_ctx: &ArcGlobalCtx, ip_version: IpVersion) -> std::io::Result<Endpoint> {
        let mgr = Self::load(global_ctx);

        let (pool, endpoint) = mgr.create(|mgr| {
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

    async fn connect(
        global_ctx: &ArcGlobalCtx,
        addr: SocketAddr,
    ) -> std::io::Result<(Endpoint, Connection)> {
        let ip_version = if addr.ip().is_ipv4() {
            IpVersion::V4
        } else {
            IpVersion::V6
        };
        let endpoint = Self::client(global_ctx, ip_version)?;
        let connection = endpoint
            .connect(addr, "localhost")
            .map_err(std::io::Error::other)?
            .await?;

        Ok((endpoint, connection))
    }
}

pub struct QUICTunnelListener {
    addr: url::Url,
    global_ctx: ArcGlobalCtx,
    endpoint: Option<Endpoint>,
}

impl QUICTunnelListener {
    pub fn new(addr: url::Url, global_ctx: ArcGlobalCtx) -> Self {
        QUICTunnelListener {
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
        };

        Ok(Box::new(TunnelWrapper::new(
            FramedReader::new_with_associate_data(r, 2000, Some(Box::new(arc_conn.clone()))),
            FramedWriter::new_with_associate_data(w, Some(Box::new(arc_conn))),
            Some(info),
        )))
    }
}

#[async_trait::async_trait]
impl TunnelListener for QUICTunnelListener {
    async fn listen(&mut self) -> Result<(), TunnelError> {
        let addr =
            check_scheme_and_get_socket_addr::<SocketAddr>(&self.addr, "quic", IpVersion::Both)
                .await?;
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

pub struct QUICTunnelConnector {
    addr: url::Url,
    global_ctx: ArcGlobalCtx,
    ip_version: IpVersion,
}

impl QUICTunnelConnector {
    pub fn new(addr: url::Url, global_ctx: ArcGlobalCtx) -> Self {
        QUICTunnelConnector {
            addr,
            global_ctx,
            ip_version: IpVersion::Both,
        }
    }
}

#[async_trait::async_trait]
impl TunnelConnector for QUICTunnelConnector {
    async fn connect(&mut self) -> Result<Box<dyn Tunnel>, TunnelError> {
        let addr =
            check_scheme_and_get_socket_addr::<SocketAddr>(&self.addr, "quic", self.ip_version)
                .await?;
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
}

#[cfg(test)]
mod tests {
    use crate::common::global_ctx::tests::get_mock_global_ctx_with_network;
    use crate::tunnel::{
        common::tests::{_tunnel_bench, _tunnel_pingpong},
        IpVersion,
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

    #[test]
    fn quic_pingpong() {
        RUNTIME.block_on(quic_pingpong_impl())
    }
    async fn quic_pingpong_impl() {
        let listener = QUICTunnelListener::new("quic://[::]:21011".parse().unwrap(), global_ctx());
        let connector =
            QUICTunnelConnector::new("quic://127.0.0.1:21011".parse().unwrap(), global_ctx());
        _tunnel_pingpong(listener, connector).await
    }

    #[test]
    fn quic_bench() {
        RUNTIME.block_on(quic_bench_impl())
    }
    async fn quic_bench_impl() {
        let listener = QUICTunnelListener::new("quic://[::]:21012".parse().unwrap(), global_ctx());
        let connector =
            QUICTunnelConnector::new("quic://127.0.0.1:21012".parse().unwrap(), global_ctx());
        _tunnel_bench(listener, connector).await
    }

    #[test]
    fn ipv6_pingpong() {
        RUNTIME.block_on(ipv6_pingpong_impl())
    }
    async fn ipv6_pingpong_impl() {
        let listener = QUICTunnelListener::new("quic://[::1]:31015".parse().unwrap(), global_ctx());
        let connector =
            QUICTunnelConnector::new("quic://[::1]:31015".parse().unwrap(), global_ctx());
        _tunnel_pingpong(listener, connector).await
    }

    #[test]
    fn ipv6_domain_pingpong() {
        RUNTIME.block_on(ipv6_domain_pingpong_impl())
    }
    async fn ipv6_domain_pingpong_impl() {
        let listener = QUICTunnelListener::new("quic://[::1]:31016".parse().unwrap(), global_ctx());
        let mut connector = QUICTunnelConnector::new(
            "quic://test.easytier.top:31016".parse().unwrap(),
            global_ctx(),
        );
        connector.set_ip_version(IpVersion::V6);
        _tunnel_pingpong(listener, connector).await;

        let listener =
            QUICTunnelListener::new("quic://127.0.0.1:31016".parse().unwrap(), global_ctx());
        let mut connector = QUICTunnelConnector::new(
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
            QUICTunnelListener::new("quic://0.0.0.0:0".parse().unwrap(), global_ctx());
        listener.listen().await.unwrap();
        let port = listener.local_url().port().unwrap();
        assert!(port > 0);

        // v6
        let mut listener = QUICTunnelListener::new("quic://[::]:0".parse().unwrap(), global_ctx());
        listener.listen().await.unwrap();
        let port = listener.local_url().port().unwrap();
        assert!(port > 0);
    }

    #[test]
    fn invalid_peer_addr() {
        RUNTIME.block_on(invalid_peer_addr_impl())
    }
    async fn invalid_peer_addr_impl() {
        let mut connector =
            QUICTunnelConnector::new("quic://127.0.0.1:0".parse().unwrap(), global_ctx());
        let err = connector.connect().await.unwrap_err();
        assert!(
            err.to_string().contains("invalid remote address"),
            "unexpected error: {:?}",
            err
        );
    }
}
