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
use derive_more::Deref;
use parking_lot::RwLock;
use quinn::{
    congestion::BbrConfig, AsyncUdpSocket, ClientConfig, Connection, Endpoint, EndpointConfig,
    ServerConfig, TransportConfig,
};
use std::net::{Ipv4Addr, Ipv6Addr};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::OnceLock;
use std::{net::SocketAddr, sync::Arc, time::Duration};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

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

pub struct QUICTunnelListener {
    addr: url::Url,
    endpoint: Option<Endpoint>,
}

impl QUICTunnelListener {
    pub fn new(addr: url::Url) -> Self {
        QUICTunnelListener {
            addr,
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
        let endpoint = QuicEndpointPool::create(addr, false)?;
        endpoint.set_server_config(Some(server_config()));
        self.endpoint = Some(endpoint);

        self.addr
            .set_port(Some(self.endpoint.as_ref().unwrap().local_addr()?.port()))
            .unwrap();

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

#[derive(Debug, Deref)]
struct RwPool<Item> {
    #[deref]
    pool: RwLock<Vec<Item>>,
    enabled: AtomicBool,
    capacity: usize,
}

impl<Item> RwPool<Item> {
    fn new(capacity: usize) -> Self {
        Self {
            pool: RwLock::new(Vec::new()),
            enabled: AtomicBool::new(true),
            capacity,
        }
    }

    fn is_full(&self) -> bool {
        self.read().len() >= self.capacity
    }

    fn try_push(&self, item: Item) -> Option<Item> {
        let mut pool = self.write();
        if pool.len() < self.capacity {
            pool.push(item);
            return None;
        }
        Some(item)
    }

    fn resize(&self) {
        let capacity = self.capacity * self.enabled.load(Ordering::Relaxed) as usize;
        if self.read().capacity() != capacity {
            let mut pool = self.write();
            pool.reserve_exact(capacity);
            pool.truncate(capacity);
        }
    }
}

#[derive(Debug)]
pub struct QuicEndpointPool {
    ipv4: RwPool<Endpoint>,
    ipv6: RwPool<Endpoint>,
    both: RwPool<Endpoint>,
    dual_stack: AtomicBool,
}

static QUIC_ENDPOINT_POOL: OnceLock<QuicEndpointPool> = OnceLock::new();

impl QuicEndpointPool {
    fn create(addr: SocketAddr, dual_stack: bool) -> std::io::Result<Endpoint> {
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
        let runtime = quinn::default_runtime()
            .ok_or_else(|| std::io::Error::other("no async runtime found"))?;
        let mut endpoint = Endpoint::new_with_abstract_socket(
            endpoint_config(),
            None,
            runtime.wrap_udp_socket(socket)?,
            runtime,
        )?;
        endpoint.set_default_client_config(client_config());
        Ok(endpoint)
    }
}

impl QuicEndpointPool {
    fn new(capacity: usize) -> Self {
        let ipv4 = RwPool::new(capacity.div_ceil(2));
        ipv4.enabled.store(false, Ordering::Relaxed);
        let ipv6 = RwPool::new(capacity.div_ceil(2));
        ipv6.enabled.store(false, Ordering::Relaxed);
        Self {
            ipv4,
            ipv6,
            both: RwPool::new(capacity),
            dual_stack: AtomicBool::new(true),
        }
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

        let pool = QUIC_ENDPOINT_POOL.get();
        match pool {
            Some(pool) => {
                for pool in [&pool.ipv4, &pool.ipv6, &pool.both] {
                    pool.resize();
                }
            }

            None => {
                let _ = QUIC_ENDPOINT_POOL.set(Self::new(capacity));
            }
        }

        QUIC_ENDPOINT_POOL.get().unwrap()
    }

    fn get(global_ctx: &ArcGlobalCtx, ip_version: IpVersion) -> std::io::Result<Endpoint> {
        let pools = Self::load(global_ctx);

        let pool = loop {
            let dual_stack = pools.both.enabled.load(Ordering::Relaxed);
            let (pool, addr) = match ip_version {
                IpVersion::V4 if !dual_stack => (&pools.ipv4, (Ipv4Addr::UNSPECIFIED, 0).into()),
                _ => {
                    let pool = if dual_stack { &pools.both } else { &pools.ipv6 };
                    (pool, (Ipv6Addr::UNSPECIFIED, 0).into())
                }
            };
            if pool.is_full() {
                break pool;
            }
            let endpoint = Self::create(addr, dual_stack);
            if let Err(e) = endpoint.as_ref() {
                if dual_stack {
                    tracing::warn!("create dual stack quic endpoint failed: {:?}", e);
                    pools.both.enabled.store(false, Ordering::Relaxed);
                    pools.ipv4.enabled.store(true, Ordering::Relaxed);
                    pools.ipv6.enabled.store(true, Ordering::Relaxed);
                    continue;
                }
            }
            pool.try_push(endpoint?);
            break pool;
        };

        Ok(pool
            .read()
            .iter()
            .min_by_key(|e| e.open_connections())
            .unwrap()
            .clone())
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
        let endpoint = Self::get(global_ctx, ip_version)?;
        let connection = endpoint
            .connect(addr, "localhost")
            .unwrap()
            .await
            .map_err(std::io::Error::other)?;

        Ok((endpoint, connection))
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
    async fn connect(&mut self) -> Result<Box<dyn Tunnel>, super::TunnelError> {
        let addr =
            check_scheme_and_get_socket_addr::<SocketAddr>(&self.addr, "quic", self.ip_version)
                .await?;
        let (endpoint, connection) = QuicEndpointPool::connect(&self.global_ctx, addr).await?;

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

    use super::*;

    #[tokio::test]
    async fn quic_pingpong() {
        let listener = QUICTunnelListener::new("quic://0.0.0.0:21011".parse().unwrap());
        let identity = crate::common::config::NetworkIdentity::default();
        let global_ctx = get_mock_global_ctx_with_network(Some(identity));
        let connector =
            QUICTunnelConnector::new("quic://127.0.0.1:21011".parse().unwrap(), global_ctx);
        _tunnel_pingpong(listener, connector).await
    }

    #[tokio::test]
    async fn quic_bench() {
        let listener = QUICTunnelListener::new("quic://0.0.0.0:21012".parse().unwrap());
        let identity = crate::common::config::NetworkIdentity::default();
        let global_ctx = get_mock_global_ctx_with_network(Some(identity));
        let connector =
            QUICTunnelConnector::new("quic://127.0.0.1:21012".parse().unwrap(), global_ctx);
        _tunnel_bench(listener, connector).await
    }

    #[tokio::test]
    async fn ipv6_pingpong() {
        let listener = QUICTunnelListener::new("quic://[::1]:31015".parse().unwrap());
        let identity = crate::common::config::NetworkIdentity::default();
        let global_ctx = get_mock_global_ctx_with_network(Some(identity));
        let connector = QUICTunnelConnector::new("quic://[::1]:31015".parse().unwrap(), global_ctx);
        _tunnel_pingpong(listener, connector).await
    }

    #[tokio::test]
    async fn ipv6_domain_pingpong() {
        let identity = crate::common::config::NetworkIdentity::default();
        let global_ctx = get_mock_global_ctx_with_network(Some(identity));

        let listener = QUICTunnelListener::new("quic://[::1]:31016".parse().unwrap());
        let mut connector = QUICTunnelConnector::new(
            "quic://test.easytier.top:31016".parse().unwrap(),
            global_ctx.clone(),
        );
        connector.set_ip_version(IpVersion::V6);
        _tunnel_pingpong(listener, connector).await;

        let listener = QUICTunnelListener::new("quic://127.0.0.1:31016".parse().unwrap());
        let mut connector = QUICTunnelConnector::new(
            "quic://test.easytier.top:31016".parse().unwrap(),
            global_ctx.clone(),
        );
        connector.set_ip_version(IpVersion::V4);
        _tunnel_pingpong(listener, connector).await;
    }

    #[tokio::test]
    async fn test_alloc_port() {
        // v4
        let mut listener = QUICTunnelListener::new("quic://0.0.0.0:0".parse().unwrap());
        listener.listen().await.unwrap();
        let port = listener.local_url().port().unwrap();
        assert!(port > 0);

        // v6
        let mut listener = QUICTunnelListener::new("quic://[::]:0".parse().unwrap());
        listener.listen().await.unwrap();
        let port = listener.local_url().port().unwrap();
        assert!(port > 0);
    }
}
