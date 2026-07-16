//! This example demonstrates how to make a QUIC connection that ignores the server certificate.
//!
//! Checkout the `README.md` for guidance.

use super::FromUrl;
use crate::common::{global_ctx::ArcGlobalCtx, netns::NetNS};
use crate::socket::{
    udp::{RuntimeUdpSessionSocketListener, new_runtime_udp_session_listener},
    udp_src,
};
use crate::tunnel::common::bind;
use crate::{proto::common::TunnelInfo, tunnel::TunnelUrl};
use anyhow::Context;
use derivative::Derivative;
use derive_more::{Deref, DerefMut};
use easytier_core::{
    connectivity::{
        protocol::{ServerProtocolAdmission, ServerTunnelAcceptor},
        transport::ConnectedUdpSession,
    },
    socket::udp::{
        UdpBindOptions, UdpSession, UdpSessionAcceptKind, UdpSessionListenRequest,
        UdpSessionProtocol, UdpSessionSocket, parse_quic_initial_dcid,
    },
    tunnel::{
        IpVersion, Tunnel, TunnelError,
        framed::{FramedReader, FramedWriter},
        wrapper::TunnelWrapper,
    },
};
use parking_lot::RwLock;
use quinn::{
    AsyncUdpSocket, ClientConfig, ConnectError, Connecting, Connection, Endpoint, EndpointConfig,
    Incoming, ServerConfig, TransportConfig, UdpPoller,
    congestion::BbrConfig,
    default_runtime,
    udp::{RecvMeta, Transmit},
};
use std::{
    collections::{HashMap, HashSet, hash_map::Entry},
    fmt::Formatter,
    future::Future,
    io::{self, IoSliceMut},
    net::SocketAddr,
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
    pin::Pin,
    sync::OnceLock,
    sync::atomic::{AtomicBool, AtomicUsize, Ordering},
    sync::{Arc, Mutex as StdMutex},
    task::{Context as TaskContext, Poll},
    time::Duration,
};
use tokio::{
    net::UdpSocket,
    runtime::Handle,
    sync::{
        OwnedSemaphorePermit, Semaphore,
        mpsc::{Receiver, Sender, channel, error::TrySendError},
        watch,
    },
    task::JoinSet,
};
use tokio_util::task::AbortOnDropHandle;

mod session_socket;
pub(crate) use session_socket::QuicUdpSessionSocket;

// region config
mod crypto {
    use crate::utils::BoxExt;
    use bytes::{Buf, BytesMut};
    use quinn_proto::crypto::{
        ClientConfig, ExportKeyingMaterialError, KeyPair, Keys, ServerConfig, Session,
        UnsupportedVersion,
    };
    use quinn_proto::transport_parameters::TransportParameters;
    use quinn_proto::{
        ConnectError, ConnectionId, Side, TransportError,
        crypto::{CryptoError, HeaderKey, PacketKey},
    };
    use seahash::SeaHasher;
    use std::any::Any;
    use std::{hash::Hasher, sync::Arc};
    use tracing::{error, instrument, trace};

    #[derive(Debug, Clone, Copy)]
    struct CryptoKey;

    impl CryptoKey {
        fn header(self) -> KeyPair<Box<dyn HeaderKey>> {
            KeyPair {
                local: Box::new(self),
                remote: Box::new(self),
            }
        }

        fn packet(self) -> KeyPair<Box<dyn PacketKey>> {
            KeyPair {
                local: Box::new(self),
                remote: Box::new(self),
            }
        }

        fn keys(self) -> Keys {
            Keys {
                header: self.header(),
                packet: self.packet(),
            }
        }
    }

    impl HeaderKey for CryptoKey {
        fn decrypt(&self, _: usize, _: &mut [u8]) {}
        fn encrypt(&self, _: usize, _: &mut [u8]) {}
        fn sample_size(&self) -> usize {
            0
        }
    }

    impl CryptoKey {
        fn checksum(slices: &[&[u8]]) -> u64 {
            let mut hasher = SeaHasher::default();
            for slice in slices {
                hasher.write(&(slice.len() as u64).to_le_bytes());
                hasher.write(slice);
            }
            hasher.finish()
        }
    }

    impl PacketKey for CryptoKey {
        #[instrument(level = "trace")]
        fn encrypt(&self, packet: u64, buf: &mut [u8], header_len: usize) {
            let (header, rest) = buf.split_at_mut(header_len);
            let (payload, tag) = rest.split_at_mut(rest.len() - self.tag_len());
            let checksum = Self::checksum(&[header, payload]);
            tag.copy_from_slice(&checksum.to_be_bytes());
            trace!(checksum, ?header, ?payload, ?tag);
        }

        #[instrument(level = "trace")]
        fn decrypt(
            &self,
            packet: u64,
            header: &[u8],
            payload: &mut BytesMut,
        ) -> Result<(), CryptoError> {
            let tag = payload.split_off(payload.len() - self.tag_len()).get_u64();
            trace!(tag, ?payload);
            let checksum = Self::checksum(&[header, payload]);
            if checksum != tag {
                error!(tag, checksum, "checksum mismatch");
                return Err(CryptoError);
            }
            Ok(())
        }

        fn tag_len(&self) -> usize {
            8
        }

        fn confidentiality_limit(&self) -> u64 {
            u64::MAX
        }

        fn integrity_limit(&self) -> u64 {
            1 << 36
        }
    }

    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    enum HandshakeState {
        EmitInitial,
        EmitHandshake,
        Done,
    }

    #[derive(Debug)]
    struct QuicSession {
        side: Side,
        state: HandshakeState,
        local: TransportParameters,
        remote: Option<TransportParameters>,
    }

    impl QuicSession {
        fn new(side: Side, params: TransportParameters) -> Self {
            Self {
                side,
                state: HandshakeState::EmitInitial,
                local: params,
                remote: None,
            }
        }
    }

    impl Session for QuicSession {
        fn initial_keys(&self, _: &ConnectionId, _: Side) -> Keys {
            CryptoKey.keys()
        }

        fn handshake_data(&self) -> Option<Box<dyn Any>> {
            self.remote.map(|params| params.boxed() as _)
        }

        fn peer_identity(&self) -> Option<Box<dyn Any>> {
            None
        }

        fn early_crypto(&self) -> Option<(Box<dyn HeaderKey>, Box<dyn PacketKey>)> {
            None
        }

        fn early_data_accepted(&self) -> Option<bool> {
            Some(false)
        }

        #[instrument(level = "trace")]
        fn is_handshaking(&self) -> bool {
            self.remote.is_none() || self.state != HandshakeState::Done
        }

        #[instrument(level = "trace")]
        fn read_handshake(&mut self, mut buf: &[u8]) -> Result<bool, TransportError> {
            if self.remote.is_none() {
                self.remote = Some(
                    TransportParameters::read(self.side, &mut buf)
                        .expect("failed to read transport parameters"),
                );
            }
            Ok(true)
        }

        #[instrument(level = "trace")]
        fn transport_parameters(&self) -> Result<Option<TransportParameters>, TransportError> {
            Ok(self.remote)
        }

        #[instrument(level = "trace")]
        fn write_handshake(&mut self, buf: &mut Vec<u8>) -> Option<Keys> {
            match self.state {
                HandshakeState::EmitInitial => {
                    if self.side.is_client() {
                        self.local.write(buf);
                    }
                    self.state = HandshakeState::EmitHandshake;
                    Some(CryptoKey.keys())
                }
                HandshakeState::EmitHandshake => {
                    if self.side.is_server() {
                        self.local.write(buf);
                    }
                    self.state = HandshakeState::Done;
                    Some(CryptoKey.keys())
                }
                HandshakeState::Done => None,
            }
        }

        fn next_1rtt_keys(&mut self) -> Option<KeyPair<Box<dyn PacketKey>>> {
            Some(CryptoKey.packet())
        }

        fn is_valid_retry(&self, _: &ConnectionId, _: &[u8], _: &[u8]) -> bool {
            true
        }

        fn export_keying_material(
            &self,
            _: &mut [u8],
            _: &[u8],
            _: &[u8],
        ) -> Result<(), ExportKeyingMaterialError> {
            Ok(())
        }
    }

    #[derive(Debug)]
    pub struct CryptoConfig;

    impl ClientConfig for CryptoConfig {
        #[instrument(level = "trace")]
        fn start_session(
            self: Arc<Self>,
            version: u32,
            server_name: &str,
            params: &TransportParameters,
        ) -> Result<Box<dyn Session>, ConnectError> {
            Ok(Box::new(QuicSession::new(Side::Client, *params)))
        }
    }

    impl ServerConfig for CryptoConfig {
        fn initial_keys(&self, _: u32, _: &ConnectionId) -> Result<Keys, UnsupportedVersion> {
            Ok(CryptoKey.keys())
        }

        fn retry_tag(&self, _: u32, _: &ConnectionId, _: &[u8]) -> [u8; 16] {
            [0u8; 16]
        }

        #[instrument(level = "trace")]
        fn start_session(
            self: Arc<Self>,
            version: u32,
            params: &TransportParameters,
        ) -> Box<dyn Session> {
            Box::new(QuicSession::new(Side::Server, *params))
        }
    }
}

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
    let mut config = ServerConfig::with_crypto(Arc::new(crypto::CryptoConfig));
    config.transport_config(transport_config());
    config
}

pub fn client_config() -> ClientConfig {
    let mut config = ClientConfig::new(Arc::new(crypto::CryptoConfig));
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
        let persistent_len = self.persistent.read().len();
        let ephemeral_len = self.ephemeral.read().len();
        persistent_len + ephemeral_len
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
        self.persistent
            .read()
            .iter()
            .any(|endpoint| endpoint.local_addr().ok() == Some(local_addr))
            || self
                .ephemeral
                .read()
                .iter()
                .any(|endpoint| endpoint.local_addr().ok() == Some(local_addr))
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
    fn try_create(
        addr: SocketAddr,
        dual_stack: bool,
        socket_mark: Option<u32>,
    ) -> Result<Endpoint, TunnelError> {
        let socket = bind::<UdpSocket>()
            .addr(addr)
            .only_v6(addr.is_ipv6() && !dual_stack)
            .maybe_socket_mark(socket_mark)
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
        socket_mark: Option<u32>,
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

            let endpoint = Self::try_create(addr, dual_stack, socket_mark);
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
        let socket_mark = global_ctx.config.get_flags().socket_mark;

        let (pool, endpoint) = mgr.create(socket_mark, |mgr| {
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

    fn client_endpoint(
        &self,
        ip_version: IpVersion,
        socket_mark: Option<u32>,
    ) -> Result<Endpoint, TunnelError> {
        let (pool, endpoint) = self.create(socket_mark, |mgr| {
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
        let socket_mark = global_ctx.config.get_flags().socket_mark;
        Self::load(global_ctx)
            .connect_with_ip_version(addr, ip_version, socket_mark)
            .await
    }

    async fn connect_with_ip_version(
        &self,
        addr: SocketAddr,
        ip_version: IpVersion,
        socket_mark: Option<u32>,
    ) -> Result<(Endpoint, Connection), TunnelError> {
        let max_endpoint_stopping_retries = self.client_pool(ip_version).len().saturating_add(1);
        let mut endpoint_stopping_retries = 0;

        loop {
            let endpoint = self.client_endpoint(ip_version, socket_mark)?;
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
    _endpoint: Option<Endpoint>,
    _udp_session_cleanup: Option<QuicUdpSessionCleanup>,
}

impl Drop for ConnWrapper {
    fn drop(&mut self) {
        self.conn.close(0u32.into(), b"done");
    }
}

type QuicUdpSessionClosers = Arc<StdMutex<HashMap<SocketAddr, Arc<QuicUdpSessionCloser>>>>;
type QuicUdpInitialKey = (SocketAddr, Vec<u8>);
type QuicUdpPendingInitials = Arc<StdMutex<HashMap<QuicUdpInitialKey, QuicUdpPendingInitial>>>;

struct QuicUdpPendingInitial {
    closer: Arc<QuicUdpSessionCloser>,
    claimed: bool,
}

struct QuicUdpSessionCloser {
    close: watch::Sender<bool>,
    claimed: AtomicBool,
    active_connections: AtomicUsize,
    claimed_initials: StdMutex<HashSet<QuicUdpInitialKey>>,
}

impl QuicUdpSessionCloser {
    fn new(close: watch::Sender<bool>) -> Self {
        Self {
            close,
            claimed: AtomicBool::new(false),
            active_connections: AtomicUsize::new(0),
            claimed_initials: StdMutex::new(HashSet::new()),
        }
    }

    fn try_claim(&self, initial_key: &QuicUdpInitialKey) -> bool {
        self.claimed.store(true, Ordering::Relaxed);
        let mut claimed_initials = self.claimed_initials.lock().unwrap();
        if claimed_initials.contains(initial_key) {
            return true;
        }
        if claimed_initials.len() >= QUIC_UDP_MAX_CLAIMED_INITIALS_PER_SESSION {
            return false;
        }
        claimed_initials.insert(initial_key.clone());
        true
    }

    fn is_claimed(&self) -> bool {
        self.claimed.load(Ordering::Relaxed)
    }

    fn is_initial_claimed(&self, initial_key: &QuicUdpInitialKey) -> bool {
        self.claimed_initials.lock().unwrap().contains(initial_key)
    }

    fn remove_claimed_initial(&self, initial_key: &QuicUdpInitialKey) {
        self.claimed_initials.lock().unwrap().remove(initial_key);
    }

    #[cfg(test)]
    fn claimed_initial_count(&self) -> usize {
        self.claimed_initials.lock().unwrap().len()
    }

    fn retain_connection(&self) {
        self.active_connections.fetch_add(1, Ordering::Relaxed);
    }

    fn release_connection(&self) -> bool {
        let previous = self.active_connections.fetch_sub(1, Ordering::AcqRel);
        debug_assert!(previous > 0);
        previous == 1
    }

    fn close(&self) {
        let _ = self.close.send(true);
    }
}

struct QuicUdpSessionCleanup {
    peer_addr: SocketAddr,
    initial_key: QuicUdpInitialKey,
    closer: Arc<QuicUdpSessionCloser>,
    closers: QuicUdpSessionClosers,
    pending_initials: QuicUdpPendingInitials,
    runtime: Option<Handle>,
}

impl QuicUdpSessionCleanup {
    fn new(
        initial_key: QuicUdpInitialKey,
        closer: Arc<QuicUdpSessionCloser>,
        closers: QuicUdpSessionClosers,
        pending_initials: QuicUdpPendingInitials,
    ) -> Self {
        let peer_addr = initial_key.0;
        closer.retain_connection();
        Self {
            peer_addr,
            initial_key,
            closer,
            closers,
            pending_initials,
            runtime: Handle::try_current().ok(),
        }
    }
}

impl Drop for QuicUdpSessionCleanup {
    fn drop(&mut self) {
        if !self.closer.release_connection() {
            retain_claimed_initial_tombstone_for_stale_incoming(
                self.pending_initials.clone(),
                self.initial_key.clone(),
                self.closer.clone(),
                self.runtime.clone(),
            );
            return;
        }
        retain_claimed_initial_tombstone_for_stale_incoming(
            self.pending_initials.clone(),
            self.initial_key.clone(),
            self.closer.clone(),
            self.runtime.clone(),
        );
        self.closer.close();
        let mut closers = self.closers.lock().unwrap();
        if closers
            .get(&self.peer_addr)
            .is_some_and(|current| Arc::ptr_eq(current, &self.closer))
        {
            closers.remove(&self.peer_addr);
        }
    }
}

fn pending_initial_matches(
    pending: &QuicUdpPendingInitial,
    closer: &Arc<QuicUdpSessionCloser>,
) -> bool {
    Arc::ptr_eq(&pending.closer, closer)
}

fn remove_pending_initial_if_matches(
    pending_initials: &QuicUdpPendingInitials,
    initial_key: &QuicUdpInitialKey,
    closer: &Arc<QuicUdpSessionCloser>,
) {
    let mut pending_initials = pending_initials.lock().unwrap();
    if pending_initials
        .get(initial_key)
        .is_some_and(|current| pending_initial_matches(current, closer))
    {
        pending_initials.remove(initial_key);
    }
}

fn remove_tombstone_and_claim_if_matches(
    pending_initials: &QuicUdpPendingInitials,
    initial_key: &QuicUdpInitialKey,
    closer: &Arc<QuicUdpSessionCloser>,
) {
    remove_pending_initial_if_matches(pending_initials, initial_key, closer);
    closer.remove_claimed_initial(initial_key);
}

fn remove_unclaimed_pending_initial_if_matches(
    pending_initials: &QuicUdpPendingInitials,
    initial_key: &QuicUdpInitialKey,
    closer: &Arc<QuicUdpSessionCloser>,
) {
    let mut pending_initials = pending_initials.lock().unwrap();
    if pending_initials
        .get(initial_key)
        .is_some_and(|current| !current.claimed && pending_initial_matches(current, closer))
    {
        pending_initials.remove(initial_key);
    }
}

fn expire_unclaimed_pending_initial_after_timeout(
    pending_initials: QuicUdpPendingInitials,
    initial_key: QuicUdpInitialKey,
    closer: Arc<QuicUdpSessionCloser>,
) {
    expire_unclaimed_pending_initial_after(
        pending_initials,
        initial_key,
        closer,
        QUIC_UDP_UNCLAIMED_INITIAL_TIMEOUT,
    );
}

fn expire_unclaimed_pending_initial_after(
    pending_initials: QuicUdpPendingInitials,
    initial_key: QuicUdpInitialKey,
    closer: Arc<QuicUdpSessionCloser>,
    timeout: Duration,
) {
    tokio::spawn(async move {
        tokio::time::sleep(timeout).await;
        remove_unclaimed_pending_initial_if_matches(&pending_initials, &initial_key, &closer);
    });
}

fn retain_pending_initial_tombstone_for_stale_incoming(
    pending_initials: QuicUdpPendingInitials,
    initial_key: QuicUdpInitialKey,
    closer: Arc<QuicUdpSessionCloser>,
) {
    retain_pending_initial_tombstone_for_stale_incoming_after(
        pending_initials,
        initial_key,
        closer,
        QUIC_UDP_STALE_INCOMING_TOMBSTONE_TIMEOUT,
    );
}

fn retain_pending_initial_tombstone_for_stale_incoming_after(
    pending_initials: QuicUdpPendingInitials,
    initial_key: QuicUdpInitialKey,
    closer: Arc<QuicUdpSessionCloser>,
    timeout: Duration,
) {
    {
        let mut pending_initials = pending_initials.lock().unwrap();
        if let Some(pending) = pending_initials.get_mut(&initial_key) {
            if pending_initial_matches(pending, &closer) {
                pending.claimed = true;
            }
        }
    }
    tokio::spawn(async move {
        tokio::time::sleep(timeout).await;
        remove_pending_initial_if_matches(&pending_initials, &initial_key, &closer);
    });
}

fn retain_claimed_initial_tombstone_for_stale_incoming(
    pending_initials: QuicUdpPendingInitials,
    initial_key: QuicUdpInitialKey,
    closer: Arc<QuicUdpSessionCloser>,
    runtime: Option<Handle>,
) {
    retain_claimed_initial_tombstone_for_stale_incoming_after(
        pending_initials,
        initial_key,
        closer,
        QUIC_UDP_STALE_INCOMING_TOMBSTONE_TIMEOUT,
        runtime,
    );
}

fn retain_claimed_initial_tombstone_for_stale_incoming_after(
    pending_initials: QuicUdpPendingInitials,
    initial_key: QuicUdpInitialKey,
    closer: Arc<QuicUdpSessionCloser>,
    timeout: Duration,
    runtime: Option<Handle>,
) {
    {
        let mut pending_initials = pending_initials.lock().unwrap();
        pending_initials
            .entry(initial_key.clone())
            .or_insert_with(|| QuicUdpPendingInitial {
                closer: closer.clone(),
                claimed: true,
            });
    }

    let Some(runtime) = runtime.or_else(|| Handle::try_current().ok()) else {
        remove_tombstone_and_claim_if_matches(&pending_initials, &initial_key, &closer);
        return;
    };
    runtime.spawn(async move {
        tokio::time::sleep(timeout).await;
        remove_tombstone_and_claim_if_matches(&pending_initials, &initial_key, &closer);
    });
}

enum PendingInitialRegister {
    Registered,
    AlreadyRegisteredSameGeneration,
    AlreadyClaimedSameGeneration,
    OccupiedByOtherGeneration,
    TooManyPendingInitials,
}

fn register_pending_initial(
    pending_initials: &QuicUdpPendingInitials,
    initial_key: QuicUdpInitialKey,
    closer: Arc<QuicUdpSessionCloser>,
) -> PendingInitialRegister {
    let mut pending_initials = pending_initials.lock().unwrap();
    let pending_initial_count = pending_initials
        .values()
        .filter(|pending| !pending.claimed && pending_initial_matches(pending, &closer))
        .count();
    match pending_initials.entry(initial_key) {
        Entry::Vacant(entry) => {
            if closer.is_initial_claimed(entry.key()) {
                return PendingInitialRegister::AlreadyClaimedSameGeneration;
            }
            if pending_initial_count >= QUIC_UDP_MAX_PENDING_INITIALS_PER_SESSION {
                return PendingInitialRegister::TooManyPendingInitials;
            }
            entry.insert(QuicUdpPendingInitial {
                closer,
                claimed: false,
            });
            PendingInitialRegister::Registered
        }
        Entry::Occupied(entry) if pending_initial_matches(entry.get(), &closer) => {
            if entry.get().claimed || closer.is_initial_claimed(entry.key()) {
                PendingInitialRegister::AlreadyClaimedSameGeneration
            } else {
                PendingInitialRegister::AlreadyRegisteredSameGeneration
            }
        }
        Entry::Occupied(_) => PendingInitialRegister::OccupiedByOtherGeneration,
    }
}

fn claim_pending_initial(
    pending_initials: &QuicUdpPendingInitials,
    initial_key: &QuicUdpInitialKey,
) -> Option<Arc<QuicUdpSessionCloser>> {
    let mut pending_initials = pending_initials.lock().unwrap();
    let pending = pending_initials.get_mut(initial_key)?;
    if pending.claimed {
        return None;
    }
    pending.claimed = true;
    let closer = pending.closer.clone();
    if !closer.try_claim(initial_key) {
        pending_initials.remove(initial_key);
        return None;
    }
    pending_initials.remove(initial_key);
    Some(closer)
}

struct QuicUdpPoller {
    socket: Arc<UdpSocket>,
    writable: StdMutex<Option<Pin<Box<dyn Future<Output = io::Result<()>> + Send>>>>,
}

impl std::fmt::Debug for QuicUdpPoller {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("QuicUdpPoller").finish()
    }
}

impl UdpPoller for QuicUdpPoller {
    fn poll_writable(self: Pin<&mut Self>, cx: &mut TaskContext<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        let mut writable = this.writable.lock().unwrap();
        loop {
            if writable.is_none() {
                let socket = this.socket.clone();
                *writable = Some(Box::pin(async move { socket.writable().await }));
            }

            let wait = writable.as_mut().unwrap();
            match wait.as_mut().poll(cx) {
                Poll::Ready(ret) => {
                    *writable = None;
                    return Poll::Ready(ret);
                }
                Poll::Pending => return Poll::Pending,
            }
        }
    }
}

struct QuicUdpDatagram {
    payload: Vec<u8>,
    peer_addr: SocketAddr,
    dst_ip: Option<IpAddr>,
}

const QUIC_UDP_DATAGRAM_QUEUE_CAPACITY: usize = 1024;
const QUIC_UDP_UNCLAIMED_SESSION_TIMEOUT: Duration = Duration::from_secs(10);
const QUIC_UDP_STALE_INCOMING_TOMBSTONE_TIMEOUT: Duration = Duration::from_secs(30);
const QUIC_UDP_UNCLAIMED_INITIAL_TIMEOUT: Duration = QUIC_UDP_STALE_INCOMING_TOMBSTONE_TIMEOUT;
const QUIC_UDP_MAX_PENDING_INITIALS_PER_SESSION: usize = 64;
const QUIC_UDP_MAX_CLAIMED_INITIALS_PER_SESSION: usize = 64;
const QUIC_MAX_ACTIVE_UDP_SESSIONS: usize = 1024;
const QUIC_MAX_IN_FLIGHT_HANDSHAKES: usize = 128;
const QUIC_ACCEPT_COMPLETION_TIMEOUT: Duration = Duration::from_secs(10);

struct QuicUdpListenerSocket {
    send_socket: Arc<UdpSocket>,
    local_addr: SocketAddr,
    incoming: StdMutex<Receiver<io::Result<QuicUdpDatagram>>>,
    _accept_task: AbortOnDropHandle<()>,
}

impl std::fmt::Debug for QuicUdpListenerSocket {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("QuicUdpListenerSocket")
            .field("local_addr", &self.local_addr)
            .finish()
    }
}

impl QuicUdpListenerSocket {
    fn new(
        session_listener: Arc<RuntimeUdpSessionSocketListener>,
        send_socket: Arc<UdpSocket>,
        udp_session_closers: QuicUdpSessionClosers,
        pending_initials: QuicUdpPendingInitials,
    ) -> io::Result<Self> {
        let local_addr = send_socket.local_addr()?;
        let (incoming_tx, incoming_rx) = channel(QUIC_UDP_DATAGRAM_QUEUE_CAPACITY);
        let active_session_permits = Arc::new(Semaphore::new(QUIC_MAX_ACTIVE_UDP_SESSIONS));
        let accept_task = AbortOnDropHandle::new(tokio::spawn(async move {
            let mut session_tasks = JoinSet::new();
            loop {
                let session = match session_listener.accept_session().await {
                    Ok(session) => session,
                    Err(err) => {
                        let _ = incoming_tx
                            .send(Err(io::Error::other(err.to_string())))
                            .await;
                        break;
                    }
                };
                let peer_addr = match session.peer_addr() {
                    Ok(addr) => addr,
                    Err(err) => {
                        tracing::debug!(?err, "quic udp session peer addr error");
                        continue;
                    }
                };
                let Ok(session_permit) = active_session_permits.clone().try_acquire_owned() else {
                    tracing::debug!(
                        ?peer_addr,
                        "drop quic udp session after active session limit"
                    );
                    continue;
                };
                let (close_tx, mut close_rx) = watch::channel(false);
                let closer = Arc::new(QuicUdpSessionCloser::new(close_tx));
                udp_session_closers
                    .lock()
                    .unwrap()
                    .insert(peer_addr, closer.clone());
                let session_incoming_tx = incoming_tx.clone();
                let session_closers = udp_session_closers.clone();
                let session_pending_initials = pending_initials.clone();
                session_tasks.spawn(async move {
                    let _session_permit = session_permit;
                    let mut buf = vec![0u8; 64 * 1024];
                    let unclaimed_timeout = tokio::time::sleep(QUIC_UDP_UNCLAIMED_SESSION_TIMEOUT);
                    tokio::pin!(unclaimed_timeout);
                    loop {
                        tokio::select! {
                            biased;
                            _ = close_rx.changed() => break,
                            _ = &mut unclaimed_timeout, if !closer.is_claimed() => {
                                tracing::debug!(
                                    ?peer_addr,
                                    "quic udp session was not claimed before timeout"
                                );
                                break;
                            }
                            recv = session.recv_with_meta(&mut buf) => {
                                match recv {
                                    Ok((len, meta)) => {
                                        let mut should_forward = true;
                                        if let Some(dcid) = parse_quic_initial_dcid(&buf[..len]) {
                                            let key = (peer_addr, dcid);
                                            match register_pending_initial(
                                                &session_pending_initials,
                                                key.clone(),
                                                closer.clone(),
                                            ) {
                                                PendingInitialRegister::Registered => {
                                                    expire_unclaimed_pending_initial_after_timeout(
                                                        session_pending_initials.clone(),
                                                        key,
                                                        closer.clone(),
                                                    );
                                                }
                                                PendingInitialRegister::AlreadyRegisteredSameGeneration
                                                | PendingInitialRegister::AlreadyClaimedSameGeneration => {}
                                                PendingInitialRegister::TooManyPendingInitials => {
                                                    tracing::debug!(
                                                        ?peer_addr,
                                                        "drop quic initial after pending limit"
                                                    );
                                                    should_forward = false;
                                                }
                                                PendingInitialRegister::OccupiedByOtherGeneration => {
                                                    tracing::debug!(
                                                        ?peer_addr,
                                                        "drop duplicate quic initial generation"
                                                    );
                                                    break;
                                                }
                                            }
                                        }
                                        if !should_forward {
                                            continue;
                                        }
                                        match session_incoming_tx.try_send(Ok(QuicUdpDatagram {
                                                payload: buf[..len].to_vec(),
                                                peer_addr,
                                                dst_ip: meta.dst_ip,
                                            })) {
                                            Ok(()) => {}
                                            Err(TrySendError::Full(_)) => {
                                                tracing::debug!(
                                                    ?peer_addr,
                                                    "drop quic udp datagram after incoming queue full"
                                                );
                                            }
                                            Err(TrySendError::Closed(_)) => break,
                                        }
                                    }
                                    Err(err) => {
                                        tracing::debug!(
                                            ?err,
                                            ?peer_addr,
                                            "quic udp session recv stopped"
                                        );
                                        break;
                                    }
                                }
                            }
                        }
                    }
                    {
                        let mut session_closers = session_closers.lock().unwrap();
                        if session_closers
                            .get(&peer_addr)
                            .is_some_and(|current| Arc::ptr_eq(current, &closer))
                        {
                            session_closers.remove(&peer_addr);
                        }
                    }
                    let initial_keys = session_pending_initials
                        .lock()
                        .unwrap()
                        .iter()
                        .filter_map(|(key, pending)| {
                            pending_initial_matches(pending, &closer).then(|| key.clone())
                        })
                        .collect::<Vec<_>>();
                    for initial_key in initial_keys {
                        retain_pending_initial_tombstone_for_stale_incoming(
                            session_pending_initials.clone(),
                            initial_key,
                            closer.clone(),
                        );
                    }
                });
                while session_tasks.try_join_next().is_some() {}
            }
        }));

        Ok(Self {
            send_socket,
            local_addr,
            incoming: StdMutex::new(incoming_rx),
            _accept_task: accept_task,
        })
    }

    fn try_send_payload(
        &self,
        payload: &[u8],
        destination: SocketAddr,
        src_ip: Option<IpAddr>,
    ) -> io::Result<()> {
        let len = if let Some(src_ip) = src_ip {
            udp_src::try_send_to_with_src_ip(&self.send_socket, src_ip, destination, payload)?
        } else {
            self.send_socket.try_send_to(payload, destination)?
        };
        if len != payload.len() {
            return Err(io::Error::new(
                io::ErrorKind::WriteZero,
                "quic udp datagram was partially sent",
            ));
        }
        Ok(())
    }

    fn send_transmit(&self, transmit: &Transmit<'_>) -> io::Result<()> {
        if let Some(segment_size) = transmit.segment_size {
            for segment in transmit.contents.chunks(segment_size) {
                self.try_send_payload(segment, transmit.destination, transmit.src_ip)?;
            }
        } else {
            self.try_send_payload(transmit.contents, transmit.destination, transmit.src_ip)?;
        }
        Ok(())
    }
}

impl AsyncUdpSocket for QuicUdpListenerSocket {
    fn create_io_poller(self: Arc<Self>) -> Pin<Box<dyn UdpPoller>> {
        Box::pin(QuicUdpPoller {
            socket: self.send_socket.clone(),
            writable: StdMutex::new(None),
        })
    }

    fn try_send(&self, transmit: &Transmit<'_>) -> io::Result<()> {
        self.send_transmit(transmit)
    }

    fn poll_recv(
        &self,
        cx: &mut TaskContext<'_>,
        bufs: &mut [IoSliceMut<'_>],
        meta: &mut [RecvMeta],
    ) -> Poll<io::Result<usize>> {
        if bufs.is_empty() || meta.is_empty() {
            return Poll::Ready(Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "quic udp recv buffers are empty",
            )));
        }

        let mut incoming = self.incoming.lock().unwrap();
        loop {
            match Pin::new(&mut *incoming).poll_recv(cx) {
                Poll::Ready(Some(Ok(datagram))) => {
                    if bufs[0].len() < datagram.payload.len() {
                        tracing::debug!(
                            payload_len = datagram.payload.len(),
                            recv_buf_len = bufs[0].len(),
                            peer_addr = ?datagram.peer_addr,
                            "drop oversized quic udp datagram"
                        );
                        continue;
                    }
                    bufs[0][..datagram.payload.len()].copy_from_slice(&datagram.payload);
                    meta[0] = RecvMeta {
                        addr: datagram.peer_addr,
                        len: datagram.payload.len(),
                        stride: datagram.payload.len(),
                        ecn: None,
                        dst_ip: datagram.dst_ip,
                    };
                    return Poll::Ready(Ok(1));
                }
                Poll::Ready(Some(Err(error))) => return Poll::Ready(Err(error)),
                Poll::Ready(None) => {
                    return Poll::Ready(Err(io::Error::new(
                        io::ErrorKind::UnexpectedEof,
                        "quic udp session closed",
                    )));
                }
                Poll::Pending => return Poll::Pending,
            }
        }
    }

    fn local_addr(&self) -> io::Result<SocketAddr> {
        Ok(self.local_addr)
    }

    fn may_fragment(&self) -> bool {
        false
    }
}

struct PendingQuicTunnel {
    connecting: Connecting,
    endpoint: Endpoint,
    local_url: url::Url,
    remote_addr: SocketAddr,
    cleanup: QuicUdpSessionCleanup,
}

async fn accept_quic_incoming(
    endpoint: Endpoint,
    local_url: url::Url,
    udp_session_closers: QuicUdpSessionClosers,
    pending_initials: QuicUdpPendingInitials,
) -> Result<PendingQuicTunnel, TunnelError> {
    let incoming = endpoint
        .accept()
        .await
        .ok_or_else(|| TunnelError::InvalidPacket("quic accept failed".to_owned()))?;
    let remote_addr = incoming.remote_address();
    let initial_key = (remote_addr, incoming.orig_dst_cid().to_vec());
    let closer = claim_pending_initial(&pending_initials, &initial_key)
        .ok_or_else(|| TunnelError::InvalidPacket("quic udp session was closed".to_owned()))?;
    let cleanup = QuicUdpSessionCleanup::new(
        initial_key,
        closer,
        udp_session_closers,
        pending_initials.clone(),
    );
    let connecting = incoming
        .accept()
        .with_context(|| "quic accept connection failed")?;

    Ok(PendingQuicTunnel {
        connecting,
        endpoint,
        local_url,
        remote_addr,
        cleanup,
    })
}

async fn finish_quic_tunnel(pending: PendingQuicTunnel) -> Result<Box<dyn Tunnel>, TunnelError> {
    let PendingQuicTunnel {
        connecting,
        endpoint,
        local_url,
        remote_addr,
        cleanup,
    } = pending;
    let conn = tokio::time::timeout(QUIC_ACCEPT_COMPLETION_TIMEOUT, connecting)
        .await
        .map_err(TunnelError::Timeout)?
        .with_context(|| "accept connection failed")?;
    let (w, r) = tokio::time::timeout(QUIC_ACCEPT_COMPLETION_TIMEOUT, conn.accept_bi())
        .await
        .map_err(TunnelError::Timeout)?
        .with_context(|| "accept_bi failed")?;
    let arc_conn = Arc::new(ConnWrapper {
        conn,
        _endpoint: Some(endpoint),
        _udp_session_cleanup: Some(cleanup),
    });

    let info = TunnelInfo {
        tunnel_type: "quic".to_owned(),
        local_addr: Some(local_url.into()),
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

async fn accept_quic_tunnels(
    endpoint: Endpoint,
    local_url: url::Url,
    udp_session_closers: QuicUdpSessionClosers,
    pending_initials: QuicUdpPendingInitials,
    conn_send: Sender<Box<dyn Tunnel>>,
) {
    let mut complete_tasks = JoinSet::new();
    loop {
        tokio::select! {
            Some(ret) = complete_tasks.join_next(), if !complete_tasks.is_empty() => {
                match ret {
                    Ok(Ok(conn)) => {
                        match conn_send.try_send(conn) {
                            Ok(()) => {}
                            Err(TrySendError::Full(_)) => {
                                tracing::warn!(
                                    "quic accept channel full; drop completed connection"
                                );
                            }
                            Err(TrySendError::Closed(_)) => {
                                tracing::warn!("quic accept channel closed");
                                break;
                            }
                        }
                    }
                    Ok(Err(err)) => {
                        tracing::warn!(?err, "quic accept fail");
                    }
                    Err(err) => {
                        tracing::warn!(?err, "quic accept task panic");
                    }
                }
            }
            accepted = accept_quic_incoming(
                endpoint.clone(),
                local_url.clone(),
                udp_session_closers.clone(),
                pending_initials.clone(),
            ), if complete_tasks.len() < QUIC_MAX_IN_FLIGHT_HANDSHAKES => {
                match accepted {
                    Ok(pending) => {
                        complete_tasks.spawn(finish_quic_tunnel(pending));
                    }
                    Err(err) => {
                        tracing::warn!(?err, "quic accept fail");
                        tokio::time::sleep(Duration::from_millis(1)).await;
                    }
                }
            }
        }
    }
}

pub struct QuicTunnelListener {
    addr: url::Url,
    session_listener: Option<Arc<RuntimeUdpSessionSocketListener>>,
    endpoint: Option<Endpoint>,
    conn_send: Sender<Box<dyn Tunnel>>,
    conn_recv: Receiver<Box<dyn Tunnel>>,
    udp_session_closers: QuicUdpSessionClosers,
    pending_initials: QuicUdpPendingInitials,
    forward_tasks: Arc<StdMutex<JoinSet<()>>>,
    global_ctx: ArcGlobalCtx,
}

impl std::fmt::Debug for QuicTunnelListener {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("QuicTunnelListener")
            .field("addr", &self.addr)
            .field("listening", &self.endpoint.is_some())
            .finish()
    }
}

impl QuicTunnelListener {
    pub fn new(addr: url::Url, global_ctx: ArcGlobalCtx) -> Self {
        let (conn_send, conn_recv) = channel(100);
        QuicTunnelListener {
            addr,
            session_listener: None,
            endpoint: None,
            conn_send,
            conn_recv,
            udp_session_closers: Arc::new(StdMutex::new(HashMap::new())),
            pending_initials: Arc::new(StdMutex::new(HashMap::new())),
            forward_tasks: Arc::new(StdMutex::new(JoinSet::new())),
            global_ctx,
        }
    }

    async fn listen_tunnel(&mut self) -> Result<(), TunnelError> {
        if self.endpoint.is_some() {
            return Ok(());
        }
        use crate::common::config::ConfigLoader as _;
        let addr = SocketAddr::from_url(self.addr.clone(), IpVersion::Both).await?;
        let bind = UdpBindOptions::port_bound_listener(addr)
            .with_socket_mark(self.global_ctx.config.get_flags().socket_mark)
            .with_bind_device(TunnelUrl::from(self.addr.clone()).bind_dev())
            .with_only_v6(addr.ip() != IpAddr::V6(Ipv6Addr::UNSPECIFIED));
        let mut session_listener = new_runtime_udp_session_listener(
            self.addr.clone(),
            UdpSessionListenRequest::new(bind),
            UdpSessionAcceptKind::Classified(UdpSessionProtocol::Quic),
            NetNS::new(None),
        );
        easytier_core::listener::SocketListener::listen(&mut session_listener).await?;
        let send_socket = session_listener.bound_socket()?.socket();
        let session_listener = Arc::new(session_listener);
        let udp_socket = Arc::new(QuicUdpListenerSocket::new(
            session_listener.clone(),
            send_socket,
            self.udp_session_closers.clone(),
            self.pending_initials.clone(),
        )?);
        let runtime = default_runtime().ok_or(TunnelError::InternalError(
            "no async runtime found".to_owned(),
        ))?;
        self.endpoint = Some(Endpoint::new_with_abstract_socket(
            endpoint_config(),
            Some(server_config()),
            udp_socket,
            runtime,
        )?);
        self.session_listener = Some(session_listener);
        let endpoint = self.endpoint.as_ref().unwrap().clone();
        let local_url = self
            .session_listener
            .as_ref()
            .map(|listener| easytier_core::listener::SocketListener::local_url(listener.as_ref()))
            .unwrap_or_else(|| self.addr.clone());
        let udp_session_closers = self.udp_session_closers.clone();
        let pending_initials = self.pending_initials.clone();
        let conn_send = self.conn_send.clone();
        self.forward_tasks
            .lock()
            .unwrap()
            .spawn(accept_quic_tunnels(
                endpoint,
                local_url,
                udp_session_closers,
                pending_initials,
                conn_send,
            ));
        Ok(())
    }

    async fn accept_tunnel(&mut self) -> Result<Box<dyn Tunnel>, TunnelError> {
        self.conn_recv.recv().await.ok_or(TunnelError::Shutdown)
    }
}

#[async_trait::async_trait]
impl easytier_core::listener::SocketListener for QuicTunnelListener {
    type Accepted = Box<dyn Tunnel>;

    async fn listen(&mut self) -> anyhow::Result<()> {
        Ok(self.listen_tunnel().await?)
    }

    async fn accept(&mut self) -> anyhow::Result<Self::Accepted> {
        Ok(self.accept_tunnel().await?)
    }

    fn local_url(&self) -> url::Url {
        self.session_listener
            .as_ref()
            .map(|listener| easytier_core::listener::SocketListener::local_url(listener.as_ref()))
            .unwrap_or_else(|| self.addr.clone())
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

    pub fn set_ip_version(&mut self, ip_version: IpVersion) {
        self.ip_version = ip_version;
    }

    pub fn set_resolved_addr(&mut self, addr: SocketAddr) {
        self.resolved_addr = Some(addr);
    }

    async fn connect_tunnel(&self) -> Result<Box<dyn Tunnel>, TunnelError> {
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

        let arc_conn = Arc::new(ConnWrapper {
            conn: connection,
            _endpoint: None,
            _udp_session_cleanup: None,
        });
        Ok(Box::new(TunnelWrapper::new(
            FramedReader::new_with_associate_data(r, 4500, Some(Box::new(arc_conn.clone()))),
            FramedWriter::new_with_associate_data(w, Some(Box::new(arc_conn))),
            Some(info),
        )))
    }
}

pub(crate) async fn upgrade_connected(
    connected: ConnectedUdpSession,
    remote_url: url::Url,
) -> Result<Box<dyn Tunnel>, TunnelError> {
    let socket = Arc::new(QuicUdpSessionSocket::new(connected)?);
    let local_addr = socket.local_addr()?;
    let remote_addr = socket.peer_addr();
    let runtime = default_runtime().ok_or(TunnelError::InternalError(
        "no async runtime found".to_owned(),
    ))?;
    let mut endpoint =
        Endpoint::new_with_abstract_socket(endpoint_config(), None, socket, runtime)?;
    endpoint.set_default_client_config(client_config());
    let connecting = endpoint
        .connect(remote_addr, "localhost")
        .map_err(anyhow::Error::new)
        .with_context(|| format!("failed to start connection to {remote_addr}"))?;
    let connection = connecting
        .await
        .with_context(|| format!("failed to connect to {remote_addr}"))?;
    let (write, read) = connection
        .open_bi()
        .await
        .with_context(|| "open_bi failed")?;
    let resolved_remote_addr = connection.remote_address();
    let connection = Arc::new(ConnWrapper {
        conn: connection,
        _endpoint: Some(endpoint),
        _udp_session_cleanup: None,
    });
    let info = TunnelInfo {
        tunnel_type: "quic".to_owned(),
        local_addr: Some(super::build_url_from_socket_addr(&local_addr.to_string(), "quic").into()),
        remote_addr: Some(remote_url.into()),
        resolved_remote_addr: Some(
            super::build_url_from_socket_addr(&resolved_remote_addr.to_string(), "quic").into(),
        ),
    };
    Ok(Box::new(TunnelWrapper::new(
        FramedReader::new_with_associate_data(read, 4500, Some(Box::new(connection.clone()))),
        FramedWriter::new_with_associate_data(write, Some(Box::new(connection))),
        Some(info),
    )))
}

struct PendingQuicSessionTunnel {
    connecting: Connecting,
    endpoint: Endpoint,
    local_url: url::Url,
    remote_addr: SocketAddr,
    _handshake_permit: OwnedSemaphorePermit,
}

async fn finish_quic_session_tunnel(
    pending: PendingQuicSessionTunnel,
) -> Result<Box<dyn Tunnel>, TunnelError> {
    let PendingQuicSessionTunnel {
        connecting,
        endpoint,
        local_url,
        remote_addr,
        _handshake_permit,
    } = pending;
    let connection = tokio::time::timeout(QUIC_ACCEPT_COMPLETION_TIMEOUT, connecting)
        .await
        .map_err(TunnelError::Timeout)?
        .with_context(|| "accept connection failed")?;
    let (write, read) =
        tokio::time::timeout(QUIC_ACCEPT_COMPLETION_TIMEOUT, connection.accept_bi())
            .await
            .map_err(TunnelError::Timeout)?
            .with_context(|| "accept_bi failed")?;
    let connection = Arc::new(ConnWrapper {
        conn: connection,
        _endpoint: Some(endpoint),
        _udp_session_cleanup: None,
    });
    let remote_url = super::build_url_from_socket_addr(&remote_addr.to_string(), "quic");
    let info = TunnelInfo {
        tunnel_type: "quic".to_owned(),
        local_addr: Some(local_url.into()),
        remote_addr: Some(remote_url.clone().into()),
        resolved_remote_addr: Some(remote_url.into()),
    };
    Ok(Box::new(TunnelWrapper::new(
        FramedReader::new_with_associate_data(read, 2000, Some(Box::new(connection.clone()))),
        FramedWriter::new_with_associate_data(write, Some(Box::new(connection))),
        Some(info),
    )))
}

async fn run_quic_accepted_session(
    endpoint: Endpoint,
    local_url: url::Url,
    handshakes: Arc<Semaphore>,
    completed: Sender<Result<Box<dyn Tunnel>, TunnelError>>,
) {
    let mut complete_tasks = JoinSet::new();
    let mut pending_incoming: Option<Incoming> = None;
    loop {
        tokio::select! {
            Some(result) = complete_tasks.join_next(), if !complete_tasks.is_empty() => {
                let result = match result {
                    Ok(result) => result,
                    Err(error) => Err(TunnelError::InternalError(
                        format!("quic accept task failed: {error}"),
                    )),
                };
                if completed.send(result).await.is_err() {
                    break;
                }
            }
            incoming = endpoint.accept(), if pending_incoming.is_none() => {
                match incoming {
                    Some(incoming) => pending_incoming = Some(incoming),
                    None => break,
                }
            }
            permit = handshakes.clone().acquire_owned(), if pending_incoming.is_some() => {
                let Ok(handshake_permit) = permit else {
                    break;
                };
                let incoming = pending_incoming.take().unwrap();
                let remote_addr = incoming.remote_address();
                match incoming.accept() {
                    Ok(connecting) => {
                        complete_tasks.spawn(finish_quic_session_tunnel(
                            PendingQuicSessionTunnel {
                                connecting,
                                endpoint: endpoint.clone(),
                                local_url: local_url.clone(),
                                remote_addr,
                                _handshake_permit: handshake_permit,
                            },
                        ));
                    }
                    Err(error) => {
                        drop(handshake_permit);
                        if completed
                            .send(Err(anyhow::Error::new(error)
                                .context("quic accept connection failed")
                                .into()))
                            .await
                            .is_err()
                        {
                            break;
                        }
                    }
                }
            }
        }
    }
}

pub(crate) struct QuicAcceptedSession {
    completed: Receiver<Result<Box<dyn Tunnel>, TunnelError>>,
    _accept_task: AbortOnDropHandle<()>,
}

impl QuicAcceptedSession {
    pub(crate) fn new(
        session: UdpSession,
        local_url: url::Url,
        admission: ServerProtocolAdmission,
    ) -> Result<Self, TunnelError> {
        let (active_session, handshake_slots) = admission.into_parts();
        Self::new_with_admission_parts(session, local_url, active_session, handshake_slots)
    }

    fn new_with_admission_parts(
        session: UdpSession,
        local_url: url::Url,
        active_session: OwnedSemaphorePermit,
        handshakes: Arc<Semaphore>,
    ) -> Result<Self, TunnelError> {
        let socket = Arc::new(QuicUdpSessionSocket::from_accepted(
            session,
            active_session,
        )?);
        let runtime = default_runtime().ok_or(TunnelError::InternalError(
            "no async runtime found".to_owned(),
        ))?;
        let endpoint = Endpoint::new_with_abstract_socket(
            endpoint_config(),
            Some(server_config()),
            socket,
            runtime,
        )?;
        let (completed_tx, completed) = channel(100);
        let accept_task = AbortOnDropHandle::new(tokio::spawn(run_quic_accepted_session(
            endpoint,
            local_url,
            handshakes,
            completed_tx,
        )));
        Ok(Self {
            completed,
            _accept_task: accept_task,
        })
    }

    pub(crate) async fn accept(&mut self) -> Result<Box<dyn Tunnel>, TunnelError> {
        while let Some(result) = self.completed.recv().await {
            match result {
                Ok(tunnel) => return Ok(tunnel),
                Err(error) => {
                    tracing::warn!(?error, "QUIC session connection failed");
                }
            }
        }
        Err(TunnelError::Shutdown)
    }
}

#[async_trait::async_trait]
impl ServerTunnelAcceptor for QuicAcceptedSession {
    async fn accept(&mut self) -> anyhow::Result<Box<dyn Tunnel>> {
        Ok(QuicAcceptedSession::accept(self).await?)
    }
}

#[async_trait::async_trait]
impl easytier_core::connectivity::protocol::raw::TunnelDialer for QuicTunnelConnector {
    async fn connect(&self) -> anyhow::Result<Box<dyn Tunnel>> {
        Ok(self.connect_tunnel().await?)
    }

    fn remote_url(&self) -> url::Url {
        self.addr.clone()
    }
}

#[cfg(test)]
mod tests {
    use crate::common::global_ctx::tests::get_mock_global_ctx_with_network;
    use crate::socket::udp::RuntimeUdpSessionControlHandler;
    use crate::tunnel::common::tests::{_tunnel_bench, _tunnel_pingpong};
    use easytier_core::{
        connectivity::protocol::{ServerProtocolAdmissionController, raw::TunnelDialer},
        connectivity::transport::{UdpSessionMode, connect_udp},
        listener::SocketListener,
        packet::ZCPacket,
        socket::udp::{UdpBindOptions, VirtualUdpSocket},
    };
    use futures::{SinkExt, StreamExt, future::poll_fn};
    use std::io::IoSliceMut;
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

    struct SessionQuicConnector {
        remote_url: url::Url,
    }

    #[async_trait::async_trait]
    impl easytier_core::connectivity::protocol::raw::TunnelDialer for SessionQuicConnector {
        async fn connect(&self) -> anyhow::Result<Box<dyn Tunnel>> {
            let remote_addr =
                SocketAddr::from_url(self.remote_url.clone(), IpVersion::Both).await?;
            let connected = connect_udp(
                Arc::new(RuntimeUdpSessionControlHandler),
                remote_addr,
                Vec::new(),
                UdpBindOptions::direct_connect(),
                UdpSessionMode::Classified(UdpSessionProtocol::Quic),
            )
            .await?;
            Ok(upgrade_connected(connected, self.remote_url.clone()).await?)
        }

        fn remote_url(&self) -> url::Url {
            self.remote_url.clone()
        }
    }

    fn stopped_client_endpoint() -> (Endpoint, SocketAddr) {
        let rt = Builder::new_current_thread().enable_all().build().unwrap();
        let endpoint = rt.block_on(async {
            QuicEndpointManager::try_create((Ipv4Addr::UNSPECIFIED, 0).into(), false, None).unwrap()
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
    fn quic_over_connected_udp_session_pingpong() {
        RUNTIME.block_on(async {
            let listener =
                QuicTunnelListener::new("quic://127.0.0.1:21013".parse().unwrap(), global_ctx());
            let connector = SessionQuicConnector {
                remote_url: "quic://127.0.0.1:21013".parse().unwrap(),
            };
            _tunnel_pingpong(listener, connector).await;
        })
    }

    #[test]
    fn accepted_udp_session_supports_multiple_quic_connections() {
        RUNTIME.block_on(async {
            tokio::time::timeout(Duration::from_secs(5), async {
                let bind_addr: SocketAddr = "127.0.0.1:0".parse().unwrap();
                let mut listener = new_runtime_udp_session_listener(
                    format!("quic://{bind_addr}").parse().unwrap(),
                    UdpSessionListenRequest::new(
                        UdpBindOptions::port_bound_listener(bind_addr).with_only_v6(false),
                    ),
                    UdpSessionAcceptKind::Classified(UdpSessionProtocol::Quic),
                    NetNS::new(None),
                );
                listener.listen().await.unwrap();
                let remote_addr = listener.bound_socket().unwrap().local_addr().unwrap();
                let local_url = listener.local_url();

                let connected = connect_udp(
                    Arc::new(RuntimeUdpSessionControlHandler),
                    remote_addr,
                    Vec::new(),
                    UdpBindOptions::direct_connect(),
                    UdpSessionMode::Classified(UdpSessionProtocol::Quic),
                )
                .await
                .unwrap();
                let socket = Arc::new(QuicUdpSessionSocket::new(connected).unwrap());
                let runtime = default_runtime().unwrap();
                let mut endpoint =
                    Endpoint::new_with_abstract_socket(endpoint_config(), None, socket, runtime)
                        .unwrap();
                endpoint.set_default_client_config(client_config());

                let server_task = tokio::spawn(async move {
                    let session = listener.accept().await.unwrap();
                    let admission = ServerProtocolAdmissionController::new(1, 2)
                        .try_admit()
                        .unwrap();
                    let mut accepted =
                        QuicAcceptedSession::new(session, local_url, admission).unwrap();
                    let first = accepted.accept().await.unwrap();
                    let second = accepted.accept().await.unwrap();
                    assert!(
                        tokio::time::timeout(Duration::from_millis(50), listener.accept())
                            .await
                            .is_err(),
                        "both QUIC connections must use the first accepted UDP session"
                    );
                    (first, second)
                });

                let first_connection = endpoint
                    .connect(remote_addr, "localhost")
                    .unwrap()
                    .await
                    .unwrap();
                let (first_write, first_read) = first_connection.open_bi().await.unwrap();
                let mut first_send = FramedWriter::new(first_write);
                first_send
                    .send(ZCPacket::new_with_payload(b"first QUIC connection"))
                    .await
                    .unwrap();
                let second_connection = endpoint
                    .connect(remote_addr, "localhost")
                    .unwrap()
                    .await
                    .unwrap();
                let (second_write, second_read) = second_connection.open_bi().await.unwrap();
                let mut second_send = FramedWriter::new(second_write);
                second_send
                    .send(ZCPacket::new_with_payload(b"second QUIC connection"))
                    .await
                    .unwrap();
                let (first_server, second_server) = server_task.await.unwrap();

                drop(first_send);
                drop(first_read);
                drop(first_server);
                first_connection.close(0u32.into(), b"first connection done");

                let echo_task = tokio::spawn(crate::tunnel::common::tests::_tunnel_echo_server(
                    second_server,
                    true,
                ));
                let mut recv = FramedReader::new(second_read, 4500);
                let packet = recv.next().await.unwrap().unwrap();
                assert_eq!(packet.payload(), b"second QUIC connection".as_slice());
                let _ = second_send.close().await;
                echo_task.await.unwrap();
                second_connection.close(0u32.into(), b"second connection done");
                endpoint.close(0u32.into(), b"test done");
            })
            .await
            .unwrap();
        });
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
    fn listener_uses_udp_session_listener_outside_endpoint_manager() {
        RUNTIME.block_on(listener_uses_udp_session_listener_outside_endpoint_manager_impl())
    }
    async fn listener_uses_udp_session_listener_outside_endpoint_manager_impl() {
        let global_ctx = global_ctx();
        let mut listener =
            QuicTunnelListener::new("quic://127.0.0.1:0".parse().unwrap(), global_ctx.clone());
        listener.listen().await.unwrap();
        let listener_addr = SocketAddr::from_url(listener.local_url(), IpVersion::Both)
            .await
            .unwrap();

        assert!(!QuicEndpointManager::load(&global_ctx).contains_local_addr(listener_addr));
    }

    #[test]
    fn listener_socket_drops_oversized_datagrams() {
        RUNTIME.block_on(listener_socket_drops_oversized_datagrams_impl())
    }
    async fn listener_socket_drops_oversized_datagrams_impl() {
        let send_socket = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let local_addr = send_socket.local_addr().unwrap();
        let peer_addr: SocketAddr = "127.0.0.1:31000".parse().unwrap();
        let (incoming_tx, incoming_rx) = channel(2);
        incoming_tx
            .send(Ok(QuicUdpDatagram {
                payload: vec![0; 1500],
                peer_addr,
                dst_ip: None,
            }))
            .await
            .unwrap();
        incoming_tx
            .send(Ok(QuicUdpDatagram {
                payload: b"ok".to_vec(),
                peer_addr,
                dst_ip: None,
            }))
            .await
            .unwrap();

        let socket = QuicUdpListenerSocket {
            send_socket,
            local_addr,
            incoming: StdMutex::new(incoming_rx),
            _accept_task: AbortOnDropHandle::new(tokio::spawn(async {
                std::future::pending::<()>().await
            })),
        };
        let mut storage = [0; 8];
        let mut bufs = [IoSliceMut::new(&mut storage)];
        let mut meta = [RecvMeta::default()];
        let msgs = poll_fn(|cx| socket.poll_recv(cx, &mut bufs, &mut meta))
            .await
            .unwrap();

        assert_eq!(msgs, 1);
        assert_eq!(meta[0].addr, peer_addr);
        assert_eq!(meta[0].len, 2);
        assert_eq!(&bufs[0][..2], b"ok");
    }

    #[test]
    fn quic_udp_session_cleanup_notifies_and_removes_peer() {
        RUNTIME.block_on(quic_udp_session_cleanup_notifies_and_removes_peer_impl())
    }
    async fn quic_udp_session_cleanup_notifies_and_removes_peer_impl() {
        let peer_addr: SocketAddr = "127.0.0.1:31001".parse().unwrap();
        let closers = Arc::new(StdMutex::new(HashMap::new()));
        let pending_initials = Arc::new(StdMutex::new(HashMap::new()));
        let (close_tx, mut close_rx) = watch::channel(false);
        let closer = Arc::new(QuicUdpSessionCloser::new(close_tx));
        closers.lock().unwrap().insert(peer_addr, closer.clone());

        drop(QuicUdpSessionCleanup::new(
            (peer_addr, vec![1]),
            closer,
            closers.clone(),
            pending_initials,
        ));

        close_rx.changed().await.unwrap();
        assert!(*close_rx.borrow());
        assert!(!closers.lock().unwrap().contains_key(&peer_addr));
    }

    #[test]
    fn quic_udp_session_cleanup_drop_outside_runtime_does_not_panic() {
        let peer_addr: SocketAddr = "127.0.0.1:31011".parse().unwrap();
        let initial_key = (peer_addr, vec![1]);
        let closers = Arc::new(StdMutex::new(HashMap::new()));
        let pending_initials = Arc::new(StdMutex::new(HashMap::new()));
        let (close_tx, close_rx) = watch::channel(false);
        let closer = Arc::new(QuicUdpSessionCloser::new(close_tx));
        assert!(closer.try_claim(&initial_key));
        closers.lock().unwrap().insert(peer_addr, closer.clone());

        let cleanup = QuicUdpSessionCleanup::new(
            initial_key.clone(),
            closer.clone(),
            closers.clone(),
            pending_initials.clone(),
        );
        let pending_initials_guard = pending_initials.lock().unwrap();
        let dropper = std::thread::spawn(move || drop(cleanup));

        std::thread::sleep(Duration::from_millis(20));
        assert!(!*close_rx.borrow());
        drop(pending_initials_guard);
        dropper.join().unwrap();

        assert!(*close_rx.borrow());
        assert!(!closers.lock().unwrap().contains_key(&peer_addr));
        assert!(!pending_initials.lock().unwrap().contains_key(&initial_key));
        assert_eq!(closer.claimed_initial_count(), 0);
    }

    #[test]
    fn quic_udp_session_cleanup_closes_after_last_connection() {
        RUNTIME.block_on(quic_udp_session_cleanup_closes_after_last_connection_impl())
    }
    async fn quic_udp_session_cleanup_closes_after_last_connection_impl() {
        let peer_addr: SocketAddr = "127.0.0.1:31006".parse().unwrap();
        let closers = Arc::new(StdMutex::new(HashMap::new()));
        let pending_initials = Arc::new(StdMutex::new(HashMap::new()));
        let (close_tx, mut close_rx) = watch::channel(false);
        let closer = Arc::new(QuicUdpSessionCloser::new(close_tx));
        closers.lock().unwrap().insert(peer_addr, closer.clone());

        let first_cleanup = QuicUdpSessionCleanup::new(
            (peer_addr, vec![1]),
            closer.clone(),
            closers.clone(),
            pending_initials.clone(),
        );
        let second_cleanup = QuicUdpSessionCleanup::new(
            (peer_addr, vec![2]),
            closer.clone(),
            closers.clone(),
            pending_initials,
        );

        drop(first_cleanup);
        assert!(
            tokio::time::timeout(Duration::from_millis(20), close_rx.changed())
                .await
                .is_err()
        );
        assert!(
            closers
                .lock()
                .unwrap()
                .get(&peer_addr)
                .is_some_and(|current| Arc::ptr_eq(current, &closer))
        );

        drop(second_cleanup);
        close_rx.changed().await.unwrap();
        assert!(*close_rx.borrow());
        assert!(!closers.lock().unwrap().contains_key(&peer_addr));
    }

    #[test]
    fn stale_quic_udp_session_cleanup_does_not_close_newer_peer_session() {
        RUNTIME.block_on(stale_quic_udp_session_cleanup_does_not_close_newer_peer_session_impl())
    }
    async fn stale_quic_udp_session_cleanup_does_not_close_newer_peer_session_impl() {
        let peer_addr: SocketAddr = "127.0.0.1:31002".parse().unwrap();
        let closers = Arc::new(StdMutex::new(HashMap::new()));
        let pending_initials = Arc::new(StdMutex::new(HashMap::new()));
        let (old_close_tx, mut old_close_rx) = watch::channel(false);
        let (new_close_tx, new_close_rx) = watch::channel(false);
        let old_closer = Arc::new(QuicUdpSessionCloser::new(old_close_tx));
        let new_closer = Arc::new(QuicUdpSessionCloser::new(new_close_tx));
        let cleanup = QuicUdpSessionCleanup::new(
            (peer_addr, vec![1]),
            old_closer,
            closers.clone(),
            pending_initials,
        );
        closers
            .lock()
            .unwrap()
            .insert(peer_addr, new_closer.clone());

        drop(cleanup);

        old_close_rx.changed().await.unwrap();
        assert!(*old_close_rx.borrow());
        assert!(!*new_close_rx.borrow());
        assert!(
            closers
                .lock()
                .unwrap()
                .get(&peer_addr)
                .is_some_and(|current| Arc::ptr_eq(current, &new_closer))
        );
    }

    #[test]
    fn pending_quic_initial_keeps_first_generation_for_reused_dcid() {
        let peer_addr: SocketAddr = "127.0.0.1:31003".parse().unwrap();
        let pending_initials = Arc::new(StdMutex::new(HashMap::new()));
        let (old_close_tx, _) = watch::channel(false);
        let (new_close_tx, _) = watch::channel(false);
        let old_closer = Arc::new(QuicUdpSessionCloser::new(old_close_tx));
        let new_closer = Arc::new(QuicUdpSessionCloser::new(new_close_tx));
        let initial_key = (peer_addr, vec![1, 2, 3, 4]);

        assert!(matches!(
            register_pending_initial(&pending_initials, initial_key.clone(), old_closer.clone()),
            PendingInitialRegister::Registered
        ));
        assert!(matches!(
            register_pending_initial(&pending_initials, initial_key.clone(), old_closer.clone()),
            PendingInitialRegister::AlreadyRegisteredSameGeneration
        ));
        assert!(matches!(
            register_pending_initial(&pending_initials, initial_key.clone(), new_closer),
            PendingInitialRegister::OccupiedByOtherGeneration
        ));
        assert!(
            pending_initials
                .lock()
                .unwrap()
                .get(&initial_key)
                .is_some_and(|current| Arc::ptr_eq(&current.closer, &old_closer))
        );
    }

    #[test]
    fn pending_quic_initial_accepts_multiple_dcids_for_same_generation() {
        let peer_addr: SocketAddr = "127.0.0.1:31004".parse().unwrap();
        let pending_initials = Arc::new(StdMutex::new(HashMap::new()));
        let (close_tx, _) = watch::channel(false);
        let closer = Arc::new(QuicUdpSessionCloser::new(close_tx));
        let first_key = (peer_addr, vec![1]);
        let second_key = (peer_addr, vec![2]);

        assert!(matches!(
            register_pending_initial(&pending_initials, first_key.clone(), closer.clone()),
            PendingInitialRegister::Registered
        ));
        assert!(matches!(
            register_pending_initial(&pending_initials, second_key.clone(), closer.clone()),
            PendingInitialRegister::Registered
        ));
        let pending_initials = pending_initials.lock().unwrap();
        assert!(
            pending_initials
                .get(&first_key)
                .is_some_and(|current| Arc::ptr_eq(&current.closer, &closer))
        );
        assert!(
            pending_initials
                .get(&second_key)
                .is_some_and(|current| Arc::ptr_eq(&current.closer, &closer))
        );
    }

    #[test]
    fn pending_quic_initial_limits_unclaimed_dcids_per_session() {
        let peer_addr: SocketAddr = "127.0.0.1:31008".parse().unwrap();
        let pending_initials = Arc::new(StdMutex::new(HashMap::new()));
        let (close_tx, _) = watch::channel(false);
        let closer = Arc::new(QuicUdpSessionCloser::new(close_tx));

        for dcid in 0..QUIC_UDP_MAX_PENDING_INITIALS_PER_SESSION {
            assert!(matches!(
                register_pending_initial(
                    &pending_initials,
                    (peer_addr, vec![dcid as u8]),
                    closer.clone()
                ),
                PendingInitialRegister::Registered
            ));
        }
        assert!(matches!(
            register_pending_initial(
                &pending_initials,
                (
                    peer_addr,
                    vec![QUIC_UDP_MAX_PENDING_INITIALS_PER_SESSION as u8]
                ),
                closer,
            ),
            PendingInitialRegister::TooManyPendingInitials
        ));
    }

    #[test]
    fn pending_quic_initial_limits_claimed_dcids_per_session() {
        let peer_addr: SocketAddr = "127.0.0.1:31009".parse().unwrap();
        let pending_initials = Arc::new(StdMutex::new(HashMap::new()));
        let (close_tx, _) = watch::channel(false);
        let closer = Arc::new(QuicUdpSessionCloser::new(close_tx));

        for dcid in 0..QUIC_UDP_MAX_CLAIMED_INITIALS_PER_SESSION {
            let key = (peer_addr, vec![dcid as u8]);
            assert!(matches!(
                register_pending_initial(&pending_initials, key.clone(), closer.clone()),
                PendingInitialRegister::Registered
            ));
            assert!(claim_pending_initial(&pending_initials, &key).is_some());
        }
        assert_eq!(
            closer.claimed_initial_count(),
            QUIC_UDP_MAX_CLAIMED_INITIALS_PER_SESSION
        );

        let overflow_key = (
            peer_addr,
            vec![QUIC_UDP_MAX_CLAIMED_INITIALS_PER_SESSION as u8],
        );
        assert!(matches!(
            register_pending_initial(&pending_initials, overflow_key.clone(), closer),
            PendingInitialRegister::Registered
        ));
        assert!(claim_pending_initial(&pending_initials, &overflow_key).is_none());
        assert!(!pending_initials.lock().unwrap().contains_key(&overflow_key));
    }

    #[test]
    fn pending_quic_initial_keeps_unconsumed_sibling_after_one_dcid_is_claimed() {
        RUNTIME.block_on(
            pending_quic_initial_keeps_unconsumed_sibling_after_one_dcid_is_claimed_impl(),
        )
    }
    async fn pending_quic_initial_keeps_unconsumed_sibling_after_one_dcid_is_claimed_impl() {
        let peer_addr: SocketAddr = "127.0.0.1:31005".parse().unwrap();
        let pending_initials = Arc::new(StdMutex::new(HashMap::new()));
        let closers = Arc::new(StdMutex::new(HashMap::new()));
        let (old_close_tx, _) = watch::channel(false);
        let (new_close_tx, _) = watch::channel(false);
        let old_closer = Arc::new(QuicUdpSessionCloser::new(old_close_tx));
        let new_closer = Arc::new(QuicUdpSessionCloser::new(new_close_tx));
        let claimed_key = (peer_addr, vec![1]);
        let pending_key = (peer_addr, vec![2]);

        assert!(matches!(
            register_pending_initial(&pending_initials, claimed_key.clone(), old_closer.clone()),
            PendingInitialRegister::Registered
        ));
        assert!(matches!(
            register_pending_initial(&pending_initials, pending_key.clone(), old_closer.clone()),
            PendingInitialRegister::Registered
        ));
        let closer = claim_pending_initial(&pending_initials, &claimed_key).unwrap();
        let _cleanup = QuicUdpSessionCleanup::new(
            claimed_key.clone(),
            closer,
            closers,
            pending_initials.clone(),
        );

        assert!(matches!(
            register_pending_initial(&pending_initials, claimed_key.clone(), old_closer.clone()),
            PendingInitialRegister::AlreadyClaimedSameGeneration
        ));
        retain_pending_initial_tombstone_for_stale_incoming(
            pending_initials.clone(),
            claimed_key.clone(),
            old_closer.clone(),
        );
        retain_pending_initial_tombstone_for_stale_incoming(
            pending_initials.clone(),
            pending_key.clone(),
            old_closer.clone(),
        );

        assert!(matches!(
            register_pending_initial(&pending_initials, pending_key.clone(), new_closer),
            PendingInitialRegister::OccupiedByOtherGeneration
        ));
        assert!(
            pending_initials
                .lock()
                .unwrap()
                .get(&pending_key)
                .is_some_and(|current| Arc::ptr_eq(&current.closer, &old_closer))
        );
        assert!(!pending_initials.lock().unwrap().contains_key(&claimed_key));
    }

    #[test]
    fn pending_quic_initial_tombstone_is_not_claimable() {
        RUNTIME.block_on(pending_quic_initial_tombstone_is_not_claimable_impl())
    }
    async fn pending_quic_initial_tombstone_is_not_claimable_impl() {
        let peer_addr: SocketAddr = "127.0.0.1:31012".parse().unwrap();
        let pending_initials = Arc::new(StdMutex::new(HashMap::new()));
        let (close_tx, _) = watch::channel(false);
        let closer = Arc::new(QuicUdpSessionCloser::new(close_tx));
        let initial_key = (peer_addr, vec![1]);

        assert!(matches!(
            register_pending_initial(&pending_initials, initial_key.clone(), closer.clone()),
            PendingInitialRegister::Registered
        ));
        retain_pending_initial_tombstone_for_stale_incoming_after(
            pending_initials.clone(),
            initial_key.clone(),
            closer,
            Duration::from_millis(1),
        );

        assert!(claim_pending_initial(&pending_initials, &initial_key).is_none());
        tokio::time::sleep(Duration::from_millis(20)).await;
        assert!(!pending_initials.lock().unwrap().contains_key(&initial_key));
    }

    #[test]
    fn quic_initial_tombstones_outlive_unclaimed_sessions_and_accepts() {
        assert!(QUIC_UDP_UNCLAIMED_INITIAL_TIMEOUT > QUIC_UDP_UNCLAIMED_SESSION_TIMEOUT);
        assert!(QUIC_UDP_STALE_INCOMING_TOMBSTONE_TIMEOUT > QUIC_ACCEPT_COMPLETION_TIMEOUT);
    }

    #[test]
    fn pending_quic_initial_expires_unclaimed_sibling_while_session_is_claimed() {
        RUNTIME.block_on(
            pending_quic_initial_expires_unclaimed_sibling_while_session_is_claimed_impl(),
        )
    }
    async fn pending_quic_initial_expires_unclaimed_sibling_while_session_is_claimed_impl() {
        let peer_addr: SocketAddr = "127.0.0.1:31007".parse().unwrap();
        let pending_initials = Arc::new(StdMutex::new(HashMap::new()));
        let closers = Arc::new(StdMutex::new(HashMap::new()));
        let (close_tx, _) = watch::channel(false);
        let closer = Arc::new(QuicUdpSessionCloser::new(close_tx));
        let claimed_key = (peer_addr, vec![1]);
        let pending_key = (peer_addr, vec![2]);

        assert!(matches!(
            register_pending_initial(&pending_initials, claimed_key.clone(), closer.clone()),
            PendingInitialRegister::Registered
        ));
        assert!(matches!(
            register_pending_initial(&pending_initials, pending_key.clone(), closer.clone()),
            PendingInitialRegister::Registered
        ));
        let claimed = claim_pending_initial(&pending_initials, &claimed_key).unwrap();
        let _cleanup = QuicUdpSessionCleanup::new(
            claimed_key.clone(),
            claimed,
            closers,
            pending_initials.clone(),
        );

        expire_unclaimed_pending_initial_after(
            pending_initials.clone(),
            pending_key.clone(),
            closer,
            Duration::from_millis(1),
        );
        tokio::time::sleep(Duration::from_millis(20)).await;

        assert!(!pending_initials.lock().unwrap().contains_key(&pending_key));
    }

    #[test]
    fn claimed_quic_initial_tombstone_expires() {
        RUNTIME.block_on(claimed_quic_initial_tombstone_expires_impl())
    }
    async fn claimed_quic_initial_tombstone_expires_impl() {
        let peer_addr: SocketAddr = "127.0.0.1:31010".parse().unwrap();
        let pending_initials = Arc::new(StdMutex::new(HashMap::new()));
        let (old_close_tx, _) = watch::channel(false);
        let (new_close_tx, _) = watch::channel(false);
        let old_closer = Arc::new(QuicUdpSessionCloser::new(old_close_tx));
        let new_closer = Arc::new(QuicUdpSessionCloser::new(new_close_tx));
        let initial_key = (peer_addr, vec![1]);

        assert!(old_closer.try_claim(&initial_key));
        retain_claimed_initial_tombstone_for_stale_incoming_after(
            pending_initials.clone(),
            initial_key.clone(),
            old_closer.clone(),
            Duration::from_millis(1),
            Some(Handle::current()),
        );
        assert!(matches!(
            register_pending_initial(&pending_initials, initial_key.clone(), new_closer.clone()),
            PendingInitialRegister::OccupiedByOtherGeneration
        ));

        tokio::time::sleep(Duration::from_millis(20)).await;

        assert_eq!(old_closer.claimed_initial_count(), 0);
        assert!(matches!(
            register_pending_initial(&pending_initials, initial_key, new_closer),
            PendingInitialRegister::Registered
        ));
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
                .connect_with_ip_version("127.0.0.1:0".parse().unwrap(), IpVersion::V4, None)
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
        let connector =
            QuicTunnelConnector::new("quic://127.0.0.1:0".parse().unwrap(), global_ctx());
        let err = format!("{:?}", connector.connect().await.unwrap_err());
        assert!(
            err.contains("invalid remote address"),
            "unexpected error: {}",
            err
        );
    }
}
