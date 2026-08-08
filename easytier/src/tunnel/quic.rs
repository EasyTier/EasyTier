//! This example demonstrates how to make a QUIC connection that ignores the server certificate.
//!
//! Checkout the `README.md` for guidance.

use crate::proto::common::TunnelInfo;
use anyhow::Context;
use easytier_core::{
    connectivity::{
        protocol::{ServerProtocolAdmission, ServerTunnelAcceptor},
        transport::ConnectedUdpSession,
    },
    socket::udp::UdpSession,
    tunnel::{
        Tunnel, TunnelError,
        framed::{FramedReader, FramedWriter},
        wrapper::TunnelWrapper,
    },
};
use futures::FutureExt as _;
use quinn::{
    AsyncUdpSocket, ClientConfig, Connecting, Connection, Endpoint, EndpointConfig, Incoming,
    ServerConfig, TransportConfig, congestion::BbrConfig, default_runtime,
};
use std::{
    net::SocketAddr,
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
    time::Duration,
};
use tokio::{
    sync::{
        Notify, OwnedSemaphorePermit, Semaphore,
        mpsc::{Receiver, Sender, channel},
    },
    task::JoinSet,
    time::Instant,
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

const QUIC_ACCEPT_COMPLETION_TIMEOUT: Duration = Duration::from_secs(10);
const QUIC_ESTABLISHMENT_TIMEOUT: Duration = Duration::from_secs(30);

struct ConnWrapper {
    conn: Connection,
    _endpoint: Endpoint,
    _activity: Option<QuicActiveConnection>,
}

impl Drop for ConnWrapper {
    fn drop(&mut self) {
        self.conn.close(0u32.into(), b"done");
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
        _endpoint: endpoint,
        _activity: None,
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
    activity: Arc<QuicConnectionActivity>,
    _handshake_permit: OwnedSemaphorePermit,
}

#[derive(Debug, Default)]
struct QuicConnectionActivity {
    active: AtomicUsize,
    changed: Notify,
}

impl QuicConnectionActivity {
    fn active(&self) -> usize {
        self.active.load(Ordering::Acquire)
    }
}

struct QuicActiveConnection {
    activity: Arc<QuicConnectionActivity>,
}

impl QuicActiveConnection {
    fn new(activity: Arc<QuicConnectionActivity>) -> Self {
        activity.active.fetch_add(1, Ordering::AcqRel);
        Self { activity }
    }
}

impl Drop for QuicActiveConnection {
    fn drop(&mut self) {
        self.activity.active.fetch_sub(1, Ordering::AcqRel);
        self.activity.changed.notify_one();
    }
}

async fn finish_quic_session_tunnel(
    pending: PendingQuicSessionTunnel,
) -> Result<Box<dyn Tunnel>, TunnelError> {
    let PendingQuicSessionTunnel {
        connecting,
        endpoint,
        local_url,
        remote_addr,
        activity,
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
        _endpoint: endpoint,
        _activity: Some(QuicActiveConnection::new(activity)),
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

struct QuicAcceptedSessionLease {
    session: Arc<UdpSession>,
    _active_session: OwnedSemaphorePermit,
}

impl Drop for QuicAcceptedSessionLease {
    fn drop(&mut self) {
        self.session.close();
    }
}

fn try_accept_ready(endpoint: &Endpoint) -> Option<Incoming> {
    endpoint.accept().now_or_never().flatten()
}

async fn run_quic_accepted_session(
    endpoint: Endpoint,
    local_url: url::Url,
    handshakes: Arc<Semaphore>,
    completed: Sender<Result<Box<dyn Tunnel>, TunnelError>>,
    lease: QuicAcceptedSessionLease,
    establishment_timeout: Duration,
) {
    let activity = Arc::new(QuicConnectionActivity::default());
    let establishment_deadline = Instant::now() + establishment_timeout;
    let mut complete_tasks = JoinSet::new();
    let mut pending_incoming: Option<Incoming> = None;
    let mut ever_connected = false;

    loop {
        let no_handshake = pending_incoming.is_none() && complete_tasks.is_empty();
        if ever_connected && no_handshake && activity.active() == 0 {
            // A connection drop can become visible alongside a queued replacement Initial.
            let Some(incoming) = try_accept_ready(&endpoint) else {
                break;
            };
            pending_incoming = Some(incoming);
        }

        tokio::select! {
            biased;

            result = complete_tasks.join_next(), if !complete_tasks.is_empty() => {
                let result = match result.expect("nonempty QUIC task set must yield a result") {
                    Ok(Ok(tunnel)) => {
                        ever_connected = true;
                        Ok(tunnel)
                    }
                    Ok(Err(error)) => Err(error),
                    Err(error) => Err(TunnelError::InternalError(
                        format!("quic accept task failed: {error}")
                    )),
                };
                if completed.send(result).await.is_err() {
                    break;
                }
            }
            _ = tokio::time::sleep_until(establishment_deadline), if !ever_connected => {
                break;
            }
            _ = activity.changed.notified() => {}
            permit = handshakes.clone().acquire_owned(), if pending_incoming.is_some() => {
                let Ok(handshake_permit) = permit else {
                    break;
                };
                let incoming = pending_incoming.take().expect("pending QUIC Incoming must exist");
                let remote_addr = incoming.remote_address();
                match incoming.accept() {
                    Ok(connecting) => {
                        complete_tasks.spawn(finish_quic_session_tunnel(
                            PendingQuicSessionTunnel {
                                connecting,
                                endpoint: endpoint.clone(),
                                local_url: local_url.clone(),
                                remote_addr,
                                activity: activity.clone(),
                                _handshake_permit: handshake_permit,
                            },
                        ));
                    }
                    Err(error) => {
                        drop(handshake_permit);
                        let result = Err(
                            anyhow::Error::new(error)
                                .context("quic accept connection failed")
                                .into(),
                        );
                        if completed.send(result).await.is_err() {
                            break;
                        }
                    }
                }
            }
            incoming = endpoint.accept(), if pending_incoming.is_none() => {
                match incoming {
                    Some(incoming) => pending_incoming = Some(incoming),
                    None => break,
                }
            }
        }
    }

    endpoint.close(0u32.into(), b"accepted session retired");
    complete_tasks.abort_all();
    drop(lease);
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
        Self::new_with_establishment_timeout(
            session,
            local_url,
            admission,
            QUIC_ESTABLISHMENT_TIMEOUT,
        )
    }

    fn new_with_establishment_timeout(
        session: UdpSession,
        local_url: url::Url,
        admission: ServerProtocolAdmission,
        establishment_timeout: Duration,
    ) -> Result<Self, TunnelError> {
        let (active_session, handshakes) = admission.into_parts();
        let session = Arc::new(session);
        let lease = QuicAcceptedSessionLease {
            session: session.clone(),
            _active_session: active_session,
        };
        let socket = Arc::new(QuicUdpSessionSocket::from_accepted(session)?);
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
            lease,
            establishment_timeout,
        )));
        Ok(Self {
            completed,
            _accept_task: accept_task,
        })
    }

    pub(crate) async fn accept(&mut self) -> Result<Option<Box<dyn Tunnel>>, TunnelError> {
        while let Some(result) = self.completed.recv().await {
            match result {
                Ok(tunnel) => return Ok(Some(tunnel)),
                Err(error) => {
                    tracing::warn!(?error, "QUIC session connection failed");
                }
            }
        }
        Ok(None)
    }
}

#[async_trait::async_trait]
impl ServerTunnelAcceptor for QuicAcceptedSession {
    async fn accept(&mut self) -> anyhow::Result<Option<Box<dyn Tunnel>>> {
        Ok(QuicAcceptedSession::accept(self).await?)
    }
}

#[cfg(test)]
mod tests {
    use std::{
        io::{self, IoSliceMut},
        net::SocketAddr,
        pin::Pin,
        sync::{Arc, Mutex},
        task::{Context, Poll},
        time::Duration,
    };

    use easytier_core::{
        connectivity::{
            protocol::ServerProtocolAdmissionController,
            transport::{UdpSessionMode, connect_udp},
        },
        packet::ZCPacket,
        socket::SocketListener,
        socket::udp::{
            UdpBindOptions, UdpSessionAcceptKind, UdpSessionListenRequest, UdpSessionProtocol,
            UdpSessionSocket, VirtualUdpSocket, parse_quic_initial_dcid,
        },
    };
    use futures::{SinkExt, StreamExt};
    use quinn::{
        UdpPoller,
        udp::{RecvMeta, Transmit},
    };

    use crate::{
        common::netns::NetNS, host_runtime::native_host_runtime,
        socket::udp::new_runtime_udp_session_listener, tunnel::common::tests::_tunnel_echo_server,
    };

    use super::*;

    fn synthetic_quic_initial(dcid: u8) -> Vec<u8> {
        let mut packet = vec![0; 1200];
        packet[0] = 0xc0;
        packet[4] = 1;
        packet[5] = 1;
        packet[6] = dcid;
        packet[7] = 0;
        packet[8] = 0;
        packet[9] = 1;
        packet
    }

    #[derive(Debug)]
    struct ReplacementInitialObserver {
        inner: Arc<QuicUdpSessionSocket>,
        first_dcid: Mutex<Option<Vec<u8>>>,
        replacement_initial: Notify,
    }

    impl ReplacementInitialObserver {
        fn new(inner: Arc<QuicUdpSessionSocket>) -> Self {
            Self {
                inner,
                first_dcid: Mutex::new(None),
                replacement_initial: Notify::new(),
            }
        }

        fn observe(&self, datagram: &[u8]) {
            let Some(dcid) = parse_quic_initial_dcid(datagram) else {
                return;
            };
            let mut first_dcid = self.first_dcid.lock().unwrap();
            match first_dcid.as_ref() {
                None => *first_dcid = Some(dcid),
                Some(first_dcid) if first_dcid != &dcid => {
                    self.replacement_initial.notify_one();
                }
                Some(_) => {}
            }
        }

        fn saw_first_initial(&self) -> bool {
            self.first_dcid.lock().unwrap().is_some()
        }

        async fn replacement_initial_seen(&self) {
            self.replacement_initial.notified().await;
        }
    }

    impl AsyncUdpSocket for ReplacementInitialObserver {
        fn create_io_poller(self: Arc<Self>) -> Pin<Box<dyn UdpPoller>> {
            self.inner.clone().create_io_poller()
        }

        fn try_send(&self, transmit: &Transmit<'_>) -> io::Result<()> {
            self.inner.try_send(transmit)
        }

        fn poll_recv(
            &self,
            context: &mut Context<'_>,
            buffers: &mut [IoSliceMut<'_>],
            meta: &mut [RecvMeta],
        ) -> Poll<io::Result<usize>> {
            let result = self.inner.poll_recv(context, buffers, meta);
            if let Poll::Ready(Ok(received)) = &result {
                for (buffer, meta) in buffers.iter().zip(meta.iter()).take(*received) {
                    self.observe(&buffer[..meta.len]);
                }
            }
            result
        }

        fn local_addr(&self) -> io::Result<SocketAddr> {
            self.inner.local_addr()
        }

        fn max_transmit_segments(&self) -> usize {
            self.inner.max_transmit_segments()
        }

        fn max_receive_segments(&self) -> usize {
            self.inner.max_receive_segments()
        }

        fn may_fragment(&self) -> bool {
            self.inner.may_fragment()
        }
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn unestablished_quic_session_retires_and_releases_admission() {
        tokio::time::timeout(Duration::from_secs(3), async {
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
            let client = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
            let client_addr = client.local_addr().unwrap();

            client
                .send_to(&synthetic_quic_initial(1), remote_addr)
                .await
                .unwrap();
            let session = listener.accept().await.unwrap();
            let admission = ServerProtocolAdmissionController::new(1, 1);
            let permit = admission.try_admit().unwrap();
            let mut accepted = QuicAcceptedSession::new_with_establishment_timeout(
                session,
                local_url,
                permit,
                Duration::from_millis(100),
            )
            .unwrap();

            assert!(accepted.accept().await.unwrap().is_none());
            assert!(admission.try_admit().is_some());

            client
                .send_to(&synthetic_quic_initial(2), remote_addr)
                .await
                .unwrap();
            let fresh = tokio::time::timeout(Duration::from_secs(1), listener.accept())
                .await
                .unwrap()
                .unwrap();
            assert_eq!(fresh.peer_addr().unwrap(), client_addr);
        })
        .await
        .unwrap();
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn queued_replacement_initial_is_accepted_before_idle_retirement() {
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
                native_host_runtime(),
                remote_addr,
                Vec::new(),
                UdpBindOptions::direct_connect(),
                UdpSessionMode::Classified(UdpSessionProtocol::Quic),
            )
            .await
            .unwrap();
            let socket = Arc::new(QuicUdpSessionSocket::new(connected).unwrap());
            let runtime = default_runtime().unwrap();
            let mut client_endpoint =
                Endpoint::new_with_abstract_socket(endpoint_config(), None, socket, runtime)
                    .unwrap();
            client_endpoint.set_default_client_config(client_config());

            let first_connecting = client_endpoint.connect(remote_addr, "localhost").unwrap();
            let first_client = tokio::spawn(async move {
                let connection = first_connecting.await.unwrap();
                let (write, read) = connection.open_bi().await.unwrap();
                let mut write = FramedWriter::new(write);
                write
                    .send(ZCPacket::new_with_payload(b"first QUIC connection"))
                    .await
                    .unwrap();
                (connection, (write, read))
            });

            let session = Arc::new(listener.accept().await.unwrap());
            let socket = Arc::new(QuicUdpSessionSocket::from_accepted(session.clone()).unwrap());
            let observer = Arc::new(ReplacementInitialObserver::new(socket));
            let runtime = default_runtime().unwrap();
            let endpoint = Endpoint::new_with_abstract_socket(
                endpoint_config(),
                Some(server_config()),
                observer.clone(),
                runtime,
            )
            .unwrap();
            let endpoint_sync = endpoint.clone();
            let admission = ServerProtocolAdmissionController::new(1, 2)
                .try_admit()
                .unwrap();
            let (active_session, handshakes) = admission.into_parts();
            let lease = QuicAcceptedSessionLease {
                session,
                _active_session: active_session,
            };
            let (completed_tx, mut completed) = channel(2);
            let runner = run_quic_accepted_session(
                endpoint,
                local_url,
                handshakes,
                completed_tx,
                lease,
                Duration::from_secs(2),
            );
            tokio::pin!(runner);

            let first_server = tokio::select! {
                () = &mut runner => panic!("accepted QUIC session retired before first tunnel"),
                result = completed.recv() => result
                    .expect("accepted QUIC session must report first tunnel")
                    .expect("first QUIC tunnel must complete"),
            };
            let (first_connection, first_streams) = first_client.await.unwrap();
            assert!(observer.saw_first_initial());

            let second_connecting = client_endpoint.connect(remote_addr, "localhost").unwrap();
            let second_client = tokio::spawn(async move {
                let connection = second_connecting.await.unwrap();
                let (write, read) = connection.open_bi().await.unwrap();
                let mut write = FramedWriter::new(write);
                write
                    .send(ZCPacket::new_with_payload(b"replacement QUIC connection"))
                    .await
                    .unwrap();
                (connection, (write, read))
            });
            tokio::time::timeout(Duration::from_secs(1), observer.replacement_initial_seen())
                .await
                .expect("replacement QUIC Initial must reach the accepted session");
            // The endpoint driver holds its state lock while polling the socket and
            // queuing Incoming values. Acquiring it here waits for that poll to finish.
            let _ = endpoint_sync.stats();

            // The runner remains unpolled while Quinn queues the replacement Initial.
            // Dropping the final active tunnel now makes both select branches ready.
            drop(first_server);

            let second_server = tokio::select! {
                () = &mut runner => {
                    panic!("accepted QUIC session retired with a replacement Initial queued")
                }
                result = completed.recv() => result
                    .expect("accepted QUIC session must report replacement tunnel")
                    .expect("replacement QUIC tunnel must complete"),
            };
            let (second_connection, second_streams) = second_client.await.unwrap();
            assert!(
                tokio::time::timeout(Duration::from_millis(50), listener.accept())
                    .await
                    .is_err(),
                "replacement QUIC connection must use the first accepted UDP session"
            );

            drop(second_server);
            drop(first_streams);
            drop(second_streams);
            first_connection.close(0u32.into(), b"first connection done");
            second_connection.close(0u32.into(), b"second connection done");
            client_endpoint.close(0u32.into(), b"client test done");
        })
        .await
        .unwrap();
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn accepted_udp_session_supports_multiple_quic_connections() {
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
                native_host_runtime(),
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
                let mut accepted = QuicAcceptedSession::new_with_establishment_timeout(
                    session,
                    local_url,
                    admission,
                    Duration::from_secs(2),
                )
                .unwrap();
                let first = accepted.accept().await.unwrap().unwrap();
                let second = accepted.accept().await.unwrap().unwrap();
                assert!(
                    tokio::time::timeout(Duration::from_millis(50), listener.accept())
                        .await
                        .is_err(),
                    "both QUIC connections must use the first accepted UDP session"
                );
                (first, second, accepted)
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
                .send(ZCPacket::new_with_payload(b"second QUIC connection ready"))
                .await
                .unwrap();
            let (first_server, second_server, accepted) = server_task.await.unwrap();

            drop(first_send);
            drop(first_read);
            drop(first_server);
            first_connection.close(0u32.into(), b"first connection done");

            let echo_task = tokio::spawn(_tunnel_echo_server(second_server, false));
            let mut recv = FramedReader::new(second_read, 4500);
            let ready = recv.next().await.unwrap().unwrap();
            assert_eq!(ready.payload(), b"second QUIC connection ready".as_slice());
            second_send
                .send(ZCPacket::new_with_payload(
                    b"second QUIC connection after first closed",
                ))
                .await
                .unwrap();
            let packet = recv.next().await.unwrap().unwrap();
            assert_eq!(
                packet.payload(),
                b"second QUIC connection after first closed".as_slice()
            );
            let _ = second_send.close().await;
            echo_task.await.unwrap();
            second_connection.close(0u32.into(), b"second connection done");
            endpoint.close(0u32.into(), b"test done");
            let mut accepted = accepted;
            assert!(
                tokio::time::timeout(Duration::from_secs(1), accepted.accept())
                    .await
                    .unwrap()
                    .unwrap()
                    .is_none()
            );
        })
        .await
        .unwrap();
    }
}
