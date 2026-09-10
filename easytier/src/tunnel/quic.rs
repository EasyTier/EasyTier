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
use quinn::{
    AsyncUdpSocket, ClientConfig, Connecting, Connection, Endpoint, EndpointConfig, Incoming,
    ServerConfig, TransportConfig, congestion::BbrConfig, default_runtime,
};
use std::{net::SocketAddr, sync::Arc, time::Duration};
use tokio::{
    sync::{
        OwnedSemaphorePermit, Semaphore,
        mpsc::{Receiver, Sender, channel},
    },
    task::JoinSet,
};
use tokio_util::task::AbortOnDropHandle;

mod session_socket;
pub(crate) use session_socket::QuicUdpSessionSocket;

// region config
mod crypto {
    use crate::tunnel::quic::QUIC_VERSION_ETQ1;
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
    struct CryptoKey {
        /// Bind the packet checksum to the packet number so that a truncated
        /// packet number decoded out of window (RFC 9000 Appendix A) fails
        /// authentication instead of acknowledging an unsent packet number.
        pn_bound: bool,
    }

    impl CryptoKey {
        fn for_version(version: u32) -> Self {
            Self {
                pn_bound: version == QUIC_VERSION_ETQ1,
            }
        }

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

        // The packet number is mixed into the checksum before the slices. Real
        // QUIC derives the AEAD nonce from the packet number, so a number
        // decoded differently from how it was encoded fails authentication;
        // this mirrors that property for the SeaHash integrity check.
        fn checksum_with_packet(packet: u64, slices: &[&[u8]]) -> u64 {
            let mut hasher = SeaHasher::default();
            hasher.write(&packet.to_le_bytes());
            for slice in slices {
                hasher.write(&(slice.len() as u64).to_le_bytes());
                hasher.write(slice);
            }
            hasher.finish()
        }

        fn checksum_for(&self, packet: u64, slices: &[&[u8]]) -> u64 {
            if self.pn_bound {
                Self::checksum_with_packet(packet, slices)
            } else {
                Self::checksum(slices)
            }
        }
    }

    impl PacketKey for CryptoKey {
        #[instrument(level = "trace")]
        fn encrypt(&self, packet: u64, buf: &mut [u8], header_len: usize) {
            let (header, rest) = buf.split_at_mut(header_len);
            let (payload, tag) = rest.split_at_mut(rest.len() - self.tag_len());
            let checksum = self.checksum_for(packet, &[header, payload]);
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
            let checksum = self.checksum_for(packet, &[header, payload]);
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
        key: CryptoKey,
        state: HandshakeState,
        local: TransportParameters,
        remote: Option<TransportParameters>,
    }

    impl QuicSession {
        fn new(side: Side, version: u32, params: TransportParameters) -> Self {
            Self {
                side,
                key: CryptoKey::for_version(version),
                state: HandshakeState::EmitInitial,
                local: params,
                remote: None,
            }
        }
    }

    impl Session for QuicSession {
        fn initial_keys(&self, _: &ConnectionId, _: Side) -> Keys {
            self.key.keys()
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
                    Some(self.key.keys())
                }
                HandshakeState::EmitHandshake => {
                    if self.side.is_server() {
                        self.local.write(buf);
                    }
                    self.state = HandshakeState::Done;
                    Some(self.key.keys())
                }
                HandshakeState::Done => None,
            }
        }

        fn next_1rtt_keys(&mut self) -> Option<KeyPair<Box<dyn PacketKey>>> {
            Some(self.key.packet())
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
            Ok(Box::new(QuicSession::new(Side::Client, version, *params)))
        }
    }

    impl ServerConfig for CryptoConfig {
        fn initial_keys(&self, version: u32, _: &ConnectionId) -> Result<Keys, UnsupportedVersion> {
            Ok(CryptoKey::for_version(version).keys())
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
            Box::new(QuicSession::new(Side::Server, version, *params))
        }
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        fn roundtrip(pn_bound: bool, encrypt_pn: u64, decrypt_pn: u64) -> Result<(), CryptoError> {
            let key = CryptoKey { pn_bound };
            let mut buf = vec![7u8; 8 + 32 + key.tag_len()];
            quinn_proto::crypto::PacketKey::encrypt(&key, encrypt_pn, &mut buf, 8);
            let header = buf[..8].to_vec();
            let mut payload = BytesMut::from(&buf[8..]);
            quinn_proto::crypto::PacketKey::decrypt(&key, decrypt_pn, &header, &mut payload)
        }

        #[test]
        fn legacy_checksum_ignores_packet_number() {
            // Documents the original flaw: a packet number decoded differently
            // from how it was encoded still passes authentication.
            assert!(roundtrip(false, 100, 356).is_ok());
        }

        #[test]
        fn pn_bound_checksum_rejects_shifted_packet_number() {
            assert!(roundtrip(true, 100, 100).is_ok());
            // A 1-byte truncated packet number decoded one window (+256) ahead,
            // as happens when reordering exceeds the RFC 9000 Appendix A
            // decode window, must fail authentication.
            assert!(roundtrip(true, 100, 356).is_err());
        }
    }
}

/// EasyTier custom QUIC version "ETQ1" (0x45545131, outside the reserved
/// `0x??a?a?a?a` grease pattern).
///
/// Connections negotiated on this version bind the packet integrity checksum
/// to the packet number. With the legacy checksum, a 1-byte-encoded packet
/// number that arrives re-ordered beyond the decode window (RFC 9000
/// Appendix A) is decoded as a future packet number; the checksum still
/// passes, the peer ACKs a number that was never sent, and the connection is
/// torn down with `PROTOCOL_VIOLATION("unsent packet acked")`. Binding the
/// checksum to the packet number makes such a misdecode fail authentication,
/// mirroring real QUIC where the AEAD nonce is derived from the packet
/// number. Peers that only speak version 1 reject it via version
/// negotiation, so callers must fall back to [`client_config`] for them.
pub const QUIC_VERSION_ETQ1: u32 = 0x45545131;

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

/// Client config negotiating [`QUIC_VERSION_ETQ1`] for the QUIC proxy.
pub fn proxy_client_config() -> ClientConfig {
    let mut config = client_config();
    config.version(QUIC_VERSION_ETQ1);
    config
}

fn endpoint_config_with_versions(versions: Vec<u32>) -> EndpointConfig {
    let mut config = EndpointConfig::default();
    config.max_udp_payload_size(1200).unwrap();
    config.supported_versions(versions);
    config
}

pub fn endpoint_config() -> EndpointConfig {
    endpoint_config_with_versions(vec![1])
}

/// Endpoint config for the QUIC proxy: accepts both [`QUIC_VERSION_ETQ1`]
/// and legacy version 1, so new and old peers can connect.
pub fn proxy_endpoint_config() -> EndpointConfig {
    endpoint_config_with_versions(vec![QUIC_VERSION_ETQ1, 1])
}
//endregion

const QUIC_ACCEPT_COMPLETION_TIMEOUT: Duration = Duration::from_secs(10);

struct ConnWrapper {
    conn: Connection,
    _endpoint: Endpoint,
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
        _endpoint: endpoint,
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

#[cfg(test)]
mod tests {
    use std::{net::SocketAddr, sync::Arc, time::Duration};

    use easytier_core::{
        connectivity::{
            protocol::ServerProtocolAdmissionController,
            transport::{UdpSessionMode, connect_udp},
        },
        packet::ZCPacket,
        socket::SocketListener,
        socket::udp::{
            UdpBindOptions, UdpSessionAcceptKind, UdpSessionListenRequest, UdpSessionProtocol,
            VirtualUdpSocket,
        },
    };
    use futures::{SinkExt, StreamExt};

    use crate::{
        common::netns::NetNS, host_runtime::native_host_runtime,
        socket::udp::new_runtime_udp_session_listener, tunnel::common::tests::_tunnel_echo_server,
    };

    use super::*;

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
                let mut accepted = QuicAcceptedSession::new(session, local_url, admission).unwrap();
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
                .send(ZCPacket::new_with_payload(b"second QUIC connection ready"))
                .await
                .unwrap();
            let (first_server, second_server) = server_task.await.unwrap();

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
        })
        .await
        .unwrap();
    }
}
