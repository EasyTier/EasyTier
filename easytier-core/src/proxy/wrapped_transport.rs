use std::sync::{Arc, Weak};

use async_trait::async_trait;
use bytes::{Bytes, BytesMut};
use tokio::{sync::Mutex, task::JoinSet};

use crate::{
    packet::{PacketType, ZCPacket, ZCPacketType},
    peers::{
        PeerPacketFilter,
        peer_manager::{PeerManagerCore, PipelineRegistrationGuard},
    },
    proxy::cidr_table::ProxyCidrTable,
    runtime_config::CoreRuntimeConfigStore,
};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct WrappedTransportDirections {
    pub source: bool,
    pub destination: bool,
}

impl WrappedTransportDirections {
    fn enabled(self) -> bool {
        self.source || self.destination
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WrappedTransportKind {
    Kcp,
    Quic,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WrappedTransportRole {
    Source,
    Destination,
}

#[derive(Debug, Clone)]
pub struct WrappedTransportDatagram {
    pub transport: WrappedTransportKind,
    pub role: WrappedTransportRole,
    pub peer_id: u32,
    pub buffer: WrappedTransportDatagramBuffer,
}

#[derive(Debug, Clone)]
pub struct WrappedTransportDatagramBuffer(ZCPacket);

impl WrappedTransportDatagramBuffer {
    pub fn copy_from_payload(payload: &[u8]) -> Self {
        Self(ZCPacket::new_with_payload(payload))
    }

    pub fn from_packet_buffer(buffer: BytesMut, packet_type: ZCPacketType) -> Self {
        Self(ZCPacket::new_from_buf(buffer, packet_type))
    }
}

impl WrappedTransportDatagram {
    fn into_packet(self, my_peer_id: u32) -> ZCPacket {
        let mut packet = self.buffer.0;
        packet.fill_peer_manager_hdr(
            my_peer_id,
            self.peer_id,
            self.transport.packet_type(self.role) as u8,
        );
        packet
    }
}

#[derive(Debug, Clone)]
pub struct WrappedTransportEngineStart {
    pub directions: WrappedTransportDirections,
    pub my_peer_id: u32,
    pub datagrams: tokio::sync::mpsc::Sender<WrappedTransportDatagram>,
}

#[async_trait]
pub trait WrappedTransportEngine: Send + Sync + 'static {
    async fn prepare(&self, options: WrappedTransportEngineStart) -> anyhow::Result<()>;
    async fn activate(&self) -> anyhow::Result<()>;
    async fn inject_peer_datagram(
        &self,
        role: WrappedTransportRole,
        from_peer_id: u32,
        payload: Bytes,
    ) -> anyhow::Result<()>;
    async fn stop(&self);
}

pub struct WrappedTransportEngineBuild<A> {
    pub kcp: Option<Arc<dyn WrappedTransportEngine>>,
    pub quic: Option<Arc<dyn WrappedTransportEngine>>,
    pub attachment: A,
}

pub trait WrappedTransportEngineFactory: Send + 'static {
    type Attachment: Send + Sync + 'static;

    fn build(
        self,
        cidr_table: Arc<ProxyCidrTable>,
    ) -> anyhow::Result<WrappedTransportEngineBuild<Self::Attachment>>;
}

pub struct NoWrappedTransportEngineFactory;

impl WrappedTransportEngineFactory for NoWrappedTransportEngineFactory {
    type Attachment = ();

    fn build(
        self,
        _cidr_table: Arc<ProxyCidrTable>,
    ) -> anyhow::Result<WrappedTransportEngineBuild<Self::Attachment>> {
        Ok(WrappedTransportEngineBuild {
            kcp: None,
            quic: None,
            attachment: (),
        })
    }
}

#[derive(Default)]
struct WrappedTransportProxyState {
    active: bool,
    kcp_started: bool,
    quic_started: bool,
    pipeline_guards: Vec<PipelineRegistrationGuard>,
    tasks: JoinSet<()>,
}

impl WrappedTransportKind {
    fn packet_type(self, role: WrappedTransportRole) -> PacketType {
        match (self, role) {
            (Self::Kcp, WrappedTransportRole::Source) => PacketType::KcpSrc,
            (Self::Kcp, WrappedTransportRole::Destination) => PacketType::KcpDst,
            (Self::Quic, WrappedTransportRole::Source) => PacketType::QuicSrc,
            (Self::Quic, WrappedTransportRole::Destination) => PacketType::QuicDst,
        }
    }

    fn incoming_packet_type(self, role: WrappedTransportRole) -> PacketType {
        match role {
            WrappedTransportRole::Source => self.packet_type(WrappedTransportRole::Destination),
            WrappedTransportRole::Destination => self.packet_type(WrappedTransportRole::Source),
        }
    }
}

struct WrappedTransportPeerFilter {
    engine: Weak<dyn WrappedTransportEngine>,
    transport: WrappedTransportKind,
    role: WrappedTransportRole,
}

#[async_trait]
impl PeerPacketFilter for WrappedTransportPeerFilter {
    async fn try_process_packet_from_peer(&self, packet: ZCPacket) -> Option<ZCPacket> {
        let Some(header) = packet.peer_manager_header() else {
            return Some(packet);
        };
        if header.packet_type != self.transport.incoming_packet_type(self.role) as u8 {
            return Some(packet);
        }
        let Some(engine) = self.engine.upgrade() else {
            return Some(packet);
        };
        let from_peer_id = header.from_peer_id.get();
        if let Err(error) = engine
            .inject_peer_datagram(self.role, from_peer_id, packet.payload_bytes().freeze())
            .await
        {
            tracing::debug!(
                ?error,
                transport = ?self.transport,
                role = ?self.role,
                "failed to inject wrapped transport packet"
            );
        }
        None
    }
}

pub(crate) struct WrappedTransportProxyModule {
    peer_manager: Arc<PeerManagerCore>,
    runtime_config: CoreRuntimeConfigStore,
    kcp: Option<Arc<dyn WrappedTransportEngine>>,
    quic: Option<Arc<dyn WrappedTransportEngine>>,
    state: Mutex<WrappedTransportProxyState>,
}

impl WrappedTransportProxyModule {
    const DATAGRAM_QUEUE_CAPACITY: usize = 1024;

    pub(crate) fn new(
        peer_manager: Arc<PeerManagerCore>,
        runtime_config: CoreRuntimeConfigStore,
        kcp: Option<Arc<dyn WrappedTransportEngine>>,
        quic: Option<Arc<dyn WrappedTransportEngine>>,
    ) -> Option<Arc<Self>> {
        if kcp.is_none() && quic.is_none() {
            return None;
        }
        Some(Arc::new(Self {
            peer_manager,
            runtime_config,
            kcp,
            quic,
            state: Mutex::new(WrappedTransportProxyState::default()),
        }))
    }

    fn directions(&self) -> (WrappedTransportDirections, WrappedTransportDirections) {
        let snapshot = self.runtime_config.snapshot();
        let flags = &snapshot.peer.flags;
        (
            WrappedTransportDirections {
                source: flags.enable_kcp_proxy,
                destination: !flags.disable_kcp_input,
            },
            WrappedTransportDirections {
                source: flags.enable_quic_proxy,
                destination: !flags.disable_quic_input,
            },
        )
    }

    fn spawn_datagram_egress(
        &self,
        state: &mut WrappedTransportProxyState,
    ) -> tokio::sync::mpsc::Sender<WrappedTransportDatagram> {
        let (tx, mut rx) =
            tokio::sync::mpsc::channel::<WrappedTransportDatagram>(Self::DATAGRAM_QUEUE_CAPACITY);
        let peer_manager = self.peer_manager.clone();
        state.tasks.spawn(async move {
            while let Some(datagram) = rx.recv().await {
                let peer_id = datagram.peer_id;
                let transport = datagram.transport;
                let role = datagram.role;
                let packet = datagram.into_packet(peer_manager.my_peer_id());
                if let Err(error) = peer_manager.send_msg_for_proxy(packet, peer_id).await {
                    tracing::error!(
                        ?error,
                        ?transport,
                        ?role,
                        peer_id,
                        "failed to send wrapped transport packet"
                    );
                }
            }
        });
        tx
    }

    async fn register_peer_filters(
        &self,
        state: &mut WrappedTransportProxyState,
        engine: &Arc<dyn WrappedTransportEngine>,
        transport: WrappedTransportKind,
        directions: WrappedTransportDirections,
    ) {
        if directions.source {
            let guard = self
                .peer_manager
                .add_managed_packet_process_pipeline(Box::new(WrappedTransportPeerFilter {
                    engine: Arc::downgrade(engine),
                    transport,
                    role: WrappedTransportRole::Source,
                }))
                .await;
            state.pipeline_guards.push(guard);
        }
        if directions.destination {
            let guard = self
                .peer_manager
                .add_managed_packet_process_pipeline(Box::new(WrappedTransportPeerFilter {
                    engine: Arc::downgrade(engine),
                    transport,
                    role: WrappedTransportRole::Destination,
                }))
                .await;
            state.pipeline_guards.push(guard);
        }
    }

    async fn stop_started(&self, state: &mut WrappedTransportProxyState) {
        for guard in state.pipeline_guards.drain(..).rev() {
            guard.close();
        }
        if state.quic_started {
            if let Some(quic) = &self.quic {
                quic.stop().await;
            }
            state.quic_started = false;
        }
        if state.kcp_started {
            if let Some(kcp) = &self.kcp {
                kcp.stop().await;
            }
            state.kcp_started = false;
        }
        state.tasks.shutdown().await;
        state.active = false;
    }

    pub(crate) async fn start(&self) -> anyhow::Result<()> {
        let mut state = self.state.lock().await;
        if state.active {
            return Ok(());
        }
        let (kcp_directions, quic_directions) = self.directions();

        if let Some(kcp) = &self.kcp
            && kcp_directions.enabled()
        {
            let datagrams = self.spawn_datagram_egress(&mut state);
            state.kcp_started = true;
            if let Err(error) = kcp
                .prepare(WrappedTransportEngineStart {
                    directions: kcp_directions,
                    my_peer_id: self.peer_manager.my_peer_id(),
                    datagrams,
                })
                .await
            {
                self.stop_started(&mut state).await;
                return Err(error);
            }
            self.register_peer_filters(&mut state, kcp, WrappedTransportKind::Kcp, kcp_directions)
                .await;
            if let Err(error) = kcp.activate().await {
                self.stop_started(&mut state).await;
                return Err(error);
            }
        }
        if let Some(quic) = &self.quic
            && quic_directions.enabled()
        {
            let datagrams = self.spawn_datagram_egress(&mut state);
            state.quic_started = true;
            if let Err(error) = quic
                .prepare(WrappedTransportEngineStart {
                    directions: quic_directions,
                    my_peer_id: self.peer_manager.my_peer_id(),
                    datagrams,
                })
                .await
            {
                self.stop_started(&mut state).await;
                return Err(error);
            }
            self.register_peer_filters(
                &mut state,
                quic,
                WrappedTransportKind::Quic,
                quic_directions,
            )
            .await;
            if let Err(error) = quic.activate().await {
                self.stop_started(&mut state).await;
                return Err(error);
            }
        }
        state.active = true;
        Ok(())
    }

    pub(crate) async fn stop(&self) {
        let mut state = self.state.lock().await;
        self.stop_started(&mut state).await;
    }
}

#[cfg(test)]
mod tests {
    use std::sync::{
        Arc, Mutex,
        atomic::{AtomicUsize, Ordering},
    };

    use tokio::sync::Notify;

    use crate::{
        config::{CoreConfig, NetworkIdentity, NodeConfig},
        peers::{
            context::{HostRoutingPolicy, PeerRuntimeConfig, PeerRuntimeSnapshot},
            create_packet_recv_chan,
            peer_manager::PortablePeerManagerConfig,
        },
        runtime_config::CoreRuntimeConfig,
        socket::dns::{DnsQuery, DnsResolver},
    };

    use super::*;

    struct RecordingWrappedTransportEngine {
        name: &'static str,
        fail_start: bool,
        events: Arc<Mutex<Vec<String>>>,
    }

    struct CancelOnceStopEngine {
        stop_calls: AtomicUsize,
        stop_entered: Notify,
        release_first_stop: Notify,
        events: Arc<Mutex<Vec<String>>>,
    }

    #[derive(Default)]
    struct RecordingDatagramEngine {
        injections: Mutex<Vec<(WrappedTransportRole, u32, Bytes)>>,
    }

    #[async_trait]
    impl WrappedTransportEngine for RecordingDatagramEngine {
        async fn prepare(&self, _options: WrappedTransportEngineStart) -> anyhow::Result<()> {
            Ok(())
        }

        async fn activate(&self) -> anyhow::Result<()> {
            Ok(())
        }

        async fn inject_peer_datagram(
            &self,
            role: WrappedTransportRole,
            from_peer_id: u32,
            payload: Bytes,
        ) -> anyhow::Result<()> {
            self.injections
                .lock()
                .unwrap()
                .push((role, from_peer_id, payload));
            Ok(())
        }

        async fn stop(&self) {}
    }

    #[async_trait]
    impl WrappedTransportEngine for CancelOnceStopEngine {
        async fn prepare(&self, options: WrappedTransportEngineStart) -> anyhow::Result<()> {
            self.events.lock().unwrap().push("prepare:blocking".into());
            assert_eq!(
                options.directions,
                WrappedTransportDirections {
                    source: true,
                    destination: true,
                }
            );
            Ok(())
        }

        async fn activate(&self) -> anyhow::Result<()> {
            self.events.lock().unwrap().push("activate:blocking".into());
            Ok(())
        }

        async fn inject_peer_datagram(
            &self,
            _role: WrappedTransportRole,
            _from_peer_id: u32,
            _payload: Bytes,
        ) -> anyhow::Result<()> {
            Ok(())
        }

        async fn stop(&self) {
            let call = self.stop_calls.fetch_add(1, Ordering::AcqRel);
            self.events.lock().unwrap().push("stop:blocking".into());
            if call == 0 {
                self.stop_entered.notify_one();
                self.release_first_stop.notified().await;
            }
        }
    }

    #[async_trait]
    impl WrappedTransportEngine for RecordingWrappedTransportEngine {
        async fn prepare(&self, options: WrappedTransportEngineStart) -> anyhow::Result<()> {
            let directions = options.directions;
            self.events.lock().unwrap().push(format!(
                "prepare:{}:{}:{}",
                self.name, directions.source, directions.destination
            ));
            if self.fail_start {
                anyhow::bail!("{} start failed", self.name);
            }
            Ok(())
        }

        async fn activate(&self) -> anyhow::Result<()> {
            self.events
                .lock()
                .unwrap()
                .push(format!("activate:{}", self.name));
            Ok(())
        }

        async fn inject_peer_datagram(
            &self,
            _role: WrappedTransportRole,
            _from_peer_id: u32,
            _payload: Bytes,
        ) -> anyhow::Result<()> {
            Ok(())
        }

        async fn stop(&self) {
            self.events
                .lock()
                .unwrap()
                .push(format!("stop:{}", self.name));
        }
    }

    fn wrapped_transport_engine(
        name: &'static str,
        fail_start: bool,
        events: &Arc<Mutex<Vec<String>>>,
    ) -> Arc<dyn WrappedTransportEngine> {
        Arc::new(RecordingWrappedTransportEngine {
            name,
            fail_start,
            events: events.clone(),
        })
    }

    struct TestDnsResolver;

    #[async_trait]
    impl DnsResolver for TestDnsResolver {
        async fn resolve(&self, _query: DnsQuery) -> anyhow::Result<Vec<std::net::IpAddr>> {
            Ok(Vec::new())
        }
    }

    fn wrapped_transport_peer_manager() -> Arc<PeerManagerCore> {
        let (packet_tx, _packet_rx) = create_packet_recv_chan();
        Arc::new(
            PeerManagerCore::new_portable(
                PortablePeerManagerConfig::new(PeerRuntimeConfig {
                    core: CoreConfig {
                        node: NodeConfig {
                            peer_id: Some(1),
                            network_name: "wrapped-transport-test".to_owned(),
                            ..Default::default()
                        },
                        ..Default::default()
                    },
                    network_identity: NetworkIdentity {
                        network_name: "wrapped-transport-test".to_owned(),
                        network_secret: Some("secret".to_owned()),
                        network_secret_digest: None,
                    },
                    stun_info: Default::default(),
                    feature_flags: Default::default(),
                    secure_mode: None,
                    host_routing: HostRoutingPolicy::default(),
                }),
                Arc::new(TestDnsResolver),
                packet_tx,
            )
            .unwrap(),
        )
    }

    fn wrapped_transport_runtime(
        kcp: WrappedTransportDirections,
        quic: WrappedTransportDirections,
    ) -> CoreRuntimeConfigStore {
        let mut peer = PeerRuntimeSnapshot::default();
        peer.flags.enable_kcp_proxy = kcp.source;
        peer.flags.disable_kcp_input = !kcp.destination;
        peer.flags.enable_quic_proxy = quic.source;
        peer.flags.disable_quic_input = !quic.destination;
        CoreRuntimeConfigStore::new(CoreRuntimeConfig::default(), Arc::new(peer))
    }

    #[tokio::test]
    async fn peer_filter_maps_packet_role_and_releases_stale_engine() {
        let engine = Arc::new(RecordingDatagramEngine::default());
        let dyn_engine: Arc<dyn WrappedTransportEngine> = engine.clone();
        let filter = WrappedTransportPeerFilter {
            engine: Arc::downgrade(&dyn_engine),
            transport: WrappedTransportKind::Kcp,
            role: WrappedTransportRole::Source,
        };
        let mut packet = ZCPacket::new_with_payload(b"payload");
        packet.fill_peer_manager_hdr(7, 1, PacketType::KcpDst as u8);

        assert!(filter.try_process_packet_from_peer(packet).await.is_none());
        assert_eq!(
            *engine.injections.lock().unwrap(),
            [(
                WrappedTransportRole::Source,
                7,
                Bytes::from_static(b"payload"),
            )]
        );

        drop(dyn_engine);
        drop(engine);
        let mut packet = ZCPacket::new_with_payload(b"stale");
        packet.fill_peer_manager_hdr(7, 1, PacketType::KcpDst as u8);
        assert!(filter.try_process_packet_from_peer(packet).await.is_some());
    }

    #[test]
    fn datagram_preserves_wire_packet_types() {
        for (transport, role, packet_type) in [
            (
                WrappedTransportKind::Kcp,
                WrappedTransportRole::Source,
                PacketType::KcpSrc,
            ),
            (
                WrappedTransportKind::Kcp,
                WrappedTransportRole::Destination,
                PacketType::KcpDst,
            ),
            (
                WrappedTransportKind::Quic,
                WrappedTransportRole::Source,
                PacketType::QuicSrc,
            ),
            (
                WrappedTransportKind::Quic,
                WrappedTransportRole::Destination,
                PacketType::QuicDst,
            ),
        ] {
            let packet = WrappedTransportDatagram {
                transport,
                role,
                peer_id: 9,
                buffer: WrappedTransportDatagramBuffer::copy_from_payload(b"wire"),
            }
            .into_packet(7);
            let header = packet.peer_manager_header().unwrap();

            assert_eq!(header.from_peer_id.get(), 7);
            assert_eq!(header.to_peer_id.get(), 9);
            assert_eq!(header.packet_type, packet_type as u8);
            assert_eq!(packet.payload(), b"wire");
        }
    }

    #[test]
    fn packet_buffer_preserves_headroom_allocation() {
        let packet = ZCPacket::new_with_payload(b"wire");
        let packet_type = packet.packet_type();
        let buffer = packet.inner();
        let allocation = buffer.as_ptr();

        let mut packet = WrappedTransportDatagram {
            transport: WrappedTransportKind::Quic,
            role: WrappedTransportRole::Source,
            peer_id: 9,
            buffer: WrappedTransportDatagramBuffer::from_packet_buffer(buffer, packet_type),
        }
        .into_packet(7);

        assert_eq!(packet.mut_inner().as_ptr(), allocation);
        assert_eq!(packet.payload(), b"wire");
    }

    #[tokio::test]
    async fn module_reads_activation_flags_and_stops_in_reverse() {
        let events = Arc::new(Mutex::new(Vec::new()));
        let runtime = wrapped_transport_runtime(
            WrappedTransportDirections {
                source: false,
                destination: false,
            },
            WrappedTransportDirections {
                source: false,
                destination: false,
            },
        );
        let module = WrappedTransportProxyModule::new(
            wrapped_transport_peer_manager(),
            runtime.clone(),
            Some(wrapped_transport_engine("kcp", false, &events)),
            Some(wrapped_transport_engine("quic", false, &events)),
        )
        .unwrap();

        runtime.update_peer(Arc::new({
            let mut peer = PeerRuntimeSnapshot::default();
            peer.flags.enable_kcp_proxy = true;
            peer.flags.disable_kcp_input = true;
            peer.flags.enable_quic_proxy = false;
            peer.flags.disable_quic_input = false;
            peer
        }));

        module.start().await.unwrap();
        module.start().await.unwrap();
        module.stop().await;
        module.stop().await;

        assert_eq!(
            *events.lock().unwrap(),
            [
                "prepare:kcp:true:false",
                "activate:kcp",
                "prepare:quic:false:true",
                "activate:quic",
                "stop:quic",
                "stop:kcp",
            ]
        );
    }

    #[tokio::test]
    async fn module_rolls_back_failing_engine_and_predecessor() {
        let events = Arc::new(Mutex::new(Vec::new()));
        let runtime = wrapped_transport_runtime(
            WrappedTransportDirections {
                source: true,
                destination: true,
            },
            WrappedTransportDirections {
                source: true,
                destination: true,
            },
        );
        let module = WrappedTransportProxyModule::new(
            wrapped_transport_peer_manager(),
            runtime,
            Some(wrapped_transport_engine("kcp", false, &events)),
            Some(wrapped_transport_engine("quic", true, &events)),
        )
        .unwrap();

        assert!(module.start().await.is_err());

        assert_eq!(
            *events.lock().unwrap(),
            [
                "prepare:kcp:true:true",
                "activate:kcp",
                "prepare:quic:true:true",
                "stop:quic",
                "stop:kcp",
            ]
        );
    }

    #[tokio::test]
    async fn module_retries_cleanup_after_stop_is_cancelled() {
        let events = Arc::new(Mutex::new(Vec::new()));
        let blocking = Arc::new(CancelOnceStopEngine {
            stop_calls: AtomicUsize::new(0),
            stop_entered: Notify::new(),
            release_first_stop: Notify::new(),
            events: events.clone(),
        });
        let runtime = wrapped_transport_runtime(
            WrappedTransportDirections {
                source: true,
                destination: true,
            },
            WrappedTransportDirections {
                source: true,
                destination: true,
            },
        );
        let module = WrappedTransportProxyModule::new(
            wrapped_transport_peer_manager(),
            runtime,
            Some(wrapped_transport_engine("kcp", false, &events)),
            Some(blocking.clone()),
        )
        .unwrap();
        module.start().await.unwrap();

        let stop_task = tokio::spawn({
            let module = module.clone();
            async move { module.stop().await }
        });
        blocking.stop_entered.notified().await;
        stop_task.abort();
        assert!(stop_task.await.unwrap_err().is_cancelled());

        module.stop().await;

        assert_eq!(blocking.stop_calls.load(Ordering::Acquire), 2);
        assert_eq!(
            *events.lock().unwrap(),
            [
                "prepare:kcp:true:true",
                "activate:kcp",
                "prepare:blocking",
                "activate:blocking",
                "stop:blocking",
                "stop:blocking",
                "stop:kcp",
            ]
        );
    }
}
