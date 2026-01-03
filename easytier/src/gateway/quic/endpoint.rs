use crate::gateway::quic::cmd::{QuicCmd, QuicCmdTx};
use crate::gateway::quic::driver::{QuicDriver, QuicStreamPartsRx};
use crate::gateway::quic::evt::{QuicNetEvt, QuicNetEvtRx};
use crate::gateway::quic::stream::QuicStream;
use anyhow::{anyhow, Error};
use quinn_plaintext::{client_config, server_config};
use quinn_proto::congestion::BbrConfig;
use quinn_proto::{ClientConfig, Endpoint, EndpointConfig, TransportConfig, VarInt};
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::{mpsc, oneshot};
use tokio::task::JoinSet;
use tokio::time::sleep_until;
use tokio::select;
use crate::gateway::quic::packet::{QuicPacket, QuicPacketMargins};

#[derive(Debug)]
pub struct QuicController {
    cmd_tx: QuicCmdTx,
}

impl QuicController {
    pub async fn send(&self, packet: QuicPacket) -> Result<(), Error> {
        self.cmd_tx
            .send(QuicCmd::InputPacket(packet))
            .await
            .map_err(|e| Error::msg(format!("Failed to send QuicCmd::PacketIncoming: {:?}", e)))
    }

    pub async fn connect(&self, addr: SocketAddr) -> Result<QuicStream, Error> {
        let (stream_tx, stream_rx) = oneshot::channel();
        self.cmd_tx
            .send(QuicCmd::OpenBiStream { addr, stream_tx })
            .await?;
        let (stream_info, evt_rx) = stream_rx.await??;
        Ok(QuicStream::new(stream_info, evt_rx, self.cmd_tx.clone()))
    }
}

#[derive(Debug)]
pub struct QuicPacketRx {
    net_evt_rx: QuicNetEvtRx,
    packet_margins: QuicPacketMargins,
}

impl QuicPacketRx {
    pub async fn recv(&mut self) -> Option<QuicPacket> {
        match self.net_evt_rx.recv().await? {
            QuicNetEvt::OutputPacket(packet) => Some(packet),
        }
    }
    
    pub fn packet_margins(&self) -> QuicPacketMargins {
        self.packet_margins
    }
}

#[derive(Debug)]
pub struct QuicStreamRx {
    cmd_tx: QuicCmdTx,
    incoming_stream_rx: QuicStreamPartsRx,
}

impl QuicStreamRx {
    pub async fn recv(&mut self) -> Option<QuicStream> {
        let (stream_info, evt_rx) = self.incoming_stream_rx.recv().await?;
        Some(QuicStream::new(stream_info, evt_rx, self.cmd_tx.clone()))
    }
}

pub struct QuicEndpoint {
    endpoint: Option<Endpoint>,
    client_config: ClientConfig,
    ctrl: Option<Arc<QuicController>>,
    tasks: JoinSet<()>,
}

impl QuicEndpoint {
    pub fn new() -> Self {
        let mut server_config = server_config();
        server_config.transport = {
            let mut config = TransportConfig::default();

            config.stream_receive_window(VarInt::from_u32(10 * 1024 * 1024));
            config.receive_window(VarInt::from_u32(15 * 1024 * 1024));

            config.max_concurrent_bidi_streams(VarInt::from_u32(1024));
            config.max_concurrent_uni_streams(VarInt::from_u32(1024));

            config.congestion_controller_factory(Arc::new(BbrConfig::default()));

            config.keep_alive_interval(Some(Duration::from_secs(5)));
            config.max_idle_timeout(Some(VarInt::from_u32(30_000).into()));

            Arc::new(config)
        };

        let endpoint_config = EndpointConfig::default();

        let endpoint = Endpoint::new(
            Arc::from(endpoint_config),
            Some(Arc::from(server_config)),
            false,
            None,
        );

        Self::with_endpoint(endpoint, client_config())
    }

    pub fn with_endpoint(endpoint: Endpoint, client_config: ClientConfig) -> Self {
        Self {
            endpoint: Some(endpoint),
            client_config,
            ctrl: None,
            tasks: JoinSet::new(),
        }
    }

    pub fn run(&mut self, packet_margins: QuicPacketMargins) -> Option<(QuicPacketRx, QuicStreamRx)> {
        self.endpoint.as_ref()?;

        let (cmd_tx, mut cmd_rx) = mpsc::channel(2048);
        let (net_evt_tx, net_evt_rx) = mpsc::channel(2048);
        let (incoming_stream_tx, incoming_stream_rx) = mpsc::channel(128);

        self.ctrl = Some(QuicController {
            cmd_tx: cmd_tx.clone(),
        }.into());
        let packet_rx = QuicPacketRx { net_evt_rx, packet_margins };
        let stream_rx = QuicStreamRx {
            cmd_tx: cmd_tx.clone(),
            incoming_stream_rx,
        };

        let mut drv = QuicDriver::new(
            self.endpoint.take().unwrap(),
            self.client_config.clone(),
            net_evt_tx.clone(),
            incoming_stream_tx.clone(),
            packet_margins
        );

        self.tasks.spawn(async move {
            loop {
                let min_timeout = drv
                    .min_timeout()
                    .unwrap_or(Instant::now() + Duration::from_secs(60));

                select! {
                    Some(cmd) = cmd_rx.recv() => drv.execute(cmd),
                    _ = sleep_until(min_timeout.into()) => drv.handle_timeout(),
                }
            }
        });

        Some((packet_rx, stream_rx))
    }

    pub fn ctrl(&self) -> Result<Arc<QuicController>, Error> {
        self.ctrl
            .clone()
            .ok_or(anyhow!("Failed to get QUIC controller. Is QUIC endpoint running?"))
    }
}
