use std::{
    any::Any,
    fmt::Debug,
    pin::Pin,
    sync::{
        atomic::{AtomicU32, Ordering},
        Arc,
    },
};

use bytes::BytesMut;
use futures::{SinkExt, StreamExt, TryFutureExt};

use prost::Message;

use tokio::{
    sync::{broadcast, mpsc},
    task::JoinSet,
    time::{timeout, Duration},
};

use tokio_util::sync::PollSender;
use tracing::Instrument;
use zerocopy::AsBytes;

use crate::{
    common::{
        error::Error,
        global_ctx::{ArcGlobalCtx, NetworkIdentity},
        PeerId,
    },
    peers::packet::PacketType,
    rpc::{HandshakeRequest, PeerConnInfo, PeerConnStats, TunnelInfo},
    tunnel::{
        filter::{StatsRecorderTunnelFilter, TunnelFilter, TunnelWithFilter},
        mpsc::{MpscTunnel, MpscTunnelSender},
        packet_def::ZCPacket,
        stats::{Throughput, WindowLatency},
        Tunnel, TunnelError, ZCPacketStream,
    },
};

use super::{peer_conn_ping::PeerConnPinger, PacketRecvChan};

pub type PeerConnId = uuid::Uuid;

const MAGIC: u32 = 0xd1e1a5e1;
const VERSION: u32 = 1;

pub struct PeerConn {
    conn_id: PeerConnId,

    my_peer_id: PeerId,
    global_ctx: ArcGlobalCtx,

    tunnel: Box<dyn Any + Send + 'static>,
    sink: MpscTunnelSender,
    recv: Option<Pin<Box<dyn ZCPacketStream>>>,
    tunnel_info: Option<TunnelInfo>,

    tasks: JoinSet<Result<(), TunnelError>>,

    info: Option<HandshakeRequest>,

    close_event_sender: Option<mpsc::Sender<PeerConnId>>,

    ctrl_resp_sender: broadcast::Sender<ZCPacket>,

    latency_stats: Arc<WindowLatency>,
    throughput: Arc<Throughput>,
    loss_rate_stats: Arc<AtomicU32>,
}

impl Debug for PeerConn {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PeerConn")
            .field("conn_id", &self.conn_id)
            .field("my_peer_id", &self.my_peer_id)
            .field("info", &self.info)
            .finish()
    }
}

impl PeerConn {
    pub fn new(my_peer_id: PeerId, global_ctx: ArcGlobalCtx, tunnel: Box<dyn Tunnel>) -> Self {
        let tunnel_info = tunnel.info();
        let (ctrl_sender, _ctrl_receiver) = broadcast::channel(100);

        let peer_conn_tunnel_filter = StatsRecorderTunnelFilter::new();
        let throughput = peer_conn_tunnel_filter.filter_output();
        let peer_conn_tunnel = TunnelWithFilter::new(tunnel, peer_conn_tunnel_filter);
        let mut mpsc_tunnel = MpscTunnel::new(peer_conn_tunnel);

        let (recv, sink) = (mpsc_tunnel.get_stream(), mpsc_tunnel.get_sink());

        PeerConn {
            conn_id: PeerConnId::new_v4(),

            my_peer_id,
            global_ctx,

            tunnel: Box::new(mpsc_tunnel),
            sink,
            recv: Some(recv),
            tunnel_info,

            tasks: JoinSet::new(),

            info: None,
            close_event_sender: None,

            ctrl_resp_sender: ctrl_sender,

            latency_stats: Arc::new(WindowLatency::new(15)),
            throughput,
            loss_rate_stats: Arc::new(AtomicU32::new(0)),
        }
    }

    pub fn get_conn_id(&self) -> PeerConnId {
        self.conn_id
    }

    async fn wait_handshake(&mut self) -> Result<HandshakeRequest, Error> {
        let recv = self.recv.as_mut().unwrap();
        let Some(rsp) = recv.next().await else {
            return Err(Error::WaitRespError(
                "conn closed during wait handshake response".to_owned(),
            ));
        };
        let rsp = rsp?;
        let rsp = HandshakeRequest::decode(rsp.payload())
            .map_err(|e| Error::WaitRespError(format!("decode handshake response error: {:?}", e)));

        return Ok(rsp.unwrap());
    }

    async fn wait_handshake_loop(&mut self) -> Result<HandshakeRequest, Error> {
        Ok(timeout(Duration::from_secs(5), async move {
            loop {
                match self.wait_handshake().await {
                    Ok(rsp) => return rsp,
                    Err(e) => {
                        log::warn!("wait handshake error: {:?}", e);
                    }
                }
            }
        })
        .map_err(|e| Error::WaitRespError(format!("wait handshake timeout: {:?}", e)))
        .await?)
    }

    async fn send_handshake(&mut self) -> Result<(), Error> {
        let network = self.global_ctx.get_network_identity();
        let req = HandshakeRequest {
            magic: MAGIC,
            my_peer_id: self.my_peer_id,
            version: VERSION,
            features: Vec::new(),
            network_name: network.network_name.clone(),
            network_secret: network.network_secret.clone(),
        };

        let hs_req = req.encode_to_vec();
        let mut zc_packet = ZCPacket::new_with_payload(BytesMut::from(hs_req.as_bytes()));
        zc_packet.fill_peer_manager_hdr(
            self.my_peer_id,
            PeerId::default(),
            PacketType::HandShake as u8,
        );

        self.sink.send(zc_packet).await.map_err(|e| {
            tracing::warn!("send handshake request error: {:?}", e);
            Error::WaitRespError("send handshake request error".to_owned())
        })?;

        Ok(())
    }

    #[tracing::instrument]
    pub async fn do_handshake_as_server(&mut self) -> Result<(), Error> {
        let rsp = self.wait_handshake_loop().await?;
        tracing::info!("handshake request: {:?}", rsp);
        self.info = Some(rsp);
        self.send_handshake().await?;
        Ok(())
    }

    #[tracing::instrument]
    pub async fn do_handshake_as_client(&mut self) -> Result<(), Error> {
        self.send_handshake().await?;
        tracing::info!("waiting for handshake request from server");
        let rsp = self.wait_handshake_loop().await?;
        tracing::info!("handshake response: {:?}", rsp);
        self.info = Some(rsp);
        Ok(())
    }

    pub fn handshake_done(&self) -> bool {
        self.info.is_some()
    }

    pub fn start_recv_loop(&mut self, packet_recv_chan: PacketRecvChan) {
        let mut stream = self.recv.take().unwrap();
        let sink = self.sink.clone();
        let mut sender = PollSender::new(packet_recv_chan.clone());
        let close_event_sender = self.close_event_sender.clone().unwrap();
        let conn_id = self.conn_id;
        let ctrl_sender = self.ctrl_resp_sender.clone();
        let _conn_info = self.get_conn_info();
        let conn_info_for_instrument = self.get_conn_info();

        self.tasks.spawn(
            async move {
                tracing::info!("start recving peer conn packet");
                let mut task_ret = Ok(());
                while let Some(ret) = stream.next().await {
                    if ret.is_err() {
                        tracing::error!(error = ?ret, "peer conn recv error");
                        task_ret = Err(ret.err().unwrap());
                        break;
                    }

                    let mut zc_packet = ret.unwrap();
                    let Some(peer_mgr_hdr) = zc_packet.mut_peer_manager_header() else {
                        tracing::error!(
                            "unexpected packet: {:?}, cannot decode peer manager hdr",
                            zc_packet
                        );
                        continue;
                    };

                    if peer_mgr_hdr.packet_type == PacketType::Ping as u8 {
                        peer_mgr_hdr.packet_type = PacketType::Pong as u8;
                        if let Err(e) = sink.send(zc_packet).await {
                            tracing::error!(?e, "peer conn send req error");
                        }
                    } else if peer_mgr_hdr.packet_type == PacketType::Pong as u8 {
                        if let Err(e) = ctrl_sender.send(zc_packet) {
                            tracing::error!(?e, "peer conn send ctrl resp error");
                        }
                    } else {
                        if sender.send(zc_packet).await.is_err() {
                            break;
                        }
                    }
                }

                tracing::info!("end recving peer conn packet");

                drop(sink);
                if let Err(e) = close_event_sender.send(conn_id).await {
                    tracing::error!(error = ?e, "peer conn close event send error");
                }

                task_ret
            }
            .instrument(
                tracing::info_span!("peer conn recv loop", conn_info = ?conn_info_for_instrument),
            ),
        );
    }

    pub fn start_pingpong(&mut self) {
        let mut pingpong = PeerConnPinger::new(
            self.my_peer_id,
            self.get_peer_id(),
            self.sink.clone(),
            self.ctrl_resp_sender.clone(),
            self.latency_stats.clone(),
            self.loss_rate_stats.clone(),
        );

        let close_event_sender = self.close_event_sender.clone().unwrap();
        let conn_id = self.conn_id;

        self.tasks.spawn(async move {
            pingpong.pingpong().await;

            tracing::warn!(?pingpong, "pingpong task exit");

            if let Err(e) = close_event_sender.send(conn_id).await {
                log::warn!("close event sender error: {:?}", e);
            }

            Ok(())
        });
    }

    pub async fn send_msg(&mut self, msg: ZCPacket) -> Result<(), Error> {
        Ok(self.sink.send(msg).await?)
    }

    pub fn get_peer_id(&self) -> PeerId {
        self.info.as_ref().unwrap().my_peer_id
    }

    pub fn get_network_identity(&self) -> NetworkIdentity {
        let info = self.info.as_ref().unwrap();
        NetworkIdentity {
            network_name: info.network_name.clone(),
            network_secret: info.network_secret.clone(),
        }
    }

    pub fn set_close_event_sender(&mut self, sender: mpsc::Sender<PeerConnId>) {
        self.close_event_sender = Some(sender);
    }

    pub fn get_stats(&self) -> PeerConnStats {
        PeerConnStats {
            latency_us: self.latency_stats.get_latency_us(),

            tx_bytes: self.throughput.tx_bytes(),
            rx_bytes: self.throughput.rx_bytes(),

            tx_packets: self.throughput.tx_packets(),
            rx_packets: self.throughput.rx_packets(),
        }
    }

    pub fn get_conn_info(&self) -> PeerConnInfo {
        PeerConnInfo {
            conn_id: self.conn_id.to_string(),
            my_peer_id: self.my_peer_id,
            peer_id: self.get_peer_id(),
            features: self.info.as_ref().unwrap().features.clone(),
            tunnel: self.tunnel_info.clone(),
            stats: Some(self.get_stats()),
            loss_rate: (f64::from(self.loss_rate_stats.load(Ordering::Relaxed)) / 100.0) as f32,
        }
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use super::*;
    use crate::common::global_ctx::tests::get_mock_global_ctx;
    use crate::common::new_peer_id;
    use crate::tunnel::filter::tests::DropSendTunnelFilter;
    use crate::tunnel::filter::PacketRecorderTunnelFilter;
    use crate::tunnel::ring::create_ring_tunnel_pair;

    #[tokio::test]
    async fn peer_conn_handshake() {
        let (c, s) = create_ring_tunnel_pair();

        let c_recorder = Arc::new(PacketRecorderTunnelFilter::new());
        let s_recorder = Arc::new(PacketRecorderTunnelFilter::new());

        let c = TunnelWithFilter::new(c, c_recorder.clone());
        let s = TunnelWithFilter::new(s, s_recorder.clone());

        let c_peer_id = new_peer_id();
        let s_peer_id = new_peer_id();

        let mut c_peer = PeerConn::new(c_peer_id, get_mock_global_ctx(), Box::new(c));

        let mut s_peer = PeerConn::new(s_peer_id, get_mock_global_ctx(), Box::new(s));

        let (c_ret, s_ret) = tokio::join!(
            c_peer.do_handshake_as_client(),
            s_peer.do_handshake_as_server()
        );

        c_ret.unwrap();
        s_ret.unwrap();

        assert_eq!(c_recorder.sent.lock().unwrap().len(), 1);
        assert_eq!(c_recorder.received.lock().unwrap().len(), 1);

        assert_eq!(s_recorder.sent.lock().unwrap().len(), 1);
        assert_eq!(s_recorder.received.lock().unwrap().len(), 1);

        assert_eq!(c_peer.get_peer_id(), s_peer_id);
        assert_eq!(s_peer.get_peer_id(), c_peer_id);
        assert_eq!(c_peer.get_network_identity(), s_peer.get_network_identity());
        assert_eq!(c_peer.get_network_identity(), NetworkIdentity::default());
    }

    async fn peer_conn_pingpong_test_common(drop_start: u32, drop_end: u32, conn_closed: bool) {
        let (c, s) = create_ring_tunnel_pair();

        // drop 1-3 packets should not affect pingpong
        let c_recorder = Arc::new(DropSendTunnelFilter::new(drop_start, drop_end));
        let c = TunnelWithFilter::new(c, c_recorder.clone());

        let c_peer_id = new_peer_id();
        let s_peer_id = new_peer_id();

        let mut c_peer = PeerConn::new(c_peer_id, get_mock_global_ctx(), Box::new(c));
        let mut s_peer = PeerConn::new(s_peer_id, get_mock_global_ctx(), Box::new(s));

        let (c_ret, s_ret) = tokio::join!(
            c_peer.do_handshake_as_client(),
            s_peer.do_handshake_as_server()
        );

        s_peer.set_close_event_sender(tokio::sync::mpsc::channel(1).0);
        s_peer.start_recv_loop(tokio::sync::mpsc::channel(200).0);

        assert!(c_ret.is_ok());
        assert!(s_ret.is_ok());

        let (close_send, mut close_recv) = tokio::sync::mpsc::channel(1);
        c_peer.set_close_event_sender(close_send);
        c_peer.start_pingpong();
        c_peer.start_recv_loop(tokio::sync::mpsc::channel(200).0);

        // wait 5s, conn should not be disconnected
        tokio::time::sleep(Duration::from_secs(15)).await;

        if conn_closed {
            assert!(close_recv.try_recv().is_ok());
        } else {
            assert!(close_recv.try_recv().is_err());
        }
    }

    #[tokio::test]
    async fn peer_conn_pingpong_timeout() {
        peer_conn_pingpong_test_common(3, 5, false).await;
        peer_conn_pingpong_test_common(5, 12, true).await;
    }
}

/*
use std::{
    fmt::Debug,
    pin::Pin,
    sync::{
        atomic::{AtomicU32, Ordering},
        Arc,
    },
};

use futures::{SinkExt, StreamExt};
use pnet::datalink::NetworkInterface;

use tokio::{
    sync::{broadcast, mpsc, Mutex},
    task::JoinSet,
    time::{timeout, Duration},
};

use tokio_util::{bytes::Bytes, sync::PollSender};
use tracing::Instrument;

use crate::{
    common::{
        error::Error,
        global_ctx::{ArcGlobalCtx, NetworkIdentity},
        PeerId,
    },
    define_tunnel_filter_chain,
    peers::packet::{ArchivedPacketType, CtrlPacketPayload, PacketType},
    rpc::{PeerConnInfo, PeerConnStats},
    tunnel::{mpsc::MpscTunnelSender, stats::WindowLatency, TunnelError},
};

use super::packet::{self, HandShake, Packet};

pub type PacketRecvChan = mpsc::Sender<Bytes>;

macro_rules! wait_response {
    ($stream: ident, $out_var:ident, $pattern:pat_param => $value:expr) => {
        let Ok(rsp_vec) = timeout(Duration::from_secs(1), $stream.next()).await else {
            return Err(Error::WaitRespError(
                "wait handshake response timeout".to_owned(),
            ));
        };
        let Some(rsp_vec) = rsp_vec else {
            return Err(Error::WaitRespError(
                "wait handshake response get none".to_owned(),
            ));
        };
        let Ok(rsp_vec) = rsp_vec else {
            return Err(Error::WaitRespError(format!(
                "wait handshake response get error {}",
                rsp_vec.err().unwrap()
            )));
        };

        let $out_var;
        let rsp_bytes = Packet::decode(&rsp_vec);
        if rsp_bytes.packet_type != PacketType::HandShake {
            tracing::error!("unexpected packet type: {:?}", rsp_bytes);
            return Err(Error::WaitRespError("unexpected packet type".to_owned()));
        }
        let resp_payload = CtrlPacketPayload::from_packet(&rsp_bytes);
        match &resp_payload {
            $pattern => $out_var = $value,
            _ => {
                tracing::error!(
                    "unexpected packet: {:?}, pattern: {:?}",
                    rsp_bytes,
                    stringify!($pattern)
                );
                return Err(Error::WaitRespError("unexpected packet".to_owned()));
            }
        }
    };
}

impl<'a> From<&HandShake> for PeerInfo {
    fn from(hs: &HandShake) -> Self {
        PeerInfo {
            magic: hs.magic.into(),
            my_peer_id: hs.my_peer_id.into(),
            version: hs.version.into(),
            features: hs.features.iter().map(|x| x.to_string()).collect(),
            interfaces: Vec::new(),
            network_identity: hs.network_identity.clone(),
        }
    }
}


define_tunnel_filter_chain!(PeerConnTunnel, stats = StatsRecorderTunnelFilter);

pub struct PeerConn {
    conn_id: PeerConnId,

    my_peer_id: PeerId,
    global_ctx: ArcGlobalCtx,

    sink: Pin<Box<dyn DatagramSink>>,
    tunnel: Box<dyn Tunnel>,

    tasks: JoinSet<Result<(), TunnelError>>,

    info: Option<PeerInfo>,

    close_event_sender: Option<mpsc::Sender<PeerConnId>>,

    ctrl_resp_sender: broadcast::Sender<Bytes>,

    latency_stats: Arc<WindowLatency>,
    throughput: Arc<Throughput>,
    loss_rate_stats: Arc<AtomicU32>,
}

enum PeerConnPacketType {
    Data(Bytes),
    CtrlReq(Bytes),
    CtrlResp(Bytes),
}

impl PeerConn {
    pub fn new(my_peer_id: PeerId, global_ctx: ArcGlobalCtx, tunnel: Box<dyn Tunnel>) -> Self {
        let (ctrl_sender, _ctrl_receiver) = broadcast::channel(100);
        let peer_conn_tunnel = PeerConnTunnel::new();
        let tunnel = peer_conn_tunnel.wrap_tunnel(tunnel);

        PeerConn {
            conn_id: PeerConnId::new_v4(),

            my_peer_id,
            global_ctx,

            sink: tunnel.pin_sink(),
            tunnel: Box::new(tunnel),

            tasks: JoinSet::new(),

            info: None,
            close_event_sender: None,

            ctrl_resp_sender: ctrl_sender,

            latency_stats: Arc::new(WindowLatency::new(15)),
            throughput: peer_conn_tunnel.stats.get_throughput().clone(),
            loss_rate_stats: Arc::new(AtomicU32::new(0)),
        }
    }

    pub fn get_conn_id(&self) -> PeerConnId {
        self.conn_id
    }

    #[tracing::instrument]
    pub async fn do_handshake_as_server(&mut self) -> Result<(), TunnelError> {
        let mut stream = self.tunnel.pin_stream();
        let mut sink = self.tunnel.pin_sink();

        tracing::info!("waiting for handshake request from client");
        wait_response!(stream, hs_req, CtrlPacketPayload::HandShake(x) => x);
        self.info = Some(PeerInfo::from(hs_req));
        tracing::info!("handshake request: {:?}", hs_req);

        let hs_req = self
            .global_ctx
            .net_ns
            .run(|| packet::Packet::new_handshake(self.my_peer_id, &self.global_ctx.network));
        sink.send(hs_req.into()).await?;

        Ok(())
    }

    #[tracing::instrument]
    pub async fn do_handshake_as_client(&mut self) -> Result<(), TunnelError> {
        let mut stream = self.tunnel.pin_stream();
        let mut sink = self.tunnel.pin_sink();

        let hs_req = self
            .global_ctx
            .net_ns
            .run(|| packet::Packet::new_handshake(self.my_peer_id, &self.global_ctx.network));
        sink.send(hs_req.into()).await?;

        tracing::info!("waiting for handshake request from server");
        wait_response!(stream, hs_rsp, CtrlPacketPayload::HandShake(x) => x);
        self.info = Some(PeerInfo::from(hs_rsp));
        tracing::info!("handshake response: {:?}", hs_rsp);

        Ok(())
    }

    pub fn handshake_done(&self) -> bool {
        self.info.is_some()
    }

    pub fn start_recv_loop(&mut self, packet_recv_chan: PacketRecvChan) {
        let mut stream = self.tunnel.pin_stream();
        let mut sink = self.tunnel.pin_sink();
        let mut sender = PollSender::new(packet_recv_chan.clone());
        let close_event_sender = self.close_event_sender.clone().unwrap();
        let conn_id = self.conn_id;
        let ctrl_sender = self.ctrl_resp_sender.clone();
        let conn_info = self.get_conn_info();
        let conn_info_for_instrument = self.get_conn_info();

        self.tasks.spawn(
            async move {
                tracing::info!("start recving peer conn packet");
                let mut task_ret = Ok(());
                while let Some(ret) = stream.next().await {
                    if ret.is_err() {
                        tracing::error!(error = ?ret, "peer conn recv error");
                        task_ret = Err(ret.err().unwrap());
                        break;
                    }

                    let buf = ret.unwrap();
                    let p = Packet::decode(&buf);
                    match p.packet_type {
                        ArchivedPacketType::Ping => {
                            let CtrlPacketPayload::Ping(seq) = CtrlPacketPayload::from_packet(p)
                            else {
                                log::error!("unexpected packet: {:?}", p);
                                continue;
                            };

                            let pong = packet::Packet::new_pong_packet(
                                conn_info.my_peer_id,
                                conn_info.peer_id,
                                seq.into(),
                            );

                            if let Err(e) = sink.send(pong.into()).await {
                                tracing::error!(?e, "peer conn send req error");
                            }
                        }
                        ArchivedPacketType::Pong => {
                            if let Err(e) = ctrl_sender.send(buf.into()) {
                                tracing::error!(?e, "peer conn send ctrl resp error");
                            }
                        }
                        _ => {
                            if sender.send(buf.into()).await.is_err() {
                                break;
                            }
                        }
                    }
                }

                tracing::info!("end recving peer conn packet");

                if let Err(close_ret) = sink.close().await {
                    tracing::error!(error = ?close_ret, "peer conn sink close error, ignore it");
                }
                if let Err(e) = close_event_sender.send(conn_id).await {
                    tracing::error!(error = ?e, "peer conn close event send error");
                }

                task_ret
            }
            .instrument(
                tracing::info_span!("peer conn recv loop", conn_info = ?conn_info_for_instrument),
            ),
        );
    }

    pub async fn send_msg(&mut self, msg: Bytes) -> Result<(), Error> {
        self.sink.send(msg).await
    }

    pub fn get_peer_id(&self) -> PeerId {
        self.info.as_ref().unwrap().my_peer_id
    }

    pub fn get_network_identity(&self) -> NetworkIdentity {
        self.info.as_ref().unwrap().network_identity.clone()
    }

    pub fn set_close_event_sender(&mut self, sender: mpsc::Sender<PeerConnId>) {
        self.close_event_sender = Some(sender);
    }

    pub fn get_stats(&self) -> PeerConnStats {
        PeerConnStats {
            latency_us: self.latency_stats.get_latency_us(),

            tx_bytes: self.throughput.tx_bytes(),
            rx_bytes: self.throughput.rx_bytes(),

            tx_packets: self.throughput.tx_packets(),
            rx_packets: self.throughput.rx_packets(),
        }
    }

    pub fn get_conn_info(&self) -> PeerConnInfo {
        PeerConnInfo {
            conn_id: self.conn_id.to_string(),
            my_peer_id: self.my_peer_id,
            peer_id: self.get_peer_id(),
            features: self.info.as_ref().unwrap().features.clone(),
            tunnel: self.tunnel.info(),
            stats: Some(self.get_stats()),
            loss_rate: (f64::from(self.loss_rate_stats.load(Ordering::Relaxed)) / 100.0) as f32,
        }
    }
}

impl Drop for PeerConn {
    fn drop(&mut self) {
        let mut sink = self.tunnel.pin_sink();
        tokio::spawn(async move {
            let ret = sink.close().await;
            tracing::info!(error = ?ret, "peer conn tunnel closed.");
        });
        log::info!("peer conn {:?} drop", self.conn_id);
    }
}

}
 */
