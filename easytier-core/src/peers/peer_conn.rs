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
        global_ctx::{ArcGlobalCtx, NetworkIdentity},
        PeerId,
    },
    define_tunnel_filter_chain,
    peers::packet::{ArchivedPacketType, CtrlPacketPayload},
    rpc::{PeerConnInfo, PeerConnStats},
    tunnels::{
        stats::{Throughput, WindowLatency},
        tunnel_filter::StatsRecorderTunnelFilter,
        DatagramSink, Tunnel, TunnelError,
    },
};

use super::packet::{self, HandShake, Packet};

pub type PacketRecvChan = mpsc::Sender<Bytes>;

pub type PeerConnId = uuid::Uuid;

macro_rules! wait_response {
    ($stream: ident, $out_var:ident, $pattern:pat_param => $value:expr) => {
        let rsp_vec = timeout(Duration::from_secs(1), $stream.next()).await;
        if rsp_vec.is_err() {
            return Err(TunnelError::WaitRespError(
                "wait handshake response timeout".to_owned(),
            ));
        }
        let rsp_vec = rsp_vec.unwrap().unwrap()?;

        let $out_var;
        let rsp_bytes = Packet::decode(&rsp_vec);
        let resp_payload = CtrlPacketPayload::from_packet(&rsp_bytes);
        match &resp_payload {
            $pattern => $out_var = $value,
            _ => {
                tracing::error!(
                    "unexpected packet: {:?}, pattern: {:?}",
                    rsp_bytes,
                    stringify!($pattern)
                );
                return Err(TunnelError::WaitRespError("unexpected packet".to_owned()));
            }
        }
    };
}

#[derive(Debug)]
pub struct PeerInfo {
    magic: u32,
    pub my_peer_id: PeerId,
    version: u32,
    pub features: Vec<String>,
    pub interfaces: Vec<NetworkInterface>,
    pub network_identity: NetworkIdentity,
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

struct PeerConnPinger {
    my_peer_id: PeerId,
    peer_id: PeerId,
    sink: Arc<Mutex<Pin<Box<dyn DatagramSink>>>>,
    ctrl_sender: broadcast::Sender<Bytes>,
    latency_stats: Arc<WindowLatency>,
    loss_rate_stats: Arc<AtomicU32>,
    tasks: JoinSet<Result<(), TunnelError>>,
}

impl Debug for PeerConnPinger {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PeerConnPinger")
            .field("my_peer_id", &self.my_peer_id)
            .field("peer_id", &self.peer_id)
            .finish()
    }
}

impl PeerConnPinger {
    pub fn new(
        my_peer_id: PeerId,
        peer_id: PeerId,
        sink: Pin<Box<dyn DatagramSink>>,
        ctrl_sender: broadcast::Sender<Bytes>,
        latency_stats: Arc<WindowLatency>,
        loss_rate_stats: Arc<AtomicU32>,
    ) -> Self {
        Self {
            my_peer_id,
            peer_id,
            sink: Arc::new(Mutex::new(sink)),
            tasks: JoinSet::new(),
            latency_stats,
            ctrl_sender,
            loss_rate_stats,
        }
    }

    async fn do_pingpong_once(
        my_node_id: PeerId,
        peer_id: PeerId,
        sink: Arc<Mutex<Pin<Box<dyn DatagramSink>>>>,
        receiver: &mut broadcast::Receiver<Bytes>,
        seq: u32,
    ) -> Result<u128, TunnelError> {
        // should add seq here. so latency can be calculated more accurately
        let req = packet::Packet::new_ping_packet(my_node_id, peer_id, seq).into();
        tracing::trace!("send ping packet: {:?}", req);
        sink.lock().await.send(req).await.map_err(|e| {
            tracing::warn!("send ping packet error: {:?}", e);
            TunnelError::CommonError("send ping packet error".to_owned())
        })?;

        let now = std::time::Instant::now();

        // wait until we get a pong packet in ctrl_resp_receiver
        let resp = timeout(Duration::from_secs(1), async {
            loop {
                match receiver.recv().await {
                    Ok(p) => {
                        let ctrl_payload =
                            packet::CtrlPacketPayload::from_packet(Packet::decode(&p));
                        if let packet::CtrlPacketPayload::Pong(resp_seq) = ctrl_payload {
                            if resp_seq == seq {
                                break;
                            }
                        }
                    }
                    Err(e) => {
                        log::warn!("recv pong resp error: {:?}", e);
                        return Err(TunnelError::WaitRespError(
                            "recv pong resp error".to_owned(),
                        ));
                    }
                }
            }
            Ok(())
        })
        .await;

        tracing::trace!(?resp, "wait ping response done");

        if resp.is_err() {
            return Err(TunnelError::WaitRespError(
                "wait ping response timeout".to_owned(),
            ));
        }

        if resp.as_ref().unwrap().is_err() {
            return Err(resp.unwrap().err().unwrap());
        }

        Ok(now.elapsed().as_micros())
    }

    async fn pingpong(&mut self) {
        let sink = self.sink.clone();
        let my_node_id = self.my_peer_id;
        let peer_id = self.peer_id;
        let latency_stats = self.latency_stats.clone();

        let (ping_res_sender, mut ping_res_receiver) = tokio::sync::mpsc::channel(100);

        let stopped = Arc::new(AtomicU32::new(0));

        // generate a pingpong task every 200ms
        let mut pingpong_tasks = JoinSet::new();
        let ctrl_resp_sender = self.ctrl_sender.clone();
        let stopped_clone = stopped.clone();
        self.tasks.spawn(async move {
            let mut req_seq = 0;
            loop {
                let receiver = ctrl_resp_sender.subscribe();
                let ping_res_sender = ping_res_sender.clone();
                let sink = sink.clone();

                if stopped_clone.load(Ordering::Relaxed) != 0 {
                    return Ok(());
                }

                while pingpong_tasks.len() > 5 {
                    pingpong_tasks.join_next().await;
                }

                pingpong_tasks.spawn(async move {
                    let mut receiver = receiver.resubscribe();
                    let pingpong_once_ret = Self::do_pingpong_once(
                        my_node_id,
                        peer_id,
                        sink.clone(),
                        &mut receiver,
                        req_seq,
                    )
                    .await;

                    if let Err(e) = ping_res_sender.send(pingpong_once_ret).await {
                        tracing::info!(?e, "pingpong task send result error, exit..");
                    };
                });

                req_seq += 1;
                tokio::time::sleep(Duration::from_millis(1000)).await;
            }
        });

        // one with 1% precision
        let loss_rate_stats_1 = WindowLatency::new(100);
        // one with 20% precision, so we can fast fail this conn.
        let loss_rate_stats_20 = WindowLatency::new(5);

        let mut counter: u64 = 0;

        while let Some(ret) = ping_res_receiver.recv().await {
            counter += 1;

            if let Ok(lat) = ret {
                latency_stats.record_latency(lat as u32);

                loss_rate_stats_1.record_latency(0);
                loss_rate_stats_20.record_latency(0);
            } else {
                loss_rate_stats_1.record_latency(1);
                loss_rate_stats_20.record_latency(1);
            }

            let loss_rate_20: f64 = loss_rate_stats_20.get_latency_us();
            let loss_rate_1: f64 = loss_rate_stats_1.get_latency_us();

            tracing::trace!(
                ?ret,
                ?self,
                ?loss_rate_1,
                ?loss_rate_20,
                "pingpong task recv pingpong_once result"
            );

            if (counter > 5 && loss_rate_20 > 0.74) || (counter > 150 && loss_rate_1 > 0.20) {
                tracing::warn!(
                    ?ret,
                    ?self,
                    ?loss_rate_1,
                    ?loss_rate_20,
                    "pingpong loss rate too high, closing"
                );
                break;
            }

            self.loss_rate_stats
                .store((loss_rate_1 * 100.0) as u32, Ordering::Relaxed);
        }

        stopped.store(1, Ordering::Relaxed);
        ping_res_receiver.close();
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

    pub fn start_pingpong(&mut self) {
        let mut pingpong = PeerConnPinger::new(
            self.my_peer_id,
            self.get_peer_id(),
            self.tunnel.pin_sink(),
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

    pub async fn send_msg(&mut self, msg: Bytes) -> Result<(), TunnelError> {
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

impl Debug for PeerConn {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PeerConn")
            .field("conn_id", &self.conn_id)
            .field("my_peer_id", &self.my_peer_id)
            .field("info", &self.info)
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use super::*;
    use crate::common::global_ctx::tests::get_mock_global_ctx;
    use crate::common::new_peer_id;
    use crate::tunnels::tunnel_filter::tests::DropSendTunnelFilter;
    use crate::tunnels::tunnel_filter::{PacketRecorderTunnelFilter, TunnelWithFilter};

    #[tokio::test]
    async fn peer_conn_handshake() {
        use crate::tunnels::ring_tunnel::create_ring_tunnel_pair;
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
        use crate::tunnels::ring_tunnel::create_ring_tunnel_pair;
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
